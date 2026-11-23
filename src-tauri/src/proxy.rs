use crate::capture::{self, CapturedBody, PREVIEW_LIMIT};
use crate::upstream::Upstream;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited};
use hyper::{body::Incoming, header, service::service_fn, Request, Response, StatusCode};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, Error>;
const TIMEOUT: Duration = Duration::from_secs(30);
const HISTORY: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MockRule {
    pub id: String,
    pub method: String,
    pub path: String,
    pub body: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    pub status: u16,
    pub enabled: bool,
}

fn default_content_type() -> String {
    "application/json".into()
}

pub fn validate_rules(rules: &[MockRule]) -> Result<(), String> {
    if rules.len() > 200 {
        return Err("Maximum 200 rules per workspace.".into());
    }
    let mut seen = std::collections::HashSet::new();
    for rule in rules {
        if !rule.path.starts_with('/')
            || rule.path.contains('#')
            || !(200..=599).contains(&rule.status)
            || rule.body.len() > 1_048_576
            || !["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
                .contains(&rule.method.as_str())
        {
            return Err(
                "Use an absolute path, a supported method, status 200–599 and a body under 1 MiB."
                    .into(),
            );
        }
        if rule.content_type.is_empty()
            || rule.content_type.len() > 255
            || rule
                .content_type
                .parse::<hyper::header::HeaderValue>()
                .is_err()
        {
            return Err("Enter a valid response content type.".into());
        }
        if rule.content_type.to_ascii_lowercase().contains("json") {
            serde_json::from_str::<serde_json::Value>(&rule.body)
                .map_err(|_| "Enter a valid JSON response.".to_string())?;
        }
        if !seen.insert((&rule.method, &rule.path)) {
            return Err("Duplicate method and path.".into());
        }
    }
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SocketMessage {
    pub kind: String,
    pub direction: String,
    pub opcode: u8,
    pub elapsed_ms: u128,
    pub payload: String,
    pub bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficEntry {
    pub socket_control: bool,
    pub messages: VecDeque<SocketMessage>,
    pub messages_dropped: u64,
    pub id: u64,
    pub revision: u64,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub request_body: String,
    pub request_available: bool,
    pub response_available: bool,
    pub request_truncated: bool,
    pub response_truncated: bool,
    pub response_bytes: u64,
    pub body_state: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration_ms: u128,
    pub response_body: String,
    pub source: String,
}

#[derive(Default)]
pub struct Store {
    pub socket_rules: Mutex<Vec<crate::socket::SocketRule>>,
    pub rules: Mutex<Vec<MockRule>>,
    pub upstream: Mutex<Upstream>,
    pub tls: Mutex<crate::tls::TlsSettings>,
    pub authority: Mutex<Option<Arc<crate::tls::Authority>>>,
    pub traffic: Mutex<VecDeque<TrafficEntry>>,
    sequence: AtomicU64,
}

impl Store {
    pub fn clear_history(&self) {
        self.traffic.lock().unwrap().clear();
    }

    pub(crate) fn respond(
        &self,
        id: u64,
        status: u16,
        started: Instant,
        body: String,
        source: &str,
    ) -> u64 {
        let mut traffic = self.traffic.lock().unwrap();
        if let Some(entry) = traffic.iter_mut().find(|entry| entry.id == id) {
            entry.status = status;
            entry.duration_ms = started.elapsed().as_millis();
            entry.response_bytes = body.len() as u64;
            entry.response_body = body;
            entry.source = source.into();
            entry.body_state = if source == "tunnel" {
                "unavailable"
            } else if source == "inspection" {
                "handshake"
            } else {
                "complete"
            }
            .into();
            entry.response_available = !["tunnel", "inspection"].contains(&source);
            entry.revision = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        }
        id
    }

    pub(crate) fn record(
        &self,
        method: String,
        url: String,
        status: u16,
        started: Instant,
        body: String,
        source: &str,
    ) -> u64 {
        let mut traffic = self.traffic.lock().unwrap();
        let id = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = TrafficEntry {
            socket_control: false,
            messages: VecDeque::new(),
            messages_dropped: 0,
            id,
            revision: id,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: String::new(),
            request_available: false,
            response_available: source != "tunnel",
            request_truncated: false,
            response_truncated: false,
            response_bytes: body.len() as u64,
            body_state: if source == "tunnel" {
                "unavailable"
            } else {
                "complete"
            }
            .into(),
            method,
            url,
            status,
            duration_ms: started.elapsed().as_millis(),
            response_body: body,
            source: source.into(),
        };
        if traffic.len() == HISTORY {
            traffic.pop_front();
        }
        traffic.push_back(entry);
        id
    }

    pub(crate) fn inspect(
        &self,
        id: u64,
        request_headers: Vec<(String, String)>,
        response_headers: Vec<(String, String)>,
        request_preview: capture::BodyPreview,
        streaming: bool,
    ) {
        let mut traffic = self.traffic.lock().unwrap();
        if let Some(entry) = traffic.iter_mut().find(|entry| entry.id == id) {
            entry.request_headers = request_headers;
            entry.response_headers = response_headers;
            entry.request_body = request_preview.text;
            entry.request_truncated = request_preview.truncated;
            entry.request_available = request_preview.available;
            if streaming {
                entry.body_state = "streaming".into();
            }
            entry.revision = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        }
    }

    pub fn finish_response(&self, id: u64, body: capture::BodyPreview, bytes: u64, state: &str) {
        let mut traffic = self.traffic.lock().unwrap();
        if let Some(entry) = traffic.iter_mut().find(|entry| entry.id == id) {
            entry.response_body = body.text;
            entry.response_available = body.available;
            entry.response_bytes = bytes;
            entry.response_truncated = body.truncated;
            entry.body_state = state.into();
            entry.revision = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        }
    }

    pub(crate) fn socket_state(&self, id: u64, state: &str, error: Option<String>) {
        let mut traffic = self.traffic.lock().unwrap();
        if let Some(entry) = traffic.iter_mut().find(|entry| entry.id == id) {
            if state == "closed" && entry.body_state == "failed" {
                return;
            }
            entry.body_state = state.into();
            if ["closed", "failed"].contains(&state) {
                entry.socket_control = false;
            }
            if let Some(error) = error {
                entry.response_body = error;
            }
            entry.response_available = false;
            entry.revision = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        }
    }

    pub(crate) fn socket_control(&self, id: u64, enabled: bool) {
        let mut traffic = self.traffic.lock().unwrap();
        if let Some(entry) = traffic.iter_mut().find(|entry| entry.id == id) {
            entry.socket_control = enabled;
            entry.revision = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        }
    }

    pub(crate) fn socket_message(&self, id: u64, message: SocketMessage) {
        let mut traffic = self.traffic.lock().unwrap();
        if let Some(entry) = traffic.iter_mut().find(|entry| entry.id == id) {
            if message.direction == "in" {
                entry.response_bytes = entry.response_bytes.saturating_add(message.bytes);
            }
            entry.messages.push_back(message);
            while entry.messages.len() > 64
                || entry
                    .messages
                    .iter()
                    .map(|m| m.payload.len())
                    .sum::<usize>()
                    > 16 * 1024
            {
                entry.messages.pop_front();
                entry.messages_dropped += 1;
            }
            entry.revision = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        }
    }
}

fn response(status: u16, text: impl Into<String>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(
            Full::new(Bytes::from(text.into()))
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .unwrap()
}

// Connection-nominated headers must also be removed on both forwarding legs.
pub(crate) fn strip_hop_headers(headers: &mut hyper::HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(|name| name.trim().to_owned()))
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

pub struct Proxy {
    pub address: std::net::SocketAddr,
    cancel: CancellationToken,
    worker: tokio::task::JoinHandle<()>,
}

impl Proxy {
    pub async fn start(address: &str, store: Arc<Store>) -> Result<Self, String> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let cancel = CancellationToken::new();
        let shutdown = cancel.clone();
        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let slots = Arc::new(Semaphore::new(256));
        let worker = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let Ok(permit) = slots.clone().try_acquire_owned() else { drop(stream); continue; };
                        let store = store.clone();
                        let client = client.clone();
                        let cancel = shutdown.clone();
                        tasks.spawn(async move {
                            let permit = Arc::new(permit);
                            let service = service_fn(move |request| handle(request, store.clone(), client.clone(), cancel.clone(), permit.clone()));
                            let mut builder = hyper::server::conn::http1::Builder::new();
                            builder.timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(TIMEOUT);
                            let connection = builder.serve_connection(TokioIo::new(stream), service).with_upgrades();
                            let _ = tokio::time::timeout(Duration::from_secs(300), connection).await;
                        });
                    }
                }
            }
            shutdown.cancel();
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            cancel,
            worker,
        })
    }

    pub async fn stop(self) {
        self.cancel.cancel();
        let _ = self.worker.await;
    }
}

#[derive(Clone)]
struct Trace(u64);

struct PendingRequest {
    store: Arc<Store>,
    id: u64,
    started: Instant,
    finished: bool,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if !self.finished {
            self.store.respond(
                self.id,
                499,
                self.started,
                "Request cancelled before response headers.".into(),
                "error",
            );
        }
    }
}

fn handle(
    mut request: Request<Incoming>,
    store: Arc<Store>,
    client: Client<HttpConnector, Full<Bytes>>,
    cancel: CancellationToken,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Infallible>> + Send>>
{
    Box::pin(async move {
        let started = Instant::now();
        let id = store.record(
            request.method().to_string(),
            request.uri().to_string(),
            0,
            started,
            String::new(),
            "pending",
        );
        {
            let mut entries = store.traffic.lock().unwrap();
            if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                entry.request_headers = capture::headers(request.headers());
                entry.body_state = "pending".into();
                entry.revision = store.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            }
        }
        request.extensions_mut().insert(Trace(id));
        let mut pending = PendingRequest {
            store: store.clone(),
            id,
            started,
            finished: false,
        };
        let result = handle_inner(request, store.clone(), client, cancel, permit).await?;
        let incomplete = store
            .traffic
            .lock()
            .unwrap()
            .iter()
            .any(|entry| entry.id == id && entry.source == "pending");
        let result = if incomplete {
            let (parts, body) = result.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|body| body.to_bytes())
                .unwrap_or_default();
            store.respond(
                id,
                parts.status.as_u16(),
                started,
                capture::preview(&bytes, &parts.headers),
                "error",
            );
            {
                let mut entries = store.traffic.lock().unwrap();
                if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                    entry.response_headers = capture::headers(&parts.headers);
                }
            }
            Response::from_parts(
                parts,
                Full::new(bytes)
                    .map_err(|never: Infallible| match never {})
                    .boxed(),
            )
        } else {
            result
        };
        pending.finished = true;
        Ok(result)
    })
}

fn handle_inner(
    mut request: Request<Incoming>,
    store: Arc<Store>,
    client: Client<HttpConnector, Full<Bytes>>,
    cancel: CancellationToken,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Infallible>> + Send>>
{
    Box::pin(async move {
        let started = Instant::now();
        let id = request
            .extensions()
            .get::<Trace>()
            .map(|trace| trace.0)
            .unwrap_or(0);
        let method = request.method().to_string();
        if request.headers().contains_key(header::UPGRADE) {
            return Ok(response(
                501,
                r#"{"error":"Protocol upgrades are not supported yet."}"#,
            ));
        }
        if request.method() == hyper::Method::CONNECT {
            return Ok(tunnel(request, store, cancel, started, permit, client).await);
        }
        let path = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let rule = store
            .rules
            .lock()
            .unwrap()
            .iter()
            .find(|rule| rule.enabled && rule.method == method && rule.path == path)
            .cloned();
        let inspected = request.extensions().get::<Inspected>().is_some();
        if rule.is_none()
            && ((request.uri().scheme_str() != Some("http")
                && !(inspected && request.uri().scheme_str() == Some("https")))
                || request.uri().authority().is_none())
        {
            return Ok(response(
                400,
                r#"{"error":"Use an absolute http:// URL for forwarding, or create a matching mock rule."}"#,
            ));
        }
        let authority = request.uri().authority().cloned();
        if rule.is_none()
            && authority.as_ref().is_some_and(|authority| {
                authority.port_u16() == Some(8080)
                    && ["127.0.0.1", "localhost", "[::1]"].contains(&authority.host())
            })
        {
            return Ok(response(400, r#"{"error":"Proxy loop rejected."}"#));
        }
        let request_headers = capture::headers(request.headers());
        let preview_headers = request.headers().clone();
        strip_hop_headers(request.headers_mut());
        if let Some(authority) = &authority {
            request
                .headers_mut()
                .insert(header::HOST, authority.as_str().parse().unwrap());
        }
        let (mut parts, body) = request.into_parts();
        // Bound buffered request bodies. Response bodies remain streamed with backpressure.
        let body = match tokio::time::timeout(
            TIMEOUT,
            Limited::new(body, 8 * 1024 * 1024).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            Ok(Err(_)) => {
                return Ok(response(
                    413,
                    r#"{"error":"Request body exceeds 8 MiB or is malformed."}"#,
                ))
            }
            Err(_) => return Ok(response(408, r#"{"error":"Request body timed out."}"#)),
        };
        let preview_bytes = body.slice(..body.len().min(PREVIEW_LIMIT));
        let request_truncated = body.len() > PREVIEW_LIMIT;
        let request_preview = tokio::task::spawn_blocking(move || {
            capture::body_preview(&preview_bytes, &preview_headers, request_truncated)
        })
        .await
        .unwrap();
        if let Some(rule) = rule {
            let bytes = if method == "HEAD" || [204, 205, 304].contains(&rule.status) {
                Bytes::new()
            } else {
                Bytes::from(rule.body)
            };
            let mut result = response(rule.status, "");
            result
                .headers_mut()
                .insert(header::CONTENT_TYPE, rule.content_type.parse().unwrap());
            let id = store.respond(
                id,
                rule.status,
                started,
                capture::preview(&bytes, result.headers()),
                "mock",
            );
            store.inspect(
                id,
                request_headers,
                capture::headers(result.headers()),
                request_preview,
                false,
            );
            store.finish_response(
                id,
                capture::body_preview(&bytes, result.headers(), false),
                bytes.len() as u64,
                "complete",
            );
            *result.body_mut() = Full::new(bytes)
                .map_err(|never: Infallible| match never {})
                .boxed();
            return Ok(result);
        }
        parts.headers.remove(header::CONTENT_LENGTH);
        let forwarded = Request::from_parts(parts, Full::new(body));
        let upstream = store.upstream.lock().unwrap().clone();
        let send = async {
            if inspected {
                send_https(forwarded, store.clone(), &upstream, cancel).await
            } else if upstream.enabled {
                upstream.send(forwarded, cancel, false).await
            } else {
                client
                    .request(forwarded)
                    .await
                    .map_err(|error| -> Error { Box::new(error) })
            }
        };
        let result = tokio::time::timeout(TIMEOUT, send).await;
        let result = match result {
            Ok(Ok(result))
                if !inspected
                    && upstream.enabled
                    && result.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED =>
            {
                let body = r#"{"error":"Upstream proxy authentication failed (407). Check the authentication settings. NTLM and Kerberos are not supported yet."}"#;
                store.respond(id, 502, started, body.into(), "error");
                response(502, body)
            }
            Ok(Ok(mut result)) => {
                strip_hop_headers(result.headers_mut());
                let status = result.status().as_u16();
                let id = store.respond(id, status, started, String::new(), "forwarded");
                store.inspect(
                    id,
                    request_headers,
                    capture::headers(result.headers()),
                    request_preview,
                    true,
                );
                let headers = result.headers().clone();
                result.map(|body| {
                    CapturedBody::new(body, store.clone(), id, headers)
                        .map_err(|error| -> Error { Box::new(error) })
                        .boxed()
                })
            }
            error => {
                let status = if error.is_err() { 504 } else { 502 };
                let auth_failed =
                    matches!(&error, Ok(Err(error)) if error.to_string().contains("407"));
                let body = if auth_failed {
                    "{\"error\":\"Upstream proxy authentication failed (407). Review the configured authentication method and credentials.\"}"
                } else if inspected {
                    "{\"error\":\"HTTPS upstream TLS validation or connection failed. Review server trust and upstream proxy settings.\"}"
                } else {
                    "{\"error\":\"Upstream connection failed or timed out.\"}"
                };
                store.respond(id, status, started, body.into(), "error");
                response(status, body)
            }
        };
        Ok(result)
    })
}

pub(crate) trait TunnelStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> TunnelStream for T {}

async fn tunnel(
    mut request: Request<Incoming>,
    store: Arc<Store>,
    cancel: CancellationToken,
    started: Instant,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    client: Client<HttpConnector, Full<Bytes>>,
) -> Response<Body> {
    let id = request
        .extensions()
        .get::<Trace>()
        .map(|trace| trace.0)
        .unwrap_or(0);
    let Some(authority) = request.uri().authority().cloned() else {
        return response(400, r#"{"error":"CONNECT requires host:port."}"#);
    };
    let Some(port) = authority.port_u16() else {
        return response(400, r#"{"error":"CONNECT requires an explicit port."}"#);
    };
    if port == 8080 && ["127.0.0.1", "localhost", "[::1]"].contains(&authority.host()) {
        return response(400, r#"{"error":"Proxy loop rejected."}"#);
    }
    if store.tls.lock().unwrap().matches(authority.as_str()) {
        return inspect_tunnel(request, authority, store, client, cancel, permit, started).await;
    }
    let config = store.upstream.lock().unwrap().clone();
    let connect = connect_target(&authority, &config, cancel.clone());
    let upstream = match tokio::time::timeout(TIMEOUT, connect).await {
        Ok(Ok(stream)) => stream,
        failure => {
            let message = match failure {
                Ok(Err(message)) => message,
                _ => "Tunnel connection timed out.".into(),
            };
            let body = serde_json::json!({"error": message}).to_string();
            store.respond(id, 502, started, body.clone(), "error");
            return response(502, body);
        }
    };
    store.respond(
        id,
        200,
        started,
        "Encrypted tunnel. HTTPS content is not inspected.".into(),
        "tunnel",
    );
    tokio::spawn(async move {
        let _permit = permit;
        let transfer = async {
            if let Ok(upgraded) = hyper::upgrade::on(&mut request).await {
                let mut client = TokioIo::new(upgraded);
                let mut upstream = upstream;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            }
        };
        tokio::select! {
            _ = cancel.cancelled() => {},
            _ = tokio::time::timeout(Duration::from_secs(3600), transfer) => {},
        }
    });
    Response::builder()
        .status(StatusCode::OK)
        .body(response(200, "").into_body())
        .unwrap()
}

#[derive(Clone)]
struct Inspected;

pub(crate) async fn connect_target(
    authority: &hyper::http::uri::Authority,
    config: &Upstream,
    cancel: CancellationToken,
) -> Result<Box<dyn TunnelStream>, String> {
    let port = authority.port_u16().unwrap_or(443);
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');

    if config.enabled {
        let connect_request = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri(authority.as_str())
            .header(header::HOST, authority.as_str())
            .body(Full::new(Bytes::new()))
            .unwrap();
        let mut result = config
            .send(connect_request, cancel.clone(), true)
            .await
            .map_err(|_| "Could not connect to the upstream proxy.".to_string())?;
        if !result.status().is_success() {
            return Err(
                if result.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    "Upstream proxy authentication failed (407). Check authentication settings; NTLM and Kerberos are not supported yet.".into()
                } else {
                    format!(
                        "Upstream proxy rejected CONNECT ({}).",
                        result.status().as_u16()
                    )
                },
            );
        }
        let upgraded = hyper::upgrade::on(&mut result)
            .await
            .map_err(|_| "Upstream CONNECT upgrade failed.".to_string())?;
        Ok::<Box<dyn TunnelStream>, String>(Box::new(TokioIo::new(upgraded)))
    } else {
        TcpStream::connect((host, port))
            .await
            .map(|stream| Box::new(stream) as Box<dyn TunnelStream>)
            .map_err(|_| "Tunnel connection failed.".to_string())
    }
}

async fn send_https(
    mut request: Request<Full<Bytes>>,
    store: Arc<Store>,
    upstream: &Upstream,
    cancel: CancellationToken,
) -> Result<Response<Incoming>, Error> {
    let authority = request.uri().authority().unwrap().clone();
    let config = store
        .authority
        .lock()
        .unwrap()
        .as_ref()
        .ok_or("Inspection CA is unavailable")?
        .client_config
        .clone();
    let stream = connect_target(&authority, upstream, cancel.clone())
        .await
        .map_err(std::io::Error::other)?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host)?;
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await?;
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .parse()?;
    request.headers_mut().insert(
        header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(async move {
        tokio::select! { _ = cancel.cancelled() => {}, _ = connection => {} }
    });
    Ok(sender.send_request(request).await?)
}

async fn inspect_tunnel(
    mut request: Request<Incoming>,
    authority: hyper::http::uri::Authority,
    store: Arc<Store>,
    client: Client<HttpConnector, Full<Bytes>>,
    cancel: CancellationToken,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    started: Instant,
) -> Response<Body> {
    let id = request
        .extensions()
        .get::<Trace>()
        .map(|trace| trace.0)
        .unwrap_or(0);
    let ca = store.authority.lock().unwrap().clone();
    let Some(ca) = ca else {
        return response(
            503,
            r#"{"error":"Prepare the inspection CA in Settings first."}"#,
        );
    };
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let config = match tokio::task::spawn_blocking(move || ca.server_config(&host)).await {
        Ok(Ok(config)) => config,
        _ => {
            return response(
                500,
                r#"{"error":"Could not create the inspection certificate."}"#,
            )
        }
    };
    store.respond(
        id,
        200,
        started,
        "TLS inspection selected. The test client must trust the WireForge CA.".into(),
        "inspection",
    );
    tokio::spawn(async move {
        let _permit = permit.clone();
        let destination = authority.to_string();
        let transfer = async {
            let upgraded = hyper::upgrade::on(&mut request)
                .await
                .map_err(|e| e.to_string())?;
            let tls = tokio::time::timeout(
                TIMEOUT,
                tokio_rustls::TlsAcceptor::from(config).accept(TokioIo::new(upgraded)),
            )
            .await
            .map_err(|_| "Client TLS handshake timed out.".to_string())?
            .map_err(|_| {
                "Client TLS handshake failed. Check that the client trusts the WireForge CA."
                    .to_string()
            })?;
            let service_store = store.clone();
            let service_cancel = cancel.clone();
            let service = service_fn(move |mut request: Request<Incoming>| {
                let authority = authority.clone();
                let store = service_store.clone();
                let client = client.clone();
                let cancel = service_cancel.clone();
                let permit = permit.clone();
                async move {
                    if request.method() == hyper::Method::CONNECT
                        || request.uri().authority().is_some_and(|value| {
                            !value.as_str().eq_ignore_ascii_case(authority.as_str())
                        })
                    {
                        return Ok::<_, Infallible>(response(
                            421,
                            r#"{"error":"Request target does not match the inspected CONNECT destination."}"#,
                        ));
                    }
                    let path = request
                        .uri()
                        .path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or("/");
                    let uri: hyper::Uri = format!("https://{authority}{path}").parse().unwrap();
                    *request.uri_mut() = uri;
                    request.extensions_mut().insert(Inspected);
                    handle(request, store, client, cancel, permit).await
                }
            });
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(TIMEOUT);
            builder
                .serve_connection(TokioIo::new(tls), service)
                .await
                .map_err(|e| e.to_string())
        };
        tokio::select! {
            _ = cancel.cancelled() => {},
            result = tokio::time::timeout(Duration::from_secs(300), transfer) => {
                if let Ok(Err(message)) = result {
                    store.record("TLS".into(), destination, 502, started, message, "error");
                }
            }
        }
    });
    Response::builder()
        .status(200)
        .body(response(200, "").into_body())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn exchange(address: std::net::SocketAddr, request: String) -> String {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            String::from_utf8(bytes).unwrap()
        })
        .await
        .expect("HTTP exchange timed out")
    }

    #[test]
    fn validates_duplicate_and_invalid_mock_rules() {
        let rule = MockRule {
            content_type: "application/json".into(),
            id: "1".into(),
            method: "GET".into(),
            path: "/health".into(),
            body: "{}".into(),
            status: 200,
            enabled: true,
        };
        assert!(validate_rules(&[rule.clone()]).is_ok());
        assert!(validate_rules(&[rule.clone(), rule.clone()]).is_err());
        assert!(validate_rules(&[MockRule {
            body: "bad json".into(),
            ..rule
        }])
        .is_err());
    }

    #[tokio::test]
    async fn supports_text_mocks_and_legacy_json_rules() {
        let legacy: MockRule = serde_json::from_str(
            r#"{"id":"old","method":"GET","path":"/old","body":"{}","status":200,"enabled":true}"#,
        )
        .unwrap();
        assert_eq!(legacy.content_type, "application/json");
        let store = Arc::new(Store::default());
        let rule = MockRule {
            id: "text".into(),
            method: "GET".into(),
            path: "/text".into(),
            body: "custom response".into(),
            content_type: "text/plain; charset=utf-8".into(),
            status: 404,
            enabled: true,
        };
        assert!(validate_rules(&[rule.clone()]).is_ok());
        store.rules.lock().unwrap().push(rule);
        let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
        let result = exchange(
            proxy.address,
            "GET /text HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(result.starts_with("HTTP/1.1 404"));
        assert!(result
            .to_lowercase()
            .contains("content-type: text/plain; charset=utf-8"));
        assert!(result.ends_with("custom response"));
        proxy.stop().await;
    }

    #[tokio::test]
    async fn serves_mocks_and_releases_listener_on_stop() {
        let store = Arc::new(Store::default());
        store.rules.lock().unwrap().push(MockRule {
            content_type: "application/json".into(),
            id: "1".into(),
            method: "GET".into(),
            path: "/health?ready=1".into(),
            body: "{\"ready\":true}".into(),
            status: 201,
            enabled: true,
        });
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let address = proxy.address;
        let response = exchange(
            address,
            "GET /health?ready=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 201"));
        assert!(response.contains("{\"ready\":true}"));
        assert_eq!(store.traffic.lock().unwrap().back().unwrap().source, "mock");
        proxy.stop().await;
        let restarted = Proxy::start(&address.to_string(), store).await.unwrap();
        restarted.stop().await;
    }

    #[tokio::test]
    async fn forwards_post_and_strips_connection_headers() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0; 1024];
            loop {
                let count = stream.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.windows(4).any(|part| part == b"\r\n\r\n") && bytes.ends_with(b"ping") {
                    break;
                }
            }
            let request = String::from_utf8(bytes).unwrap().to_lowercase();
            assert!(request.starts_with("post /echo?q=1 http/1.1"));
            assert!(!request.contains("x-private:"));
            assert!(!request.contains("proxy-authorization:"));
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close, x-hidden\r\nX-Hidden: secret\r\n\r\npong").await.unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let result = exchange(proxy.address, format!("POST http://{target}/echo?q=1 HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nConnection: close, x-private\r\nX-Private: secret\r\nProxy-Authorization: secret\r\n\r\nping")).await;
        assert!(result.starts_with("HTTP/1.1 200"), "{result}");
        assert!(result.ends_with("pong"));
        assert!(!result.to_lowercase().contains("x-hidden:"));
        origin.await.unwrap();
        assert_eq!(
            store.traffic.lock().unwrap().back().unwrap().source,
            "forwarded"
        );
        proxy.stop().await;
    }

    #[tokio::test]
    async fn tunnels_bytes_and_cancels_active_tunnels() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = echo.local_addr().unwrap();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                let mut end = [0; 1];
                assert_eq!(stream.read(&mut end).await.unwrap(), 0);
            });
            let proxy = Proxy::start("127.0.0.1:0", Arc::new(Store::default()))
                .await
                .unwrap();
            let mut stream = TcpStream::connect(proxy.address).await.unwrap();
            stream
                .write_all(
                    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut headers = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                headers.push(byte);
                if headers.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            assert!(headers.starts_with(b"HTTP/1.1 200"));
            stream.write_all(b"ping").await.unwrap();
            let mut result = [0; 4];
            stream.read_exact(&mut result).await.unwrap();
            assert_eq!(&result, b"ping");
            proxy.stop().await;
            let mut end = [0; 1];
            assert_eq!(stream.read(&mut end).await.unwrap(), 0);
            origin.await.unwrap();
        })
        .await
        .expect("Tunnel shutdown timed out");
    }

    async fn read_headers(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
            assert!(bytes.len() < 16384);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn configure_upstream(store: &Store, address: std::net::SocketAddr) {
        *store.upstream.lock().unwrap() = Upstream {
            enabled: true,
            host: address.ip().to_string(),
            port: address.port(),
            username: "developer".into(),
            password: "test-only".into(),
            basic_auth: true,
            password_available: true,
        };
    }

    #[tokio::test]
    async fn chains_http_with_absolute_url_and_configured_credentials() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let store = Arc::new(Store::default());
        configure_upstream(&store, upstream.local_addr().unwrap());
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let headers = read_headers(&mut stream).await.to_lowercase();
            assert!(
                headers.starts_with("get http://destination.invalid/api?q=1 http/1.1"),
                "{headers}"
            );
            assert!(headers.contains("host: destination.invalid"));
            assert!(headers.contains("proxy-authorization: basic zgv2zwxvcgvyonrlc3qtb25seq=="));
            assert!(!headers.contains("client-secret"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nchained",
                )
                .await
                .unwrap();
        });
        let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
        let result = exchange(proxy.address, "GET http://destination.invalid/api?q=1 HTTP/1.1\r\nHost: destination.invalid\r\nProxy-Authorization: client-secret\r\nConnection: close\r\n\r\n".into()).await;
        assert!(result.starts_with("HTTP/1.1 200"), "{result}");
        assert!(result.ends_with("chained"));
        upstream_task.await.unwrap();
        proxy.stop().await;
    }

    #[tokio::test]
    async fn chains_connect_and_preserves_bytes_after_upstream_headers() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let store = Arc::new(Store::default());
            configure_upstream(&store, upstream.local_addr().unwrap());
            let upstream_task = tokio::spawn(async move {
                let (mut stream, _) = upstream.accept().await.unwrap();
                let headers = read_headers(&mut stream).await.to_lowercase();
                assert!(headers.starts_with("connect destination.invalid:443 http/1.1"));
                assert!(headers.contains("proxy-authorization: basic zgv2zwxvcgvyonrlc3qtb25seq=="));
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nhello").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"ping");
                stream.write_all(b"pong").await.unwrap();
            });
            let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
            let mut client = TcpStream::connect(proxy.address).await.unwrap();
            client.write_all(b"CONNECT destination.invalid:443 HTTP/1.1\r\nHost: destination.invalid:443\r\n\r\n").await.unwrap();
            assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
            let mut greeting = [0; 5];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"hello");
            client.write_all(b"ping").await.unwrap();
            let mut result = [0; 4];
            client.read_exact(&mut result).await.unwrap();
            assert_eq!(&result, b"pong");
            upstream_task.await.unwrap();
            proxy.stop().await;
        }).await.expect("Chained tunnel timed out");
    }

    #[tokio::test]
    async fn upstream_authentication_failures_are_actionable_for_http_and_connect() {
        for request in [
            "GET http://destination.invalid/ HTTP/1.1\r\nHost: destination.invalid\r\nConnection: close\r\n\r\n",
            "CONNECT destination.invalid:443 HTTP/1.1\r\nHost: destination.invalid:443\r\nConnection: close\r\n\r\n",
        ] {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let store = Arc::new(Store::default());
            configure_upstream(&store, upstream.local_addr().unwrap());
            let upstream_task = tokio::spawn(async move {
                let (mut stream, _) = upstream.accept().await.unwrap();
                read_headers(&mut stream).await;
                stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            });
            let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
            let result = exchange(proxy.address, request.into()).await;
            assert!(result.starts_with("HTTP/1.1 502"), "{result}");
            assert!(result.contains("407"));
            assert!(!result.to_lowercase().contains("proxy-authenticate:"));
            upstream_task.await.unwrap();
            proxy.stop().await;
        }
    }

    #[tokio::test]
    async fn upstream_failure_does_not_fall_back_and_mock_has_precedence() {
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unavailable.local_addr().unwrap();
        drop(unavailable);
        let store = Arc::new(Store::default());
        configure_upstream(&store, address);
        store.rules.lock().unwrap().push(MockRule {
            content_type: "application/json".into(),
            id: "1".into(),
            method: "GET".into(),
            path: "/mock".into(),
            body: "{}".into(),
            status: 200,
            enabled: true,
        });
        let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
        let mock = exchange(proxy.address, "GET http://destination.invalid/mock HTTP/1.1\r\nHost: destination.invalid\r\nConnection: close\r\n\r\n".into()).await;
        assert!(mock.starts_with("HTTP/1.1 200"));
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = origin.local_addr().unwrap();
        for request in [
            format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
        ] {
            let result = exchange(proxy.address, request).await;
            assert!(result.starts_with("HTTP/1.1 502"), "{result}");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), origin.accept())
                .await
                .is_err()
        );
        proxy.stop().await;
    }

    #[tokio::test]
    async fn captures_request_and_full_response_without_duplicate_entries() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            read_headers(&mut stream).await;
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"{\"x\":1}");
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nX-Trace: test\r\nConnection: close\r\n\r\n{\"ok\":true}").await.unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let result = exchange(proxy.address, format!("POST http://{target}/capture HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Length: 7\r\nProxy-Authorization: never-capture-me\r\nConnection: close\r\n\r\n{{\"x\":1}}")).await;
        assert!(result.ends_with("{\"ok\":true}"));
        origin.await.unwrap();
        {
            let entries = store.traffic.lock().unwrap();
            assert_eq!(entries.len(), 1);
            let entry = &entries[0];
            assert_eq!(entry.request_body, "{\"x\":1}");
            assert_eq!(entry.response_body, "{\"ok\":true}");
            assert_eq!(entry.body_state, "complete");
            assert_eq!(entry.response_bytes, 11);
            assert!(entry.revision > entry.id);
            assert!(entry
                .response_headers
                .iter()
                .any(|(name, value)| name == "x-trace" && value == "test"));
            assert!(!entry
                .request_headers
                .iter()
                .any(|(_, value)| value.contains("never-capture-me")));
        }
        proxy.stop().await;
    }

    #[tokio::test]
    async fn large_response_preview_is_bounded_while_client_receives_every_byte() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            read_headers(&mut stream).await;
            let payload = vec![b'x'; PREVIEW_LIMIT * 4];
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).as_bytes()).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let result = exchange(
            proxy.address,
            format!(
                "GET http://{target}/large HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(
            result.split_once("\r\n\r\n").unwrap().1.len(),
            PREVIEW_LIMIT * 4
        );
        origin.await.unwrap();
        {
            let entries = store.traffic.lock().unwrap();
            assert_eq!(entries[0].response_body.len(), PREVIEW_LIMIT);
            assert!(entries[0].response_truncated);
            assert_eq!(entries[0].response_bytes, (PREVIEW_LIMIT * 4) as u64);
            assert_eq!(entries[0].body_state, "complete");
        }
        proxy.stop().await;
    }

    #[tokio::test]
    async fn chunked_response_updates_revision_after_stream_completion() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = upstream.local_addr().unwrap();
            let (release, wait) = tokio::sync::oneshot::channel();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = upstream.accept().await.unwrap();
                read_headers(&mut stream).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nping\r\n").await.unwrap();
                wait.await.unwrap();
                stream.write_all(b"4\r\npong\r\n0\r\n\r\n").await.unwrap();
            });
            let store = Arc::new(Store::default());
            let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
            let mut client = TcpStream::connect(proxy.address).await.unwrap();
            client.write_all(format!("GET http://{target}/stream HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
            assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
            let revision = {
                let entries = store.traffic.lock().unwrap();
                assert_eq!(entries[0].body_state, "streaming");
                entries[0].revision
            };
            release.send(()).unwrap();
            let mut remaining = Vec::new();
            client.read_to_end(&mut remaining).await.unwrap();
            origin.await.unwrap();
            {
                let entries = store.traffic.lock().unwrap();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].response_body, "pingpong");
                assert_eq!(entries[0].body_state, "complete");
                assert!(entries[0].revision > revision);
            }
            proxy.stop().await;
        }).await.unwrap();
    }

    #[tokio::test]
    async fn incomplete_upstream_body_is_marked_failed() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            read_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
                )
                .await
                .unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        client.write_all(format!("GET http://{target}/broken HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut bytes))
            .await
            .unwrap();
        origin.await.unwrap();
        assert_eq!(store.traffic.lock().unwrap()[0].body_state, "failed");
        proxy.stop().await;
    }

    #[test]
    fn clearing_history_keeps_ids_monotonic_and_discards_old_completions() {
        let store = Store::default();
        let old = store.record(
            "GET".into(),
            "http://example.invalid/old".into(),
            200,
            Instant::now(),
            String::new(),
            "forwarded",
        );
        store.clear_history();
        store.finish_response(
            old,
            capture::BodyPreview {
                text: "old".into(),
                truncated: false,
                available: true,
            },
            3,
            "complete",
        );
        assert!(store.traffic.lock().unwrap().is_empty());
        let new = store.record(
            "GET".into(),
            "http://example.invalid/new".into(),
            200,
            Instant::now(),
            String::new(),
            "forwarded",
        );
        assert!(new > old);
        assert_eq!(store.traffic.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn gzip_previews_decode_without_changing_transferred_bytes() {
        use std::io::Write;
        let json = b"{\"compressed\":true}";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(json).unwrap();
        let compressed = encoder.finish().unwrap();
        let expected = compressed.clone();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap();
        let payload = compressed.clone();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let headers = read_headers(&mut stream).await.to_lowercase();
            assert!(headers.contains("content-encoding: gzip"));
            let mut body = vec![0; payload.len()];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, payload);
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).as_bytes()).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        client.write_all(format!("POST http://{target}/compressed HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", compressed.len()).as_bytes()).await.unwrap();
        client.write_all(&compressed).await.unwrap();
        let headers = read_headers(&mut client).await.to_lowercase();
        assert!(headers.contains("content-encoding: gzip"));
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, expected);
        origin.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let complete =
                    store.traffic.lock().unwrap().back().unwrap().body_state == "complete";
                if complete {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let entry = store.traffic.lock().unwrap().back().unwrap().clone();
        assert_eq!(entry.request_body.as_bytes(), json);
        assert_eq!(entry.response_body.as_bytes(), json);
        assert!(entry.request_available && entry.response_available);
        assert!(!entry.request_truncated && !entry.response_truncated);
        assert_eq!(entry.response_bytes, compressed.len() as u64);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn captures_rejected_upgrade_and_invalid_destination() {
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let upgrade = exchange(proxy.address, "GET http://example.invalid/socket HTTP/1.1\r\nHost: example.invalid\r\nUpgrade: websocket\r\nConnection: close, upgrade\r\n\r\n".into()).await;
        assert!(upgrade.starts_with("HTTP/1.1 501"));
        let invalid = exchange(
            proxy.address,
            "GET /unmatched HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(invalid.starts_with("HTTP/1.1 400"));
        let entries = store.traffic.lock().unwrap().clone();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].status, 501);
        assert_eq!(entries[1].status, 400);
        assert!(entries.iter().all(|entry| entry.source == "error"));
        assert!(entries[0].response_body.contains("Protocol upgrades"));
        proxy.stop().await;
    }

    #[tokio::test]
    async fn request_is_visible_before_upstream_response_arrives() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let (ready, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            read_headers(&mut stream).await;
            ready.send(()).unwrap();
            wait.await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let proxy_address = proxy.address;
        let request = tokio::spawn(async move {
            exchange(proxy_address, format!("GET http://{address}/slow HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")).await
        });
        observed.await.unwrap();
        let id = {
            let entries = store.traffic.lock().unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].status, 0);
            assert_eq!(entries[0].body_state, "pending");
            entries[0].id
        };
        release.send(()).unwrap();
        request.await.unwrap();
        worker.await.unwrap();
        {
            let entries = store.traffic.lock().unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, id);
            assert_eq!(entries[0].status, 200);
        }
        proxy.stop().await;
    }
}
