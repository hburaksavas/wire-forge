use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{header, Request, Uri};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpStream;

const BODY_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BodyEncoding {
    #[default]
    Text,
    Base64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayInput {
    #[serde(default)]
    pub body_encoding: BodyEncoding,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

fn build(input: ReplayInput) -> Result<Request<Full<Bytes>>, String> {
    let parsed = tauri::Url::parse(&input.url)
        .map_err(|_| "Enter an absolute HTTP(S) URL with a valid port".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.port_or_known_default() == Some(0)
        || input.url.len() > 8192
    {
        return Err("Enter an absolute HTTP(S) URL with a valid port (up to 8 KiB)".into());
    }
    if !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        .contains(&input.method.as_str())
    {
        return Err("Choose a supported HTTP method.".into());
    }
    let uri: Uri = input
        .url
        .parse()
        .map_err(|_| "Enter an absolute HTTP or HTTPS URL.".to_string())?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.authority().unwrap().as_str().contains('@')
        || input.url.contains('#')
        || uri.authority().is_some_and(|authority| {
            authority.port().is_some() && authority.port_u16().is_none_or(|port| port == 0)
        })
    {
        return Err("Replay requires an absolute HTTP(S) URL without credentials or fragments and a valid port.".into());
    }
    if input.headers.len() > 100 {
        return Err("Replay accepts up to 8 MiB of body data and 100 headers.".into());
    }
    let body = match (input.body_encoding, input.body) {
        (BodyEncoding::Text, body) => {
            if body.len() > BODY_LIMIT {
                return Err("Replay body exceeds 8 MiB".into());
            }
            body.into_bytes()
        }
        (BodyEncoding::Base64, body) => {
            if body.len() > BODY_LIMIT.div_ceil(3) * 4 {
                return Err("Replay body exceeds 8 MiB".into());
            }
            let bytes = STANDARD
                .decode(body)
                .map_err(|_| "Enter valid padded Base64 without whitespace".to_string())?;
            if bytes.len() > BODY_LIMIT {
                return Err("Replay body exceeds 8 MiB".into());
            }
            bytes
        }
    };
    let host = uri.authority().unwrap().as_str().to_owned();
    let mut request = Request::builder()
        .method(input.method.as_str())
        .uri(uri)
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| "Could not build the replay request.".to_string())?;
    let mut total = 0;
    for (name, value) in input.headers {
        total += name.len() + value.len();
        if total > 16 * 1024 {
            return Err("Replay headers exceed 16 KiB.".into());
        }
        let name: header::HeaderName = name
            .parse()
            .map_err(|_| "Invalid replay header name.".to_string())?;
        let value = header::HeaderValue::from_str(&value)
            .map_err(|_| "Invalid replay header value.".to_string())?;
        if ["host", "content-length", "expect"].contains(&name.as_str()) {
            continue;
        }
        request.headers_mut().append(name, value);
    }
    crate::proxy::strip_hop_headers(request.headers_mut());
    request
        .headers_mut()
        .insert(header::HOST, host.parse().unwrap());
    request.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    Ok(request)
}

async fn exchange(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    request: Request<Full<Bytes>>,
) -> Result<u16, String> {
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| "Replay connection failed".to_string())?;
    let mut driver = tokio::task::JoinSet::new();
    driver.spawn(connection);
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| "Replay request failed".to_string())?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        frame.map_err(|_| "Replay response ended unexpectedly".to_string())?;
    }
    Ok(status)
}

pub async fn send(
    address: SocketAddr,
    input: ReplayInput,
    store: Arc<crate::proxy::Store>,
) -> Result<u16, String> {
    let mut request = build(input)?;
    let secure = if request.uri().scheme_str() == Some("https") {
        let authority = request.uri().authority().unwrap();
        let target = if authority.port_u16().is_some() {
            authority.to_string()
        } else {
            format!("{}:443", authority.host())
        };
        if !store
            .tls
            .lock()
            .map_err(|e| e.to_string())?
            .matches(&target)
        {
            return Err(format!("Enable HTTPS inspection for {target} or All HTTPS hosts in Settings before replaying."));
        }
        let ca = store
            .authority
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or("Prepare the inspection CA in Settings before HTTPS replay")?;
        let config = ca.replay_config()?;
        let host = authority.host().trim_matches(['[', ']']).to_owned();
        Some((target, host, config))
    } else {
        None
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        let stream = TcpStream::connect(address)
            .await
            .map_err(|_| "Could not connect to the local proxy.".to_string())?;
        let Some((target, host, config)) = secure else {
            return exchange(stream, request).await;
        };
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| e.to_string())?;
        let mut driver = tokio::task::JoinSet::new();
        driver.spawn(connection.with_upgrades());
        let connect = Request::builder()
            .method("CONNECT")
            .uri(&target)
            .header(header::HOST, &target)
            .body(Full::new(Bytes::new()))
            .map_err(|e| e.to_string())?;
        let response = sender
            .send_request(connect)
            .await
            .map_err(|e| format!("HTTPS proxy connection failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "HTTPS proxy CONNECT failed (HTTP {})",
                response.status().as_u16()
            ));
        }
        let upgraded = hyper::upgrade::on(response)
            .await
            .map_err(|e| e.to_string())?;
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| e.to_string())?;
        let tls = tokio_rustls::TlsConnector::from(config)
            .connect(name, TokioIo::new(upgraded))
            .await
            .map_err(|e| format!("WireForge TLS verification failed: {e}"))?;
        *request.uri_mut() = request
            .uri()
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/")
            .parse()
            .map_err(|e: hyper::http::uri::InvalidUri| e.to_string())?;
        request.headers_mut().insert(
            header::HOST,
            target
                .parse()
                .map_err(|e: hyper::header::InvalidHeaderValue| e.to_string())?,
        );
        exchange(tls, request).await
    })
    .await
    .map_err(|_| "Replay timed out after 30 seconds.".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{MockRule, Proxy, Store};
    use std::sync::Arc;

    fn input() -> ReplayInput {
        ReplayInput {
            body_encoding: BodyEncoding::Text,
            method: "POST".into(),
            url: "http://destination.invalid/replay".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: "{\"replayed\":true}".into(),
        }
    }

    #[tokio::test]
    async fn replay_passes_through_local_proxy_and_mock_rules() {
        let store = Arc::new(Store::default());
        store.rules.lock().unwrap().push(MockRule {
            content_type: "application/json".into(),
            id: "one".into(),
            method: "POST".into(),
            path: "/replay".into(),
            status: 202,
            body: "{}".into(),
            enabled: true,
            ..Default::default()
        });
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        assert_eq!(
            send(proxy.address, input(), store.clone()).await.unwrap(),
            202
        );
        let entry = store.traffic.lock().unwrap().back().unwrap().clone();
        assert_eq!(entry.request_body, "{\"replayed\":true}");
        assert_eq!(entry.source, "mock");
        proxy.stop().await;
    }

    #[test]
    fn validates_urls_headers_and_methods() {
        for url in [
            "https://example.com:abc/path",
            "https://example.com:65536/path",
            "https://example.com:0/path",
            "https://user:secret@example.com/path",
            "https://example.com/path#fragment",
            "ftp://example.com/path",
        ] {
            assert!(
                build(ReplayInput {
                    url: url.into(),
                    ..input()
                })
                .is_err(),
                "Accepted invalid replay URL: {url}"
            );
        }
        assert!(build(ReplayInput {
            url: "https://example.com".into(),
            ..input()
        })
        .is_ok());
        assert!(build(ReplayInput {
            method: "CONNECT".into(),
            ..input()
        })
        .is_err());
        assert!(build(ReplayInput {
            headers: vec![("x-test".into(), "value\r\nInjected: bad".into())],
            ..input()
        })
        .is_err());
        let request = build(ReplayInput {
            headers: vec![
                ("Host".into(), "wrong.invalid".into()),
                ("Proxy-Authorization".into(), "private".into()),
                ("Content-Length".into(), "999".into()),
            ],
            ..input()
        })
        .unwrap();
        assert_eq!(request.headers()[header::HOST], "destination.invalid");
        assert!(!request.headers().contains_key(header::PROXY_AUTHORIZATION));
        assert!(!request.headers().contains_key(header::CONTENT_LENGTH));
    }

    #[tokio::test]
    async fn replay_uses_the_configured_upstream_route() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
            }
            assert!(String::from_utf8(headers)
                .unwrap()
                .starts_with("POST http://destination.invalid/replay HTTP/1.1"));
            let mut payload = vec![0; input().body.len()];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, input().body.as_bytes());
            stream.write_all(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        });
        let store = Arc::new(Store::default());
        *store.upstream.lock().unwrap() = crate::upstream::Upstream {
            enabled: true,
            host: "127.0.0.1".into(),
            port: upstream_address.port(),
            ..Default::default()
        };
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        assert_eq!(
            send(proxy.address, input(), store.clone()).await.unwrap(),
            201
        );
        task.await.unwrap();
        assert_eq!(
            store.traffic.lock().unwrap().back().unwrap().source,
            "forwarded"
        );
        proxy.stop().await;
    }

    #[tokio::test]
    async fn https_replay_captures_mock_without_contacting_destination() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(Arc::new(
            crate::tls::Authority::prepare(directory.path()).unwrap(),
        ));
        *store.tls.lock().unwrap() = crate::tls::TlsSettings {
            enabled: true,
            all_hosts: false,
            targets: vec!["mock.invalid:443".into()],
        };
        store.rules.lock().unwrap().push(MockRule {
            id: "secure".into(),
            method: "POST".into(),
            path: "/replay".into(),
            status: 202,
            body: r#"{"mock":true}"#.into(),
            content_type: "application/json".into(),
            enabled: true,
            ..Default::default()
        });
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let request = ReplayInput {
            url: "https://mock.invalid/replay".into(),
            ..input()
        };
        assert_eq!(
            send(proxy.address, request, store.clone()).await.unwrap(),
            202
        );
        let traffic = store.traffic.lock().unwrap();
        let entry = traffic.iter().find(|entry| entry.method == "POST").unwrap();
        assert_eq!(entry.source, "mock");
        assert_eq!(entry.request_body, input().body);
        assert_eq!(entry.response_body, r#"{"mock":true}"#);
        assert!(entry.url.starts_with("https://mock.invalid:443/"));
        drop(traffic);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn https_requires_selected_inspection_and_ca_before_connecting() {
        let store = Arc::new(Store::default());
        let address = "127.0.0.1:1".parse().unwrap();
        let request = || ReplayInput {
            url: "https://mock.invalid/replay".into(),
            ..input()
        };
        assert!(send(address, request(), store.clone())
            .await
            .unwrap_err()
            .contains("Enable HTTPS inspection"));
        *store.tls.lock().unwrap() = crate::tls::TlsSettings {
            enabled: true,
            all_hosts: true,
            targets: vec![],
        };
        assert!(send(address, request(), store.clone())
            .await
            .unwrap_err()
            .contains("Prepare the inspection CA"));
        assert!(store.traffic.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn https_replay_rejects_wrong_certificate_name() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let directory = tempfile::tempdir().unwrap();
        let ca = Arc::new(crate::tls::Authority::prepare(directory.path()).unwrap());
        let wrong = ca.server_config("wrong.invalid").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = vec![];
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
                assert!(headers.len() < 16384);
            }
            assert!(String::from_utf8(headers)
                .unwrap()
                .starts_with("CONNECT mock.invalid:443 HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            assert!(tokio_rustls::TlsAcceptor::from(wrong)
                .accept(stream)
                .await
                .is_err());
        });
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(ca);
        *store.tls.lock().unwrap() = crate::tls::TlsSettings {
            enabled: true,
            all_hosts: true,
            targets: vec![],
        };
        let error = send(
            address,
            ReplayInput {
                url: "https://mock.invalid/replay".into(),
                ..input()
            },
            store,
        )
        .await
        .unwrap_err();
        assert!(error.contains("TLS verification failed"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn binary_encoding_validation_limits_and_legacy_input() {
        let expected = [0, 255, 128, 13, 10, 65];
        let request = build(ReplayInput {
            body_encoding: BodyEncoding::Base64,
            body: STANDARD.encode(expected),
            ..input()
        })
        .unwrap();
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            expected.as_slice()
        );
        for body in ["%%%", "AP8", "AP8=\n"] {
            assert!(build(ReplayInput {
                body_encoding: BodyEncoding::Base64,
                body: body.into(),
                ..input()
            })
            .is_err());
        }
        let legacy:ReplayInput=serde_json::from_value(serde_json::json!({"method":"POST","url":"http://test.invalid/","headers":[],"body":"é"})).unwrap();
        assert_eq!(
            build(legacy)
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "é".as_bytes()
        );
        assert!(serde_json::from_value::<ReplayInput>(serde_json::json!({"method":"POST","url":"http://test.invalid/","headers":[],"body":"","bodyEncoding":"unknown"})).is_err());
        let exact = STANDARD.encode(vec![255; BODY_LIMIT]);
        assert_eq!(
            build(ReplayInput {
                body_encoding: BodyEncoding::Base64,
                body: exact,
                ..input()
            })
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .len(),
            BODY_LIMIT
        );
        let too_large = STANDARD.encode(vec![255; BODY_LIMIT + 1]);
        assert!(build(ReplayInput {
            body_encoding: BodyEncoding::Base64,
            body: too_large,
            ..input()
        })
        .is_err());
    }

    #[tokio::test]
    async fn binary_http_replay_delivers_exact_bytes_and_rebuilds_framing() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let expected = [0, 255, 128, 13, 10, 65];
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut headers = vec![];
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(socket.read_u8().await.unwrap());
                assert!(headers.len() < 16384);
            }
            let headers = String::from_utf8(headers).unwrap().to_lowercase();
            assert!(headers.starts_with("post /binary http/1.1"));
            assert!(headers.contains("content-length: 6\r\n"));
            assert!(!headers.contains("transfer-encoding:"));
            let mut body = [0u8; 6];
            socket.read_exact(&mut body).await.unwrap();
            assert_eq!(body, expected);
            socket
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let store = Arc::new(Store::default());
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let request = ReplayInput {
            url: format!("http://{target}/binary"),
            body_encoding: BodyEncoding::Base64,
            body: STANDARD.encode(expected),
            headers: vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("Content-Length".into(), "99999".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
            ],
            ..input()
        };
        assert_eq!(
            send(proxy.address, request, store.clone()).await.unwrap(),
            204
        );
        task.await.unwrap();
        assert!(
            !store
                .traffic
                .lock()
                .unwrap()
                .back()
                .unwrap()
                .request_available
        );
        proxy.stop().await;
    }
}
