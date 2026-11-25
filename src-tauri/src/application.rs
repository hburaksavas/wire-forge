//! Native WebView2 capture. No injected page scripts or remote debugging listener.
use crate::{
    capture::{self, BodyPreview},
    proxy::{MockRule, SocketMessage, Store},
    upstream::Upstream,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
use webview2_com::{
    CallDevToolsProtocolMethodCompletedHandler, CoTaskMemPWSTR,
    DevToolsProtocolEventReceivedEventHandler, Microsoft::Web::WebView2::Win32::*,
    WebResourceRequestedEventHandler,
};
use windows::core::{Interface, HSTRING, PWSTR};

const BODY_LIMIT: u64 = 1024 * 1024;
static GENERATION: AtomicU64 = AtomicU64::new(0);

mod socket_control;
#[cfg(test)]
mod tests;
pub use socket_control::{action as socket_action, sync_rules as sync_socket_rules};
struct Request {
    id: u64,
    started: Instant,
    headers: Vec<(String, String)>,
    body: String,
    body_missing: bool,
    response_headers: Vec<(String, String)>,
    status: u16,
    source: &'static str,
}
struct Session {
    socket_controls: HashMap<String, (String, i64)>,
    socket_native_pending: VecDeque<(String, String)>,
    socket_js_pending: VecDeque<(String, String, i64)>,
    socket_contexts: HashMap<i64, String>,
    socket_script: Option<String>,
    target_id: String,
    generation: u64,
    core: Endpoint,
    store: Arc<Store>,
    requests: HashMap<String, Request>,
    subscriptions: Vec<(ICoreWebView2DevToolsProtocolEventReceiver, i64)>,
    route: Upstream,
    auth_attempts: HashSet<String>,
    auth_order: VecDeque<String>,
    children: HashMap<String, Rc<RefCell<Session>>>,
    sockets: HashMap<String, (u64, Instant)>,
    source: &'static str,
    mocked: Rc<RefCell<HashSet<String>>>,
    native_mocks: Rc<RefCell<VecDeque<(String, String)>>>,
    resource_token: Option<i64>,
}

#[derive(Clone)]
struct Endpoint {
    core: ICoreWebView2,
    id: String,
    intercept: bool,
}

impl Session {
    fn new(
        generation: u64,
        core: Endpoint,
        store: Arc<Store>,
        route: Upstream,
        source: &'static str,
    ) -> Self {
        Self {
            socket_controls: HashMap::new(),
            socket_native_pending: VecDeque::new(),
            socket_js_pending: VecDeque::new(),
            socket_contexts: HashMap::new(),
            socket_script: None,
            target_id: String::new(),
            mocked: Rc::new(RefCell::new(HashSet::new())),
            native_mocks: Rc::new(RefCell::new(VecDeque::new())),
            resource_token: None,
            generation,
            core,
            store,
            route,
            source,
            requests: HashMap::new(),
            subscriptions: vec![],
            auth_attempts: HashSet::new(),
            auth_order: VecDeque::new(),
            children: HashMap::new(),
            sockets: HashMap::new(),
        }
    }
}

fn proxy_url(route: &Upstream) -> Result<Option<tauri::Url>, String> {
    if !route.enabled {
        return Ok(None);
    }
    if route.basic_auth && !route.password_available {
        return Err("Enter and save the upstream proxy password in Settings before opening the application.".into());
    }
    let host = if route.host.contains(':') {
        format!("[{}]", route.host)
    } else {
        route.host.clone()
    };
    tauri::Url::parse(&format!("http://{host}:{}", route.port))
        .map(Some)
        .map_err(|_| "Invalid upstream proxy address".into())
}

fn auth_response(route: &Upstream, challenge: &Value, attempted: bool) -> Value {
    if challenge["source"] != "Proxy" {
        return json!({"response":"Default"});
    }
    let origin = tauri::Url::parse(&text(challenge, "origin")).ok();
    let matches = origin.as_ref().is_some_and(|origin| {
        origin.scheme() == "http"
            && origin.host_str().is_some_and(|host| {
                host.trim_matches(['[', ']'])
                    .eq_ignore_ascii_case(&route.host)
            })
            && origin.port_or_known_default() == Some(route.port)
    });
    if route.enabled
        && route.basic_auth
        && route.password_available
        && matches
        && !attempted
        && text(challenge, "scheme").eq_ignore_ascii_case("basic")
    {
        json!({"response":"ProvideCredentials","username":route.username,"password":route.password})
    } else {
        json!({"response":"CancelAuth"})
    }
}
thread_local! { static SESSION: RefCell<Option<Rc<RefCell<Session>>>> = const { RefCell::new(None) }; }

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(token) = self.resource_token {
            let _ = unsafe { self.core.core.remove_WebResourceRequested(token) };
        }
        for (receiver, token) in &self.subscriptions {
            let _ = unsafe { receiver.remove_DevToolsProtocolEventReceived(*token) };
        }
        for request in self.requests.values() {
            self.store.respond(
                request.id,
                499,
                request.started,
                "Application window closed".into(),
                self.source,
            );
        }
        for (id, _) in self.sockets.values() {
            self.store.socket_state(*id, "closed", None);
        }
    }
}

fn call(
    core: &Endpoint,
    method: &str,
    params: Value,
    done: impl FnOnce(Result<Value, String>) + 'static,
) {
    // Both synchronous COM errors and asynchronous protocol errors reach the caller once.
    let done = Rc::new(RefCell::new(Some(done)));
    let callback = done.clone();
    let handler =
        CallDevToolsProtocolMethodCompletedHandler::create(Box::new(move |status, result| {
            let result = status.map_err(|e| e.to_string()).and_then(|_| {
                let value: Value = serde_json::from_str(&result).map_err(|e| e.to_string())?;
                if let Some(error) = value.get("error") {
                    Err(error.to_string())
                } else {
                    Ok(value)
                }
            });
            if let Some(done) = callback.borrow_mut().take() {
                done(result);
            }
            Ok(())
        }));
    let result = unsafe {
        if core.id.is_empty() {
            core.core.CallDevToolsProtocolMethod(
                &HSTRING::from(method),
                &HSTRING::from(params.to_string()),
                &handler,
            )
        } else {
            core.core.cast::<ICoreWebView2_11>().and_then(|native| {
                native.CallDevToolsProtocolMethodForSession(
                    &HSTRING::from(&core.id),
                    &HSTRING::from(method),
                    &HSTRING::from(params.to_string()),
                    &handler,
                )
            })
        }
    };
    if let Err(error) = result {
        if let Some(done) = done.borrow_mut().take() {
            done(Err(error.to_string()));
        }
    }
}

fn initialize(core: Endpoint, done: impl FnOnce(Result<Value, String>) + 'static) {
    let next = core.clone();
    call(
        &core,
        "Network.enable",
        json!({"maxTotalBufferSize":if core.id.is_empty(){16*BODY_LIMIT}else{2*BODY_LIMIT},"maxResourceBufferSize":BODY_LIMIT,"maxPostDataSize":capture::PREVIEW_LIMIT}),
        move |result| {
            if result.is_err() {
                done(result.map_err(|e| format!("Network.enable: {e}")));
                return;
            }
            if !next.intercept {
                call(
                    &next,
                    "Target.setAutoAttach",
                    json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true,"filter":[{"type":"worker"},{"type":"iframe"},{"exclude":true}]}),
                    done,
                );
                return;
            }
            let attach = next.clone();
            call(
                &next,
                "Fetch.enable",
                json!({"handleAuthRequests":true,"patterns":[{"urlPattern":"http://*","requestStage":"Request"},{"urlPattern":"https://*","requestStage":"Request"}]}),
                move |result| {
                    if result.is_err() {
                        done(result.map_err(|e| format!("Fetch.enable: {e}")));
                        return;
                    }
                    let discover = attach.clone();
                    call(
                        &attach,
                        "Target.setAutoAttach",
                        json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true,"filter":[{"type":"worker"},{"type":"shared_worker"},{"type":"service_worker"},{"type":"iframe"},{"exclude":true}]}),
                        move |result| {
                            if let Err(error) = result {
                                done(Err(format!("Target.setAutoAttach: {error}")));
                                return;
                            }
                            if !discover.id.is_empty() {
                                done(result);
                                return;
                            }
                            call(
                                &discover,
                                "Target.setDiscoverTargets",
                                json!({"discover":true,"filter":[{"type":"shared_worker"},{"exclude":true}]}),
                                done,
                            );
                        },
                    );
                },
            );
        },
    );
}

fn dispatch(root: &Rc<RefCell<Session>>, target: &str, name: &str, value: Value) {
    if name == "Target.targetCreated" {
        let kind = text(&value["targetInfo"], "type");
        if kind != "shared_worker" {
            return;
        }
        let id = text(&value["targetInfo"], "targetId");
        let state = root.borrow();
        if state
            .children
            .values()
            .any(|child| child.borrow().target_id == id)
        {
            return;
        }
        let core = state.core.clone();
        let store = state.store.clone();
        drop(state);
        call(
            &core,
            "Target.attachToTarget",
            json!({"targetId":id,"flatten":true}),
            move |result| {
                if let Err(error) = result {
                    store.record(
                        "CAPTURE".into(),
                        "Worker capture".into(),
                        502,
                        Instant::now(),
                        error,
                        "worker",
                    );
                }
            },
        );
        return;
    }
    if name == "Target.attachedToTarget" {
        let id = text(&value, "sessionId");
        let mut state = root.borrow_mut();
        let core = Endpoint {
            core: state.core.core.clone(),
            id: id.clone(),
            intercept: value["targetInfo"]["type"] == "iframe",
        };
        if state.children.len() >= 64 {
            state.store.record(
                "CAPTURE".into(),
                "Worker capture".into(),
                503,
                Instant::now(),
                "Target limit reached (64)".into(),
                "worker",
            );
            let parent = state.core.clone();
            drop(state);
            call(
                &parent,
                "Target.detachFromTarget",
                json!({"sessionId":id}),
                |_| {},
            );
            return;
        }
        let child = Rc::new(RefCell::new(Session::new(
            state.generation,
            core.clone(),
            state.store.clone(),
            state.route.clone(),
            if value["targetInfo"]["type"] == "iframe" {
                "frame"
            } else {
                "worker"
            },
        )));
        child.borrow_mut().target_id = text(&value["targetInfo"], "targetId");
        child.borrow_mut().mocked = state.mocked.clone();
        child.borrow_mut().native_mocks = state.native_mocks.clone();
        state.children.insert(id, child.clone());
        let store = state.store.clone();
        drop(state);
        let resume = core.clone();
        let controls = child;
        let early_resume = (value["targetInfo"]["type"] == "service_worker").then(|| core.clone());
        initialize(core, move |result| {
            if let Err(error) = result {
                store.record(
                    "CAPTURE".into(),
                    "Worker capture".into(),
                    502,
                    Instant::now(),
                    error,
                    "worker",
                );
            }
            socket_control::install(controls, move |result| {
                if let Err(error) = result {
                    store.record(
                        "CAPTURE".into(),
                        "WebSocket controls".into(),
                        502,
                        Instant::now(),
                        error,
                        "worker",
                    );
                }
                call(
                    &resume,
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    |_| {},
                );
            });
        });
        // Service-worker startup can wait for the debugger before Network.enable completes.
        if let Some(core) = early_resume {
            call(&core, "Runtime.runIfWaitingForDebugger", json!({}), |_| {});
        }
        return;
    }
    if name == "Target.detachedFromTarget" {
        root.borrow_mut()
            .children
            .remove(&text(&value, "sessionId"));
        return;
    }
    let session = if target.is_empty() {
        Some(root.clone())
    } else {
        root.borrow().children.get(target).cloned()
    };
    if let Some(session) = session {
        if matches!(
            name,
            "Network.responseReceived" | "Network.loadingFinished" | "Network.loadingFailed"
        ) {
            let key = text(&value, "requestId");
            if !session.borrow().requests.contains_key(&key) {
                let mut candidates = vec![root.clone()];
                candidates.extend(root.borrow().children.values().cloned());
                let owners: Vec<_> = candidates
                    .into_iter()
                    .filter(|candidate| {
                        !Rc::ptr_eq(candidate, &session)
                            && candidate.borrow().requests.contains_key(&key)
                    })
                    .collect();
                if owners.len() == 1 {
                    if let Some(request) = owners[0].borrow_mut().requests.remove(&key) {
                        session.borrow_mut().requests.insert(key, request);
                    }
                }
            }
        }
        Session::event(&session, name, value);
    }
}

fn socket_message(value: &Value, direction: &str, started: Instant) -> SocketMessage {
    let opcode = value["opcode"].as_u64().unwrap_or_default() as u8;
    let payload = value["payloadData"].as_str().unwrap_or_default();
    let bytes = if opcode == 1 {
        payload.len() as u64
    } else {
        ((payload.len() / 4) * 3)
            .saturating_sub(payload.bytes().rev().take_while(|b| *b == b'=').count()) as u64
    };
    let mut end = payload.len().min(4096);
    while !payload.is_char_boundary(end) {
        end -= 1;
    }
    SocketMessage {
        kind: "wire".into(),
        direction: direction.into(),
        opcode,
        elapsed_ms: started.elapsed().as_millis(),
        payload: payload[..end].into(),
        bytes,
        truncated: end < payload.len(),
    }
}

// Shared/service workers do not support the Fetch domain. Their native request
// hook delivers mocks while their CDP sessions provide request/response capture.
fn install_worker_mocks(
    root: &Rc<RefCell<Session>>,
    environment: ICoreWebView2Environment,
) -> Result<(), String> {
    let core = root.borrow().core.core.clone();
    let extended = core
        .cast::<ICoreWebView2_22>()
        .map_err(|_| "Update WebView2 to enable worker mocking".to_string())?;
    unsafe {
        extended.AddWebResourceRequestedFilterWithRequestSourceKinds(
            &HSTRING::from("*"),
            COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL,
            COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS(
                COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_SHARED_WORKER.0
                    | COREWEBVIEW2_WEB_RESOURCE_REQUEST_SOURCE_KINDS_SERVICE_WORKER.0,
            ),
        )
    }
    .map_err(|e| e.to_string())?;
    let weak = Rc::downgrade(root);
    let handler = WebResourceRequestedEventHandler::create(Box::new(move |_, args| {
        let (Some(root), Some(args)) = (weak.upgrade(), args) else {
            return Ok(());
        };
        let request = unsafe { args.Request()? };
        let mut raw = PWSTR::null();
        unsafe {
            request.Method(&mut raw)?;
        }
        let method = CoTaskMemPWSTR::from(raw).to_string();
        let mut raw = PWSTR::null();
        unsafe {
            request.Uri(&mut raw)?;
        }
        let url = CoTaskMemPWSTR::from(raw).to_string();
        let native_headers = unsafe { request.Headers()? };
        let mut headers = vec![];
        for name in [
            "origin",
            "access-control-request-method",
            "access-control-request-headers",
        ] {
            let mut raw = PWSTR::null();
            if unsafe { native_headers.GetHeader(&HSTRING::from(name), &mut raw) }.is_ok() {
                headers.push((name.into(), CoTaskMemPWSTR::from(raw).to_string()));
            }
        }
        let result = mock_response(
            &root.borrow().store.rules.lock().unwrap(),
            &method,
            &url,
            &headers,
        );
        let Some(result) = result else {
            return Ok(());
        };
        let body = STANDARD
            .decode(result["body"].as_str().unwrap_or_default())
            .unwrap_or_default();
        let response_headers = result["responseHeaders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|header| format!("{}: {}\r\n", text(header, "name"), text(header, "value")))
            .collect::<String>();
        let deliver = || -> windows::core::Result<()> {
            let stream = unsafe { windows::Win32::UI::Shell::SHCreateMemStream(Some(&body)) }
                .ok_or_else(windows::core::Error::from_thread)?;
            let response = unsafe {
                environment.CreateWebResourceResponse(
                    &stream,
                    result["responseCode"].as_i64().unwrap_or(200) as i32,
                    &HSTRING::from("Mock"),
                    &HSTRING::from(response_headers),
                )?
            };
            unsafe { args.SetResponse(&response) }
        };
        if let Err(error) = deliver() {
            let _ = unsafe { root.borrow().core.core.Stop() };
            return Err(error);
        }
        let state = root.borrow_mut();
        let ids: HashSet<u64> = state
            .store
            .traffic
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.method == method && entry.url == url && entry.status == 0)
            .map(|entry| entry.id)
            .collect();
        let mut sessions = vec![root.clone()];
        sessions.extend(state.children.values().cloned());
        let markers = state.native_mocks.clone();
        drop(state);
        let mut matched = false;
        for session in sessions {
            for request in session.borrow_mut().requests.values_mut() {
                if ids.contains(&request.id) {
                    request.source = "mock";
                    matched = true;
                }
            }
        }
        if !matched && markers.borrow().len() < 1000 {
            markers.borrow_mut().push_back((method, url));
        }
        Ok(())
    }));
    let mut token = 0;
    unsafe { core.add_WebResourceRequested(&handler, &mut token) }.map_err(|e| e.to_string())?;
    root.borrow_mut().resource_token = Some(token);
    Ok(())
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().into()
}
fn headers(value: &Value) -> Vec<(String, String)> {
    let mut remaining = capture::PREVIEW_LIMIT;
    value
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(name, value)| {
            let value = value.as_str()?;
            let size = name.len() + value.len();
            if size > remaining || name.eq_ignore_ascii_case("proxy-authorization") {
                return None;
            }
            remaining -= size;
            Some((name.clone(), value.into()))
        })
        .collect()
}
fn header<'a>(rows: &'a [(String, String)], name: &str) -> Option<&'a str> {
    rows.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}
fn preview(body: &str, missing: bool) -> BodyPreview {
    let mut result = capture::body_preview(body.as_bytes(), &hyper::HeaderMap::new(), false);
    result.available = !missing;
    result
}
fn mock_response(
    rules: &[MockRule],
    method: &str,
    url: &str,
    request_headers: &[(String, String)],
) -> Option<Value> {
    let url = tauri::Url::parse(url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().into(),
    };
    let exact = crate::mock_match::find(rules, method, &path, Some(request_headers));
    let requested = header(request_headers, "access-control-request-method");
    let preflight =
        if exact.is_none() && method == "OPTIONS" && header(request_headers, "origin").is_some() {
            requested.and_then(|requested| crate::mock_match::find(rules, requested, &path, None))
        } else {
            None
        };
    let rule = exact.or(preflight)?;
    let status = if exact.is_none() { 204 } else { rule.status };
    let mut response_headers = vec![json!({"name":"Content-Type", "value":rule.content_type})];
    if let Some(origin) = header(request_headers, "origin") {
        response_headers.extend([
            json!({"name":"Access-Control-Allow-Origin", "value":origin}),
            json!({"name":"Access-Control-Allow-Credentials", "value":"true"}),
            json!({"name":"Vary", "value":"Origin"}),
        ]);
        if preflight.is_some() {
            response_headers
                .push(json!({"name":"Access-Control-Allow-Methods", "value":requested.unwrap_or(&rule.method)}));
            if let Some(names) = header(request_headers, "access-control-request-headers") {
                response_headers
                    .push(json!({"name":"Access-Control-Allow-Headers", "value":names}));
            }
        }
    }
    if exact.is_some() {
        response_headers.extend(
            rule.response_headers
                .iter()
                .map(|pair| json!({"name":pair.name, "value":pair.value})),
        );
    }
    let body = if method == "HEAD" || [204, 205, 304].contains(&status) {
        ""
    } else {
        &rule.body
    };
    Some(
        json!({"responseCode":status, "responseHeaders":response_headers, "body":STANDARD.encode(body)}),
    )
}

impl Session {
    fn event(session: &Rc<RefCell<Self>>, name: &str, value: Value) {
        if socket_control::event(session, name, &value) {
            return;
        }
        if name == "Fetch.authRequired" {
            let mut state = session.borrow_mut();
            let id = text(&value, "requestId");
            let response = auth_response(
                &state.route,
                &value["authChallenge"],
                state.auth_attempts.contains(&id),
            );
            if response["response"] == "ProvideCredentials" {
                if state.auth_order.len() >= 1000 {
                    if let Some(oldest) = state.auth_order.pop_front() {
                        state.auth_attempts.remove(&oldest);
                    }
                }
                state.auth_attempts.insert(id.clone());
                state.auth_order.push_back(id.clone());
            }
            let core = state.core.clone();
            drop(state);
            let failed_core = core.clone();
            call(
                &core,
                "Fetch.continueWithAuth",
                json!({"requestId":id,"authChallengeResponse":response}),
                move |result| {
                    if result.is_err() {
                        call(
                            &failed_core,
                            "Fetch.failRequest",
                            json!({"requestId":id,"errorReason":"Failed"}),
                            |_| {},
                        );
                    }
                },
            );
            return;
        }
        if name == "Fetch.requestPaused" {
            let state = session.borrow();
            let request = &value["request"];
            let request_id = text(&value, "requestId");
            let network_id = text(&value, "networkId");
            let result = mock_response(
                &state.store.rules.lock().unwrap(),
                &text(request, "method"),
                &text(request, "url"),
                &headers(&request["headers"]),
            );
            let core = state.core.clone();
            drop(state);
            let (method, mut params) = match result {
                Some(params) => {
                    let mut state = session.borrow_mut();
                    if let Some(request) = state.requests.get_mut(&network_id) {
                        request.source = "mock";
                    }
                    for child in state.children.values() {
                        if let Some(request) = child.borrow_mut().requests.get_mut(&network_id) {
                            request.source = "mock";
                        }
                    }
                    if state.mocked.borrow().len() < 1000 {
                        state.mocked.borrow_mut().insert(network_id.clone());
                    }
                    ("Fetch.fulfillRequest", params)
                }
                None => ("Fetch.continueRequest", json!({})),
            };
            params["requestId"] = json!(request_id);
            let failed_core = core.clone();
            call(&core, method, params, move |result| {
                if result.is_err() {
                    // A failed mock must never fall through to the real backend.
                    call(
                        &failed_core,
                        "Fetch.failRequest",
                        json!({"requestId":request_id,"errorReason":"Failed"}),
                        |_| {},
                    );
                }
            });
            return;
        }
        let key = text(&value, "requestId");
        let mut state = session.borrow_mut();
        if matches!(name, "Network.loadingFinished" | "Network.loadingFailed") {
            state.mocked.borrow_mut().remove(&key);
        }
        if name.starts_with("Network.webSocket") {
            match name {
                "Network.webSocketCreated" => {
                    if state.sockets.len() >= 1000 {
                        return;
                    }
                    let started = Instant::now();
                    let id = state.store.record(
                        "WS".into(),
                        text(&value, "url"),
                        0,
                        started,
                        String::new(),
                        state.source,
                    );
                    state.store.socket_state(id, "connecting", None);
                    state
                        .socket_native_pending
                        .push_back((key.clone(), text(&value, "url")));
                    state.sockets.insert(key, (id, started));
                    socket_control::pair(&mut state);
                }
                "Network.webSocketWillSendHandshakeRequest" => {
                    if let Some((id, _)) = state.sockets.get(&key) {
                        state.store.inspect(
                            *id,
                            headers(&value["request"]["headers"]),
                            vec![],
                            preview("", false),
                            false,
                        );
                    }
                }
                "Network.webSocketHandshakeResponseReceived" => {
                    if let Some((id, started)) = state.sockets.get(&key) {
                        let request_headers = state
                            .store
                            .traffic
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|r| r.id == *id)
                            .map(|r| r.request_headers.clone())
                            .unwrap_or_default();
                        let status = value["response"]["status"].as_f64().unwrap_or(101.0) as u16;
                        state
                            .store
                            .respond(*id, status, *started, String::new(), state.source);
                        state.store.inspect(
                            *id,
                            request_headers,
                            headers(&value["response"]["headers"]),
                            preview("", false),
                            false,
                        );
                        state.store.socket_state(
                            *id,
                            if status == 101 { "open" } else { "failed" },
                            None,
                        );
                    }
                }
                "Network.webSocketFrameSent" | "Network.webSocketFrameReceived" => {
                    if let Some((id, started)) = state.sockets.get(&key) {
                        state.store.socket_message(
                            *id,
                            socket_message(
                                &value["response"],
                                if name.ends_with("Sent") { "out" } else { "in" },
                                *started,
                            ),
                        );
                    }
                }
                "Network.webSocketFrameError" => {
                    if let Some((id, _)) = state.sockets.get(&key) {
                        state
                            .store
                            .socket_state(*id, "failed", Some(text(&value, "errorMessage")));
                    }
                }
                "Network.webSocketClosed" => {
                    state.socket_controls.remove(&key);
                    state
                        .socket_native_pending
                        .retain(|(pending, _)| pending != &key);
                    if let Some((id, _)) = state.sockets.remove(&key) {
                        let failed = state
                            .store
                            .traffic
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|r| r.id == id && r.body_state == "failed");
                        if !failed {
                            state.store.socket_state(id, "closed", None);
                        }
                    }
                }
                _ => {}
            }
            return;
        }
        match name {
            "Network.requestWillBeSent" => {
                let request = &value["request"];
                let url = text(request, "url");
                if !url.starts_with("http://") && !url.starts_with("https://") {
                    return;
                }
                if let Some(previous) = state.requests.remove(&key) {
                    let status = value["redirectResponse"]["status"].as_u64().unwrap_or(302) as u16;
                    state.store.respond(
                        previous.id,
                        status,
                        previous.started,
                        String::new(),
                        previous.source,
                    );
                    state.store.inspect(
                        previous.id,
                        previous.headers,
                        headers(&value["redirectResponse"]["headers"]),
                        preview(&previous.body, previous.body_missing),
                        false,
                    );
                }
                if state.requests.len() >= if state.core.id.is_empty() { 1000 } else { 128 } {
                    if let Some(oldest) = state
                        .requests
                        .iter()
                        .min_by_key(|(_, r)| r.started)
                        .map(|(key, _)| key.clone())
                    {
                        if let Some(old) = state.requests.remove(&oldest) {
                            state.store.respond(
                                old.id,
                                499,
                                old.started,
                                "Capture capacity exceeded".into(),
                                old.source,
                            );
                        }
                    }
                }
                let started = Instant::now();
                let id = state.store.record(
                    text(request, "method"),
                    url,
                    0,
                    started,
                    String::new(),
                    state.source,
                );
                let row = Request {
                    id,
                    started,
                    headers: headers(&request["headers"]),
                    body: text(request, "postData"),
                    body_missing: request["hasPostData"].as_bool().unwrap_or(false)
                        && request["postData"].is_null(),
                    response_headers: vec![],
                    status: 0,
                    source: if state.mocked.borrow_mut().remove(&key) || {
                        let mut markers = state.native_mocks.borrow_mut();
                        let index = markers.iter().position(|(method, url)| {
                            method == request["method"].as_str().unwrap_or_default()
                                && url == request["url"].as_str().unwrap_or_default()
                        });
                        index.is_some_and(|index| markers.remove(index).is_some())
                    } {
                        "mock"
                    } else {
                        state.source
                    },
                };
                state.store.inspect(
                    id,
                    row.headers.clone(),
                    vec![],
                    preview(&row.body, row.body_missing),
                    true,
                );
                state.requests.insert(key, row);
            }
            "Network.responseReceived" => {
                let store = state.store.clone();
                if let Some(request) = state.requests.get_mut(&key) {
                    request.status =
                        value["response"]["status"].as_u64().unwrap_or_default() as u16;
                    request.response_headers = headers(&value["response"]["headers"]);
                    store.respond(
                        request.id,
                        request.status,
                        request.started,
                        String::new(),
                        request.source,
                    );
                    store.inspect(
                        request.id,
                        request.headers.clone(),
                        request.response_headers.clone(),
                        preview(&request.body, request.body_missing),
                        true,
                    );
                }
            }
            "Network.loadingFailed" => {
                if let Some(request) = state.requests.remove(&key) {
                    state.store.respond(
                        request.id,
                        499,
                        request.started,
                        text(&value, "errorText"),
                        request.source,
                    );
                }
            }
            "Network.loadingFinished" => {
                let Some(request) = state.requests.remove(&key) else {
                    return;
                };
                let bytes = value["encodedDataLength"]
                    .as_f64()
                    .unwrap_or_default()
                    .max(0.0) as u64;
                if bytes > BODY_LIMIT {
                    state.store.finish_response(
                        request.id,
                        BodyPreview {
                            text: "Body exceeds capture limit (1 MiB)".into(),
                            truncated: true,
                            available: false,
                        },
                        bytes,
                        "complete",
                    );
                    return;
                }
                let store = state.store.clone();
                let core = state.core.clone();
                drop(state);
                call(
                    &core,
                    "Network.getResponseBody",
                    json!({"requestId":key}),
                    move |result| {
                        let body = result.and_then(|value| {
                            let body = text(&value, "body");
                            if value["base64Encoded"].as_bool() == Some(true) {
                                STANDARD.decode(body).map_err(|e| e.to_string())
                            } else {
                                Ok(body.into_bytes())
                            }
                        });
                        let body = match body {
                            Ok(body) => {
                                capture::body_preview(&body, &hyper::HeaderMap::new(), false)
                            }
                            Err(_) => BodyPreview {
                                text: "Response body unavailable".into(),
                                truncated: false,
                                available: false,
                            },
                        };
                        store.finish_response(request.id, body, bytes, "complete");
                    },
                );
            }
            _ => {}
        }
    }
}

pub async fn open(
    app: tauri::AppHandle,
    store: Arc<Store>,
    directory: PathBuf,
    address: String,
) -> Result<(), String> {
    let url = tauri::Url::parse(address.trim()).map_err(|_| "Enter a valid HTTP or HTTPS URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Enter an HTTP or HTTPS URL without credentials".into());
    }
    if app.get_webview_window("application").is_some() {
        return Err("Close the current application window first".into());
    }
    let route = store.upstream.lock().map_err(|e| e.to_string())?.clone();
    let proxy = proxy_url(&route)?;
    // WebView2 requires a separate browser environment when proxy arguments differ.
    let directory = if let Some(proxy) = &proxy {
        let fingerprint =
            Sha256::digest(format!("{}|{}|{}", proxy, route.username, route.basic_auth));
        directory.join(format!("proxy-{:x}", fingerprint))
    } else {
        directory
    };
    let mut builder = WebviewWindowBuilder::new(
        &app,
        "application",
        WebviewUrl::External("about:blank".parse().unwrap()),
    )
    .title("WireForge · Application")
    .inner_size(1200.0, 800.0)
    .data_directory(directory)
    .on_navigation(|url| matches!(url.scheme(), "http" | "https") || url.as_str() == "about:blank")
    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
    if let Some(proxy) = proxy {
        builder = builder.proxy_url(proxy);
    }
    let window = builder.build().map_err(|e| e.to_string())?;
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let cleanup_app = app.clone();
    window.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            let _ = cleanup_app.run_on_main_thread(move || {
                SESSION.with(|slot| {
                    let mut slot = slot.borrow_mut();
                    if slot
                        .as_ref()
                        .is_some_and(|session| session.borrow().generation == generation)
                    {
                        slot.take();
                    }
                })
            });
        }
    });
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let attached = window.with_webview(move |webview| {
        let setup = || -> Result<Rc<RefCell<Session>>, String> {
            let core = unsafe { webview.controller().CoreWebView2() }.map_err(|e| e.to_string())?;
            core.cast::<ICoreWebView2_11>()
                .map_err(|_| "Update WebView2 to enable worker capture".to_string())?;
            let session = Rc::new(RefCell::new(Session::new(
                generation,
                Endpoint {
                    core: core.clone(),
                    id: String::new(),
                    intercept: true,
                },
                store,
                route,
                "webview",
            )));
            install_worker_mocks(&session, webview.environment())?;
            for name in [
                "Network.requestWillBeSent",
                "Network.responseReceived",
                "Network.loadingFinished",
                "Network.loadingFailed",
                "Fetch.requestPaused",
                "Fetch.authRequired",
                "Target.attachedToTarget",
                "Target.detachedFromTarget",
                "Target.targetCreated",
                "Runtime.bindingCalled",
                "Runtime.executionContextCreated",
                "Runtime.executionContextDestroyed",
                "Runtime.executionContextsCleared",
                "Network.webSocketCreated",
                "Network.webSocketWillSendHandshakeRequest",
                "Network.webSocketHandshakeResponseReceived",
                "Network.webSocketFrameSent",
                "Network.webSocketFrameReceived",
                "Network.webSocketFrameError",
                "Network.webSocketClosed",
            ] {
                let receiver =
                    unsafe { core.GetDevToolsProtocolEventReceiver(&HSTRING::from(name)) }
                        .map_err(|e| e.to_string())?;
                let weak = Rc::downgrade(&session);
                let handler =
                    DevToolsProtocolEventReceivedEventHandler::create(Box::new(move |_, args| {
                        if let (Some(session), Some(args)) = (weak.upgrade(), args) {
                            let mut raw = PWSTR::null();
                            unsafe {
                                args.ParameterObjectAsJson(&mut raw)?;
                            }
                            let owned = CoTaskMemPWSTR::from(raw);
                            let mut raw_session = PWSTR::null();
                            let target = if let Ok(args) =
                                args.cast::<ICoreWebView2DevToolsProtocolEventReceivedEventArgs2>()
                            {
                                unsafe {
                                    args.SessionId(&mut raw_session)?;
                                }
                                CoTaskMemPWSTR::from(raw_session).to_string()
                            } else {
                                String::new()
                            };
                            if let Ok(value) = serde_json::from_str::<Value>(&owned.to_string()) {
                                dispatch(&session, &target, name, value);
                            }
                        }
                        Ok(())
                    }));
                let mut token = 0;
                unsafe { receiver.add_DevToolsProtocolEventReceived(&handler, &mut token) }
                    .map_err(|e| e.to_string())?;
                session.borrow_mut().subscriptions.push((receiver, token));
            }
            SESSION.with(|slot| *slot.borrow_mut() = Some(session.clone()));
            Ok(session)
        };
        match setup() {
            Err(error) => {
                let _ = sender.send(Err(error));
            }
            Ok(session) => {
                let core = session.borrow().core.clone();
                let navigate = core.core.clone();
                initialize(core, move |result| {
                    if let Err(error) = result {
                        let _ = sender.send(Err(error));
                        return;
                    }
                    socket_control::install(session, move |result| {
                        let result = result.and_then(|_| {
                            unsafe { navigate.Navigate(&HSTRING::from(url.as_str())) }
                                .map_err(|e| e.to_string())
                        });
                        let _ = sender.send(result);
                    });
                });
            }
        }
    });
    if let Err(error) = attached {
        let _ = window.close();
        return Err(error.to_string());
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(15), receiver)
        .await
        .map_err(|_| "WebView capture setup timed out".to_string())
        .and_then(|result| result.map_err(|e| e.to_string()))
        .and_then(|result| result);
    if result.is_err() {
        let _ = window.close();
    }
    result
}
