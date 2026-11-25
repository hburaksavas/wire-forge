use super::*;
mod socket_controls;

fn rule() -> MockRule {
    MockRule {
        id: "test".into(),
        method: "POST".into(),
        path: "/api/mock?version=1".into(),
        body: r#"{"mock":true}"#.into(),
        content_type: "application/json".into(),
        status: 201,
        enabled: true,
        ..Default::default()
    }
}

#[test]
fn mocks_match_method_and_query_and_preserve_cors() {
    let rules = vec![rule()];
    let request_headers = vec![("Origin".into(), "http://localhost:3000".into())];
    let result = mock_response(
        &rules,
        "POST",
        "https://test.example/api/mock?version=1",
        &request_headers,
    )
    .unwrap();
    assert_eq!(result["responseCode"], 201);
    assert_eq!(
        STANDARD.decode(result["body"].as_str().unwrap()).unwrap(),
        rules[0].body.as_bytes()
    );
    assert!(result["responseHeaders"]
        .as_array()
        .unwrap()
        .iter()
        .any(|header| header["name"] == "Access-Control-Allow-Origin"
            && header["value"] == "http://localhost:3000"));
    assert!(mock_response(
        &rules,
        "GET",
        "https://test.example/api/mock?version=1",
        &[]
    )
    .is_none());
    assert!(mock_response(
        &rules,
        "POST",
        "https://test.example/api/mock?version=2",
        &[]
    )
    .is_none());
    let mut disabled = rule();
    disabled.enabled = false;
    assert!(mock_response(
        &[disabled],
        "POST",
        "https://test.example/api/mock?version=1",
        &[]
    )
    .is_none());
}

#[test]
fn preflight_is_local_only_when_matching_enabled_mock_exists() {
    let headers = vec![
        ("origin".into(), "http://localhost:3000".into()),
        ("access-control-request-method".into(), "POST".into()),
        (
            "access-control-request-headers".into(),
            "content-type,x-test".into(),
        ),
    ];
    let result = mock_response(
        &[rule()],
        "OPTIONS",
        "https://test.example/api/mock?version=1",
        &headers,
    )
    .unwrap();
    assert_eq!(result["responseCode"], 204);
    assert_eq!(result["body"], "");
    assert!(result["responseHeaders"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |h| h["name"] == "Access-Control-Allow-Headers" && h["value"] == "content-type,x-test"
        ));
    assert!(mock_response(
        &[rule()],
        "OPTIONS",
        "https://test.example/api/live",
        &headers
    )
    .is_none());
}

#[test]
fn credentials_are_scoped_to_configured_proxy_and_not_retried() {
    let route = Upstream {
        enabled: true,
        host: "proxy.example".into(),
        port: 3128,
        basic_auth: true,
        username: "user".into(),
        password: "secret".into(),
        password_available: true,
    };
    let challenge = json!({"source":"Proxy","origin":"http://proxy.example:3128","scheme":"basic"});
    assert_eq!(
        auth_response(&route, &challenge, false)["response"],
        "ProvideCredentials"
    );
    assert_eq!(
        auth_response(&route, &challenge, true)["response"],
        "CancelAuth"
    );
    assert_eq!(
        auth_response(
            &route,
            &json!({"source":"Server","origin":"http://proxy.example:3128","scheme":"basic"}),
            false
        ),
        json!({"response":"Default"})
    );
    for origin in [
        "http://attacker.example:3128",
        "http://proxy.example:80",
        "https://proxy.example:3128",
    ] {
        assert_eq!(
            auth_response(
                &route,
                &json!({"source":"Proxy","origin":origin,"scheme":"basic"}),
                false
            ),
            json!({"response":"CancelAuth"})
        );
    }
    let mut missing = route.clone();
    missing.password_available = false;
    assert!(proxy_url(&missing).is_err());
    let mut ipv6 = route;
    ipv6.host = "::1".into();
    assert_eq!(
        proxy_url(&ipv6).unwrap().unwrap().as_str(),
        "http://[::1]:3128/"
    );
}

#[test]
fn websocket_history_is_bounded_and_clear_discards_late_frames() {
    let store = Store::default();
    let started = Instant::now();
    let id = store.record(
        "WS".into(),
        "ws://test/socket".into(),
        101,
        started,
        String::new(),
        "webview",
    );
    let value = json!({"opcode":1,"payloadData":"é".repeat(3000)});
    for _ in 0..100 {
        store.socket_message(id, socket_message(&value, "in", started));
    }
    {
        let traffic = store.traffic.lock().unwrap();
        let row = traffic.front().unwrap();
        assert!(row.messages.iter().map(|m| m.payload.len()).sum::<usize>() <= 16384);
        assert_eq!(row.response_bytes, 600000);
        assert!(row.messages_dropped > 0);
        assert!(row
            .messages
            .iter()
            .all(|m| m.truncated && m.payload.len() == 4096));
    }
    store.socket_state(id, "failed", Some("connection failed".into()));
    store.socket_state(id, "closed", None);
    assert_eq!(
        store.traffic.lock().unwrap().front().unwrap().body_state,
        "failed"
    );
    store.clear_history();
    store.socket_message(id, socket_message(&value, "out", started));
    assert!(store.traffic.lock().unwrap().is_empty());
}

async fn close_window(app: &tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("application") {
        window.close().map_err(|e| e.to_string())?;
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while app.get_webview_window("application").is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| "Application did not close".to_string())
}

async fn corporate_proxy_case(app: tauri::AppHandle, directory: PathBuf) -> Result<(), String> {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{service::service_fn, Response};
    use hyper_util::rt::TokioIo;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let authorized = Arc::new(AtomicUsize::new(0));
    let calls_server = calls.clone();
    let authorized_server = authorized.clone();
    let server = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let calls = calls_server.clone();
            let authorized = authorized_server.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let authorized_request = request
                        .headers()
                        .get("proxy-authorization")
                        .and_then(|v| v.to_str().ok())
                        == Some("Basic dXNlcjpzZWNyZXQ=");
                    let response = if !authorized_request {
                        Response::builder()
                            .status(407)
                            .header("Proxy-Authenticate", "Basic realm=\"WireForge test\"")
                            .body(Full::new(Bytes::new()))
                            .unwrap()
                    } else {
                        authorized.fetch_add(1, Ordering::Relaxed);
                        calls.lock().unwrap().push(request.uri().to_string());
                        let (body, mime) = if request.uri().path() == "/" {
                            (
                                r#"<!doctype html><script>(async()=>{
                              const mock=await fetch('http://api.wireforge.invalid/api/mock?version=1',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"test":true}'}).then(r=>r.json());
                              const live=await fetch('http://api.wireforge.invalid/api/live').then(r=>r.json());
                              await fetch('/proxy-done?mock='+mock.mock+'&live='+live.live);
                            })().catch(e=>fetch('/failed?error='+encodeURIComponent(e)));</script>"#,
                                "text/html",
                            )
                        } else {
                            (r#"{"live":true}"#, "application/json")
                        };
                        Response::builder()
                            .header("Content-Type", mime)
                            .header("Access-Control-Allow-Origin", "*")
                            .body(Full::new(Bytes::from_static(body.as_bytes())))
                            .unwrap()
                    };
                    std::future::ready(Ok::<_, std::convert::Infallible>(response))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let store = Arc::new(Store::default());
    store.rules.lock().unwrap().push(rule());
    *store.upstream.lock().unwrap() = Upstream {
        enabled: true,
        host: "127.0.0.1".into(),
        port,
        username: "user".into(),
        password: "secret".into(),
        password_available: true,
        basic_auth: true,
    };
    let result = async {
        open(
            app.clone(),
            store.clone(),
            directory,
            "http://frontend.wireforge.invalid/".into(),
        )
        .await?;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                {
                    let traffic = store.traffic.lock().unwrap();
                    if let Some(row) = traffic
                        .iter()
                        .find(|r| r.url.contains("/failed?") || r.status == 499)
                    {
                        return Err(format!(
                            "Proxy request failed: {} {}",
                            row.url, row.response_body
                        ));
                    }
                    if traffic.iter().any(|r| {
                        r.url.contains("/proxy-done?mock=true&live=true")
                            && r.body_state == "complete"
                    }) {
                        if authorized.load(Ordering::Relaxed) == 0 {
                            return Err("No authenticated proxy traffic".into());
                        }
                        let calls = calls.lock().unwrap();
                        if !calls
                            .iter()
                            .any(|url| url == "http://api.wireforge.invalid/api/live")
                        {
                            return Err("API did not use upstream proxy".into());
                        }
                        if calls.iter().any(|url| url.contains("/api/mock")) {
                            return Err("Mock reached corporate proxy".into());
                        }
                        return Ok(());
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "Corporate proxy test timed out".to_string())
        .and_then(|r| r)
    }
    .await;
    server.abort();
    close_window(&app).await?;
    result
}

async fn websocket_server() -> Result<(u16, tokio::task::JoinHandle<()>), String> {
    use sha1::Sha1;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(socket.read_u8().await.unwrap());
            assert!(headers.len() < 16384);
        }
        let headers = String::from_utf8(headers).unwrap();
        let key = headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-key"))
                    .map(|(_, value)| value.trim())
            })
            .unwrap();
        let accept = STANDARD.encode(Sha1::digest(format!(
            "{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        )));
        socket.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
        let first = socket.read_u8().await.unwrap();
        let length = socket.read_u8().await.unwrap();
        assert_eq!(first, 0x81);
        assert_eq!(length, 0x84);
        let mut mask = [0u8; 4];
        socket.read_exact(&mut mask).await.unwrap();
        let mut payload = [0u8; 4];
        socket.read_exact(&mut payload).await.unwrap();
        for i in 0..4 {
            payload[i] ^= mask[i];
        }
        assert_eq!(&payload, b"ping");
        socket
            .write_all(&[
                0x81, 4, b'p', b'o', b'n', b'g', 0x82, 3, 0, 255, 1, 0x88, 2, 0x03, 0xe8,
            ])
            .await
            .unwrap();
        let mut close = [0u8; 32];
        let _ = socket.read(&mut close).await;
    });
    Ok((port, task))
}

/// Requires the installed Windows WebView2 runtime and a desktop session.
#[test]
#[ignore]
fn native_webview_capture() {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{service::service_fn, Response};
    use hyper_util::rt::TokioIo;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let profile = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::default());
    store.rules.lock().unwrap().push(rule());
    let (result_sender, result_receiver) = std::sync::mpsc::channel();
    let mut context = tauri::generate_context!();
    context.config_mut().app.windows.clear();
    let app = tauri::Builder::default().any_thread().setup(move |app| {
        let app = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            let result = async {
                let (ws_port,ws_task) = websocket_server().await?;
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e|e.to_string())?;
                let port = listener.local_addr().unwrap().port();
                let backend_hits = Arc::new(AtomicUsize::new(0));
                let count = backend_hits.clone();
                let server = tokio::spawn(async move {
                    loop {
                        let Ok((socket,_)) = listener.accept().await else { break; };
                        let count = count.clone();
                        tokio::spawn(async move {
                            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                let path = request.uri().path().to_string();
                                if path == "/api/mock" { count.fetch_add(1,Ordering::Relaxed); }
                                let (status,body,content_type) = if path=="/" {
                                    (200,format!(r#"<!doctype html><script>
                                        (async()=>{{
                                          const mock=await fetch('http://localhost:{port}/api/mock?version=1',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:'{{"test":true}}'}}).then(r=>r.json());
                                          const live=await fetch('/redirect').then(r=>r.json());
                                          await fetch('/stage?name=dedicated');
                                          await new Promise((resolve,reject)=>{{const worker=new Worker('/worker.js');worker.onmessage=e=>{{if(e.data==='ok')resolve();else reject(e.data);}};worker.onerror=reject;}});
                                          await fetch('/stage?name=shared');
                                          await new Promise((resolve,reject)=>{{const worker=new SharedWorker('/shared.js');worker.port.onmessage=e=>{{if(e.data==='ok')resolve();else reject(e.data);worker.port.close();}};worker.onerror=reject;worker.port.start();}});
                                          await fetch('/stage?name=service');
                                          const registration=await navigator.serviceWorker.register('/sw.js',{{scope:'/sw-scope/'}});
                                          const service=registration.installing||registration.waiting||registration.active;
                                          if(service.state!=='activated') await new Promise((resolve,reject)=>{{service.addEventListener('statechange',()=>{{if(service.state==='activated')resolve();if(service.state==='redundant')reject('service worker failed');}});}});
                                          await registration.unregister();
                                          await fetch('/stage?name=websocket');
                                          await new Promise((resolve,reject)=>{{const socket=new WebSocket('ws://127.0.0.1:{ws_port}/socket');let text=false,binary=false;socket.onopen=()=>socket.send('ping');socket.onmessage=e=>{{if(typeof e.data==='string')text=e.data==='pong';else binary=true;}};socket.onerror=reject;socket.onclose=()=>text&&binary?resolve():reject('Missing socket messages');}});
                                          await fetch('/done?mock='+mock.mock+'&live='+live.live);
                                        }})().catch(e=>fetch('/failed?error='+encodeURIComponent(e)));
                                    </script>"#),"text/html")
                                } else if path=="/worker.js" { (200,r#"(async()=>{try{const live=await fetch('/api/worker-live').then(r=>r.json());const mock=await fetch('/api/mock?version=1',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"worker":true}'}).then(r=>r.json());postMessage(live.live&&mock.mock?'ok':'failed');}catch(e){postMessage(String(e));}})();"#.into(),"text/javascript") }
                                else if path=="/shared.js" { (200,r#"onconnect=async e=>{const port=e.ports[0];try{const live=await fetch('/api/shared-live').then(r=>r.json());const mock=await fetch('/api/mock?version=1',{method:'POST',body:'{"shared":true}'}).then(r=>r.json());port.postMessage(live.live&&mock.mock?'ok':'failed');}catch(e){port.postMessage(String(e));}};"#.into(),"text/javascript") }
                                else if path=="/sw.js" { (200,r#"self.addEventListener('install',e=>e.waitUntil((async()=>{const live=await fetch('/api/sw-live').then(r=>r.json());const mock=await fetch('/api/mock?version=1',{method:'POST',body:'{"service":true}'}).then(r=>r.json());if(!live.live||!mock.mock)throw Error('failed');await self.skipWaiting();})()));"#.into(),"text/javascript") }
                                else if path=="/redirect" { (302,String::new(),"text/plain") }
                                else { (200,r#"{"live":true}"#.into(),"application/json") };
                                let mut response = Response::builder().status(status).header("Content-Type",content_type).header("Access-Control-Allow-Origin","*");
                                if path=="/redirect" { response = response.header("Location","/api/live"); }
                                std::future::ready(Ok::<_,std::convert::Infallible>(response.body(Full::new(Bytes::from(body))).unwrap()))
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket),service).await;
                        });
                    }
                });
                open(app.clone(),store.clone(),profile.path().join("profile"),format!("http://127.0.0.1:{port}/")).await?;
                let result = tokio::time::timeout(std::time::Duration::from_secs(25),async {
                    loop {
                        {
                            let traffic = store.traffic.lock().unwrap();
                            if let Some(failed) = traffic.iter().find(|r|r.url.contains("/failed?")) { return Err(failed.url.clone()); }
                            if traffic.iter().any(|r|r.url.contains("/done?mock=true&live=true") && r.body_state=="complete") {
                                let mock = traffic.iter().find(|r|r.method=="POST" && r.url.contains("/api/mock")).ok_or("Missing mock capture")?;
                                if mock.source!="mock" || mock.status!=201 || !mock.response_body.contains("true") || !mock.request_body.contains("test") { return Err(format!("Incorrect mock capture: {} {} {} {}",mock.source,mock.status,mock.request_body,mock.response_body)); }
                                if !traffic.iter().any(|r|r.url.ends_with("/api/live") && r.response_body.contains("live")) { return Err("Missing live response body".into()); }
                                if !traffic.iter().any(|r|r.url.ends_with("/redirect") && r.status==302) { return Err("Missing redirect".into()); }
                                for path in ["/api/worker-live","/api/shared-live","/api/sw-live"] {
                                    if !traffic.iter().any(|r|r.url.ends_with(path) && r.source=="worker" && r.response_body.contains("live")) { return Err(format!("Missing worker capture: {path}")); }
                                }
                                for marker in ["worker","shared","service"] {
                                    if !traffic.iter().any(|r|r.request_body.contains(marker) && r.source=="mock" && r.response_body.contains("mock")) {return Err(format!("Missing worker mock capture: {marker}"));}
                                }
                                let socket=traffic.iter().find(|r|r.method=="WS").ok_or("Missing WebSocket")?;
                                if socket.status!=101 || socket.body_state!="closed" {return Err(format!("Incorrect socket state {} {}",socket.status,socket.body_state));}
                                for (direction,opcode,payload) in [("out",1,"ping"),("in",1,"pong"),("in",2,"AP8B")] {
                                    if !socket.messages.iter().any(|m|m.direction==direction && m.opcode==opcode && m.payload==payload) {return Err(format!("Missing socket message {direction} {opcode}"));}
                                }
                                if backend_hits.load(Ordering::Relaxed)!=0 { return Err("Mock reached real backend".into()); }
                                return Ok(());
                            }
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }).await.map_err(|_|format!("Native capture timed out: {:?}",store.traffic.lock().unwrap().iter().map(|r|(&r.method,&r.url,r.status,&r.source,&r.response_body)).collect::<Vec<_>>())).and_then(|r|r);
                server.abort();
                ws_task.abort();
                result?;
                close_window(&app).await?;
                corporate_proxy_case(app.clone(),profile.path().join("corporate")).await?;
                socket_controls::run(app.clone(),profile.path().join("socket-controls")).await
            }.await;
            let _ = result_sender.send(result);
            app.exit(0);
        });
        Ok(())
    }).build(context).unwrap();
    app.run_return(|_, event| {
        if let tauri::RunEvent::ExitRequested {
            code: None, api, ..
        } = event
        {
            api.prevent_exit();
        }
    });
    result_receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap()
        .unwrap();
}
