use super::*;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{service::service_fn, Response};
use hyper_util::rt::TokioIo;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn until(check: impl Fn() -> bool) -> Result<(), String> {
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        while !check() {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
    })
    .await
    .map_err(|_| "Socket control assertion timed out".into())
}

pub(super) async fn run(app: tauri::AppHandle, directory: PathBuf) -> Result<(), String> {
    let socket_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let ws_port = socket_listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::<(u8, Vec<u8>)>::new()));
    let backend = received.clone();
    let ws_server = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = socket_listener.accept().await else {
                break;
            };
            let backend = backend.clone();
            tokio::spawn(async move {
                let mut header = vec![];
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(socket.read_u8().await.unwrap());
                    assert!(header.len() < 16384);
                }
                let header = String::from_utf8(header).unwrap();
                let key = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(key, _)| key.eq_ignore_ascii_case("sec-websocket-key"))
                            .map(|(_, value)| value.trim())
                    })
                    .unwrap();
                let accept = STANDARD.encode(sha1::Sha1::digest(format!(
                    "{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                )));
                socket.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
                socket.write_all(b"\x81\x0fserver-original").await.unwrap();
                loop {
                    let Ok(first) = socket.read_u8().await else {
                        break;
                    };
                    let size = socket.read_u8().await.unwrap();
                    let opcode = first & 15;
                    let length = match size & 127 {
                        126 => socket.read_u16().await.unwrap() as usize,
                        127 => socket.read_u64().await.unwrap() as usize,
                        value => value as usize,
                    };
                    assert!(length <= 65536);
                    let mut mask = [0; 4];
                    if size & 128 != 0 {
                        socket.read_exact(&mut mask).await.unwrap();
                    }
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).await.unwrap();
                    if size & 128 != 0 {
                        for (index, byte) in body.iter_mut().enumerate() {
                            *byte ^= mask[index % 4];
                        }
                    }
                    if opcode == 8 {
                        let _ = socket.write_all(&[0x88, 0]).await;
                        break;
                    }
                    backend.lock().unwrap().push((opcode, body.clone()));
                    let response = if opcode == 1 {
                        [b"echo:".as_slice(), body.as_slice()].concat()
                    } else {
                        body
                    };
                    assert!(response.len() < 126);
                    socket
                        .write_all(&[0x80 | opcode, response.len() as u8])
                        .await
                        .unwrap();
                    socket.write_all(&response).await.unwrap();
                }
            });
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| e.to_string())?;
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let body = if request.uri().path() == "/" {
                        format!(
                            r#"<!doctype html><script>
                        const socket=new WebSocket('ws://127.0.0.1:{ws_port}/socket');socket.binaryType='arraybuffer';
                        socket.onopen=()=>socket.send('local-request');
                        socket.onmessage=e=>fetch(typeof e.data==='string'?'/observed?value='+encodeURIComponent(e.data):'/observed?binary='+e.data.byteLength);
                    </script>"#
                        )
                    } else {
                        String::new()
                    };
                    std::future::ready(Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .header("Content-Type", "text/html")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    ))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let store = Arc::new(Store::default());
    let url = format!("ws://127.0.0.1:{ws_port}/socket");
    *store.socket_rules.lock().unwrap() = vec![
        crate::socket::SocketRule {
            id: "reply".into(),
            url: url.clone(),
            direction: "out".into(),
            match_text: "local-request".into(),
            response_text: "local-response".into(),
            enabled: true,
        },
        crate::socket::SocketRule {
            id: "replace".into(),
            url,
            direction: "in".into(),
            match_text: "server-original".into(),
            response_text: "server-replaced".into(),
            enabled: true,
        },
    ];
    let result = async {
        open(
            app.clone(),
            store.clone(),
            directory,
            format!("http://127.0.0.1:{port}/"),
        )
        .await?;
        until(|| {
            store.traffic.lock().unwrap().iter().any(|entry| {
                entry.method == "WS"
                    && entry.body_state == "open"
                    && entry.socket_control
                    && entry.messages.iter().any(|message| {
                        message.kind == "mock" && message.payload == "local-response"
                    })
            })
        })
        .await?;
        let id = store
            .traffic
            .lock()
            .unwrap()
            .iter()
            .find(|entry| entry.method == "WS")
            .unwrap()
            .id;
        until(|| {
            store
                .traffic
                .lock()
                .unwrap()
                .iter()
                .any(|entry| entry.url.ends_with("/observed?value=server-replaced"))
        })
        .await?;
        if received
            .lock()
            .unwrap()
            .iter()
            .any(|(_, body)| body == b"local-request")
        {
            return Err("Mocked message reached backend".into());
        }
        socket_action(app.clone(), id, "send".into(), "replayed".into(), false).await?;
        until(|| {
            received
                .lock()
                .unwrap()
                .iter()
                .any(|(_, body)| body == b"replayed")
        })
        .await?;
        until(|| {
            store.traffic.lock().unwrap().iter().any(|entry| {
                entry
                    .messages
                    .iter()
                    .any(|message| message.payload == "echo:replayed" && message.kind == "wire")
            })
        })
        .await?;
        socket_action(
            app.clone(),
            id,
            "inject".into(),
            "manual-mock".into(),
            false,
        )
        .await?;
        until(|| {
            store
                .traffic
                .lock()
                .unwrap()
                .iter()
                .any(|entry| entry.url.ends_with("/observed?value=manual-mock"))
        })
        .await?;
        socket_action(app.clone(), id, "inject".into(), "AP8B".into(), true).await?;
        until(|| {
            store
                .traffic
                .lock()
                .unwrap()
                .iter()
                .any(|entry| entry.url.ends_with("/observed?binary=3"))
        })
        .await?;
        socket_action(app.clone(), id, "send".into(), "AP8B".into(), true).await?;
        until(|| {
            received
                .lock()
                .unwrap()
                .iter()
                .any(|(opcode, body)| *opcode == 2 && body == &[0, 255, 1])
        })
        .await?;
        if socket_action(app.clone(), id, "send".into(), "invalid%".into(), true)
            .await
            .is_ok()
        {
            return Err("Invalid Base64 was accepted".into());
        }
        if socket_action(app.clone(), id, "send".into(), "x".repeat(65537), false)
            .await
            .is_ok()
        {
            return Err("Oversized payload was accepted".into());
        }
        if socket_action(
            app.clone(),
            u64::MAX,
            "send".into(),
            "replayed".into(),
            false,
        )
        .await
        .is_ok()
        {
            return Err("Unknown socket was accepted".into());
        }
        store.socket_rules.lock().unwrap().clear();
        sync_socket_rules(app.clone()).await?;
        socket_action(
            app.clone(),
            id,
            "send".into(),
            "local-request".into(),
            false,
        )
        .await?;
        until(|| {
            received
                .lock()
                .unwrap()
                .iter()
                .any(|(_, body)| body == b"local-request")
        })
        .await?;
        app.get_webview_window("application")
            .unwrap()
            .reload()
            .map_err(|e| e.to_string())?;
        until(|| {
            received
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, body)| body == b"local-request")
                .count()
                >= 2
        })
        .await?;
        if socket_action(app.clone(), id, "send".into(), "stale".into(), false)
            .await
            .is_ok()
        {
            return Err("Stale socket was accepted after reload".into());
        }
        close_window(&app).await?;
        if socket_action(app.clone(), id, "inject".into(), "stale".into(), false)
            .await
            .is_ok()
        {
            return Err("Closed socket was accepted".into());
        }
        Ok::<(), String>(())
    }
    .await;
    server.abort();
    ws_server.abort();
    result.map_err(|error| {
        format!(
            "{error}; received={:?}; sockets={:?}",
            received.lock().unwrap(),
            store
                .traffic
                .lock()
                .unwrap()
                .iter()
                .filter(|entry| entry.method == "WS")
                .map(|entry| (
                    entry.status,
                    entry.socket_control,
                    &entry.body_state,
                    serde_json::to_string(&entry.messages).unwrap()
                ))
                .collect::<Vec<_>>()
        )
    })
}
