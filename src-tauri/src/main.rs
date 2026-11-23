#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod application;
mod capture;
mod key_protection;
mod proxy;
mod replay;
mod socket;
mod tls;
mod upstream;
mod workspace;
use proxy::{MockRule, Proxy, Store, TrafficEntry};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{Manager, State};
use upstream::{UpstreamInput, UpstreamView};
use workspace::WorkspaceFile;

struct Workspace {
    socket_edits: tokio::sync::Mutex<()>,
    proxy: tokio::sync::Mutex<Option<Proxy>>,
    store: Arc<Store>,
    file: Arc<Mutex<WorkspaceFile>>,
    directory: std::path::PathBuf,
    tls_warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    socket_rules: Option<Vec<socket::SocketRule>>,
    running: bool,
    application_open: bool,
    address: Option<String>,
    rules: Option<Vec<MockRule>>,
    traffic: Vec<TrafficEntry>,
    upstream: Option<UpstreamView>,
    workspace_path: Option<String>,
    startup_warning: Option<String>,
    tls: Option<tls::TlsSettings>,
    ca: Option<tls::CaInfo>,
    tls_warning: Option<String>,
}

#[tauri::command]
async fn start_proxy(state: State<'_, Workspace>) -> Result<(), String> {
    let mut proxy = state.proxy.lock().await;
    if proxy.is_none() {
        if let Some(warning) = state.file.lock().map_err(|e| e.to_string())?.warning() {
            return Err(warning);
        }
        {
            let config = state.store.upstream.lock().map_err(|e| e.to_string())?;
            if config.enabled && config.basic_auth && !config.password_available {
                return Err("Enter and save the upstream proxy password in Settings before starting the proxy.".into());
            }
        }
        if state.store.tls.lock().map_err(|e| e.to_string())?.enabled
            && state
                .store
                .authority
                .lock()
                .map_err(|e| e.to_string())?
                .is_none()
        {
            return Err("Prepare the inspection CA before enabling HTTPS inspection.".into());
        }
        *proxy = Some(Proxy::start("127.0.0.1:8080", state.store.clone()).await?);
    }
    Ok(())
}

#[tauri::command]
async fn stop_proxy(state: State<'_, Workspace>) -> Result<(), String> {
    let mut proxy = state.proxy.lock().await;
    if let Some(server) = proxy.take() {
        server.stop().await;
    }
    Ok(())
}

#[tauri::command]
async fn save_rules(rules: Vec<MockRule>, state: State<'_, Workspace>) -> Result<(), String> {
    proxy::validate_rules(&rules)?;
    let store = state.store.clone();
    let file = state.file.clone();
    tokio::task::spawn_blocking(move || {
        let file = file.lock().map_err(|e| e.to_string())?;
        let upstream = store.upstream.lock().map_err(|e| e.to_string())?.clone();
        let tls = store.tls.lock().map_err(|e| e.to_string())?.clone();
        file.save(
            &rules,
            &upstream,
            &tls,
            &store.socket_rules.lock().map_err(|e| e.to_string())?,
        )?;
        *store.rules.lock().map_err(|e| e.to_string())? = rules;
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn save_upstream(
    app: tauri::AppHandle,
    config: UpstreamInput,
    state: State<'_, Workspace>,
) -> Result<UpstreamView, String> {
    let proxy = state.proxy.lock().await;
    if proxy.is_some() {
        return Err("Stop the proxy before changing the upstream connection.".into());
    }
    if app.get_webview_window("application").is_some() {
        return Err("Close the application window before changing the upstream connection.".into());
    }
    let store = state.store.clone();
    let file = state.file.clone();
    tokio::task::spawn_blocking(move || {
        let file = file.lock().map_err(|e| e.to_string())?;
        let next = store
            .upstream
            .lock()
            .map_err(|e| e.to_string())?
            .updated(config)?;
        let rules = store.rules.lock().map_err(|e| e.to_string())?.clone();
        let tls = store.tls.lock().map_err(|e| e.to_string())?.clone();
        file.save(
            &rules,
            &next,
            &tls,
            &store.socket_rules.lock().map_err(|e| e.to_string())?,
        )?;
        let view = next.view();
        *store.upstream.lock().map_err(|e| e.to_string())? = next;
        Ok::<UpstreamView, String>(view)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn prepare_ca(state: State<'_, Workspace>) -> Result<tls::CaInfo, String> {
    let proxy = state.proxy.lock().await;
    if proxy.is_some() {
        return Err("Stop the proxy before preparing the inspection CA.".into());
    }
    let directory = state.directory.clone();
    let authority = tokio::task::spawn_blocking(move || tls::Authority::prepare(&directory))
        .await
        .map_err(|e| e.to_string())??;
    let info = authority.info.clone();
    *state.store.authority.lock().map_err(|e| e.to_string())? = Some(Arc::new(authority));
    Ok(info)
}

#[tauri::command]
async fn save_tls(
    mut config: tls::TlsSettings,
    state: State<'_, Workspace>,
) -> Result<tls::TlsSettings, String> {
    let proxy = state.proxy.lock().await;
    if proxy.is_some() {
        return Err("Stop the proxy before changing HTTPS inspection targets.".into());
    }
    for target in &mut config.targets {
        *target = target.trim().to_ascii_lowercase();
        if let Ok(authority) = target.parse::<hyper::http::uri::Authority>() {
            if let Some(port) = authority.port_u16() {
                *target = format!("{}:{port}", authority.host());
            }
        }
    }
    config.validate()?;
    if config.enabled
        && state
            .store
            .authority
            .lock()
            .map_err(|e| e.to_string())?
            .is_none()
    {
        return Err("Prepare the inspection CA first.".into());
    }
    let store = state.store.clone();
    let file = state.file.clone();
    tokio::task::spawn_blocking(move || {
        let file = file.lock().map_err(|e| e.to_string())?;
        let upstream = store.upstream.lock().map_err(|e| e.to_string())?.clone();
        let rules = store.rules.lock().map_err(|e| e.to_string())?.clone();
        file.save(
            &rules,
            &upstream,
            &config,
            &store.socket_rules.lock().map_err(|e| e.to_string())?,
        )?;
        *store.tls.lock().map_err(|e| e.to_string())? = config.clone();
        Ok::<_, String>(config)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn clear_traffic(state: State<'_, Workspace>) -> Result<(), String> {
    state.store.clear_history();
    Ok(())
}

#[tauri::command]
async fn replay_request(
    input: replay::ReplayInput,
    state: State<'_, Workspace>,
) -> Result<u16, String> {
    let address = state
        .proxy
        .lock()
        .await
        .as_ref()
        .map(|proxy| proxy.address)
        .ok_or("Start the proxy before replaying a request.")?;
    replay::send(address, input, state.store.clone()).await
}

#[tauri::command]
async fn get_snapshot(
    app: tauri::AppHandle,
    after_id: Option<u64>,
    state: State<'_, Workspace>,
) -> Result<Snapshot, String> {
    let proxy = state.proxy.lock().await;
    let (workspace_path, startup_warning) = if after_id.is_none() {
        let file = state.file.lock().map_err(|e| e.to_string())?;
        (Some(file.path()), file.warning())
    } else {
        (None, None)
    };
    Ok(Snapshot {
        socket_rules: if after_id.is_none() {
            Some(
                state
                    .store
                    .socket_rules
                    .lock()
                    .map_err(|e| e.to_string())?
                    .clone(),
            )
        } else {
            None
        },
        application_open: app.get_webview_window("application").is_some(),
        tls: if after_id.is_none() {
            Some(state.store.tls.lock().map_err(|e| e.to_string())?.clone())
        } else {
            None
        },
        ca: if after_id.is_none() {
            state
                .store
                .authority
                .lock()
                .map_err(|e| e.to_string())?
                .as_ref()
                .map(|authority| authority.info.clone())
        } else {
            None
        },
        tls_warning: if after_id.is_none() {
            state.tls_warning.clone()
        } else {
            None
        },
        workspace_path,
        startup_warning,
        upstream: if after_id.is_none() {
            Some(
                state
                    .store
                    .upstream
                    .lock()
                    .map_err(|e| e.to_string())?
                    .view(),
            )
        } else {
            None
        },
        running: proxy.is_some(),
        address: proxy.as_ref().map(|server| server.address.to_string()),
        rules: if after_id.is_none() {
            Some(state.store.rules.lock().map_err(|e| e.to_string())?.clone())
        } else {
            None
        },
        traffic: state
            .store
            .traffic
            .lock()
            .map_err(|e| e.to_string())?
            .iter()
            .filter(|entry| after_id.is_none_or(|id| entry.revision > id))
            .cloned()
            .collect(),
    })
}

#[tauri::command]
async fn open_application(
    app: tauri::AppHandle,
    state: State<'_, Workspace>,
    url: String,
) -> Result<(), String> {
    let _socket_edit = state.socket_edits.lock().await;
    let _connection_guard = state.proxy.lock().await;
    if let Some(warning) = state.file.lock().map_err(|e| e.to_string())?.warning() {
        return Err(warning);
    }
    #[cfg(windows)]
    {
        application::open(
            app,
            state.store.clone(),
            state.directory.join("application-profile"),
            url,
        )
        .await
    }
    #[cfg(not(windows))]
    {
        let _ = (app, state, url);
        Err("Application capture currently requires Windows WebView2".into())
    }
}

#[tauri::command]
async fn close_application(
    app: tauri::AppHandle,
    state: State<'_, Workspace>,
) -> Result<(), String> {
    let _socket_edit = state.socket_edits.lock().await;
    if let Some(window) = app.get_webview_window("application") {
        window.close().map_err(|e| e.to_string())?;
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while app.get_webview_window("application").is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .map_err(|_| "Application window did not close".to_string())
}

#[tauri::command]
async fn reload_application(
    app: tauri::AppHandle,
    state: State<'_, Workspace>,
) -> Result<(), String> {
    let _socket_edit = state.socket_edits.lock().await;
    let window = app
        .get_webview_window("application")
        .ok_or("Open an application first")?;
    window.reload().map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct SocketRulesSaved {
    rules: Vec<socket::SocketRule>,
    warning: Option<String>,
}

#[tauri::command]
async fn save_socket_rules(
    app: tauri::AppHandle,
    state: State<'_, Workspace>,
    rules: Vec<socket::SocketRule>,
) -> Result<SocketRulesSaved, String> {
    socket::validate(&rules)?;
    let _edit = state.socket_edits.lock().await;
    let store = state.store.clone();
    let file = state.file.clone();
    let next = rules.clone();
    tokio::task::spawn_blocking(move || {
        let file = file.lock().map_err(|e| e.to_string())?;
        let http = store.rules.lock().map_err(|e| e.to_string())?.clone();
        let upstream = store.upstream.lock().map_err(|e| e.to_string())?.clone();
        let tls = store.tls.lock().map_err(|e| e.to_string())?.clone();
        file.save(&http, &upstream, &tls, &next)?;
        *store.socket_rules.lock().map_err(|e| e.to_string())? = next;
        Ok::<(), String>(())
    })
    .await
    .map_err(|e| e.to_string())??;
    #[cfg(windows)]
    let warning = if let Err(error) = application::sync_socket_rules(app.clone()).await {
        if let Some(window) = app.get_webview_window("application") {
            let _ = window.destroy();
        }
        Some(format!(
            "Rules saved. Reopen the application to apply them. {error}"
        ))
    } else {
        None
    };
    #[cfg(not(windows))]
    let warning = {
        let _ = app;
        None
    };
    Ok(SocketRulesSaved { rules, warning })
}

#[tauri::command]
async fn socket_action(
    app: tauri::AppHandle,
    id: u64,
    action: String,
    payload: String,
    binary: bool,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        application::socket_action(app, id, action, payload, binary).await
    }
    #[cfg(not(windows))]
    {
        let _ = (app, id, action, payload, binary);
        Err("WebSocket controls require Windows WebView2".into())
    }
}

fn main() {
    let handlers: Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync> =
        Box::new(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            save_rules,
            save_upstream,
            get_snapshot,
            clear_traffic,
            replay_request,
            prepare_ca,
            save_tls,
            open_application,
            close_application,
            reload_application,
            save_socket_rules,
            socket_action
        ]);
    tauri::Builder::default()
        .on_window_event(|window, event| {
            if window.label() == "main" && matches!(event, tauri::WindowEvent::Destroyed) {
                if let Some(application) = window.app_handle().get_webview_window("application") {
                    let _ = application.destroy();
                }
            }
        })
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            let (file, saved) = WorkspaceFile::open(&directory).map_err(std::io::Error::other)?;
            let store = Store::default();
            *store.tls.lock().unwrap() = saved.tls;
            let tls_warning = match tls::Authority::load(&directory) {
                Ok(authority) => {
                    *store.authority.lock().unwrap() = authority.map(Arc::new);
                    None
                }
                Err(error) => Some(error),
            };
            *store.rules.lock().unwrap() = saved.rules;
            *store.socket_rules.lock().unwrap() = saved.socket_rules;
            *store.upstream.lock().unwrap() =
                saved.upstream.restore().map_err(std::io::Error::other)?;
            app.manage(Workspace {
                socket_edits: tokio::sync::Mutex::new(()),
                proxy: tokio::sync::Mutex::new(None),
                store: Arc::new(store),
                file: Arc::new(Mutex::new(file)),
                directory,
                tls_warning,
            });
            Ok(())
        })
        .invoke_handler(move |invoke| {
            if invoke.message.webview().label() != "main" {
                invoke
                    .resolver
                    .reject("Application windows cannot access WireForge commands");
                return true;
            }
            handlers(invoke)
        })
        .run(tauri::generate_context!())
        .expect("Could not launch WireForge");
}
