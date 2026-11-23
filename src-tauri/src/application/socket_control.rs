use super::*;

fn checked(result: Result<Value, String>) -> Result<Value, String> {
    result.and_then(|value| {
        if value.get("exceptionDetails").is_some() {
            Err("WebSocket controller could not execute in this context".into())
        } else {
            Ok(value)
        }
    })
}

pub(super) fn install(
    session: Rc<RefCell<Session>>,
    done: impl FnOnce(Result<Value, String>) + 'static,
) {
    let core = session.borrow().core.clone();
    if core.intercept {
        call(&core, "Page.enable", json!({}), move |result| {
            if result.is_err() {
                done(result);
            } else {
                install_inner(session, done);
            }
        });
    } else {
        install_inner(session, done);
    }
}

fn install_inner(
    session: Rc<RefCell<Session>>,
    done: impl FnOnce(Result<Value, String>) + 'static,
) {
    let core = session.borrow().core.clone();
    let enable = core.clone();
    call(
        &core,
        "Runtime.addBinding",
        json!({"name":"__wireforgeSocketEvent"}),
        move |result| {
            if result.is_err() {
                done(result);
                return;
            }
            let evaluate = enable.clone();
            call(&enable, "Runtime.enable", json!({}), move |result| {
                if result.is_err() {
                    done(result);
                    return;
                }
                let source =
                    crate::socket::script(&session.borrow().store.socket_rules.lock().unwrap());
                if evaluate.intercept {
                    let remove = evaluate.clone();
                    call(
                        &evaluate,
                        "Page.addScriptToEvaluateOnNewDocument",
                        json!({"source":source,"runImmediately":true}),
                        move |result| {
                            let result = match result {
                                Ok(value) => value,
                                Err(error) => {
                                    done(Err(error));
                                    return;
                                }
                            };
                            let old = session
                                .borrow_mut()
                                .socket_script
                                .replace(text(&result, "identifier"));
                            if let Some(identifier) = old {
                                call(
                                    &remove,
                                    "Page.removeScriptToEvaluateOnNewDocument",
                                    json!({"identifier":identifier}),
                                    done,
                                );
                            } else {
                                done(Ok(result));
                            }
                        },
                    );
                } else {
                    call(
                        &evaluate,
                        "Runtime.evaluate",
                        json!({"expression":source,"returnByValue":true}),
                        move |result| done(checked(result)),
                    );
                }
            });
        },
    );
}

pub(super) fn pair(state: &mut Session) {
    let mut index = 0;
    while index < state.socket_js_pending.len() {
        let (_, url, _) = &state.socket_js_pending[index];
        if let Some(native) = state
            .socket_native_pending
            .iter()
            .position(|(_, native_url)| native_url == url)
        {
            let (key, _) = state.socket_native_pending.remove(native).unwrap();
            let (js_id, _, context) = state.socket_js_pending.remove(index).unwrap();
            if let Some((id, _)) = state.sockets.get(&key) {
                state.store.socket_control(*id, true);
                state.socket_controls.insert(key, (js_id, context));
            }
        } else {
            index += 1;
        }
    }
}

pub(super) fn event(session: &Rc<RefCell<Session>>, name: &str, value: &Value) -> bool {
    let mut state = session.borrow_mut();
    match name {
        "Runtime.executionContextCreated" => {
            if value["context"]["auxData"]["isDefault"].as_bool() != Some(false) {
                if let Some(id) = value["context"]["id"].as_i64() {
                    if state.socket_contexts.len() < 256 {
                        let unique = text(&value["context"], "uniqueId");
                        if !unique.is_empty() {
                            state.socket_contexts.insert(id, unique);
                        }
                    }
                }
            }
        }
        "Runtime.executionContextDestroyed" | "Runtime.executionContextsCleared" => {
            let context = value["executionContextId"].as_i64();
            let keys: Vec<_> = state
                .socket_controls
                .iter()
                .filter(|(_, (_, id))| context.is_none_or(|context| context == *id))
                .map(|(key, _)| key.clone())
                .collect();
            for key in keys {
                state.socket_controls.remove(&key);
                if let Some((id, _)) = state.sockets.get(&key) {
                    state.store.socket_control(*id, false);
                }
            }
            state
                .socket_js_pending
                .retain(|(_, _, id)| context.is_some_and(|context| context != *id));
            if let Some(context) = context {
                state.socket_contexts.remove(&context);
            } else {
                state.socket_contexts.clear();
                state.socket_native_pending.clear();
            }
        }
        "Runtime.bindingCalled" => {
            if value["name"] != "__wireforgeSocketEvent" {
                return true;
            }
            let Some(context) = value["executionContextId"].as_i64() else {
                return true;
            };
            if !state.socket_contexts.contains_key(&context) {
                return true;
            }
            let payload = text(value, "payload");
            if payload.len() > 32768 {
                return true;
            }
            let Ok(value) = serde_json::from_str::<Value>(&payload) else {
                return true;
            };
            let js_id = text(&value, "id");
            if js_id.len() > 64 {
                return true;
            }
            match value["type"].as_str() {
                Some("created") => {
                    let url = text(&value, "url");
                    if state.socket_js_pending.len() < 1000 && url.len() < 8192 {
                        state.socket_js_pending.push_back((js_id, url, context));
                        pair(&mut state);
                    }
                }
                Some("message") => {
                    let Some(key) = state
                        .socket_controls
                        .iter()
                        .find(|(_, (id, ctx))| id == &js_id && ctx == &context)
                        .map(|(key, _)| key.clone())
                    else {
                        return true;
                    };
                    let Some((id, started)) = state.sockets.get(&key).copied() else {
                        return true;
                    };
                    let direction = text(&value, "direction");
                    let kind = text(&value, "kind");
                    if !["in", "out"].contains(&direction.as_str())
                        || !["mock", "blocked"].contains(&kind.as_str())
                    {
                        return true;
                    }
                    let mut message = socket_message(
                        &json!({"opcode":value["opcode"],"payloadData":value["payload"]}),
                        &direction,
                        started,
                    );
                    message.kind = kind;
                    message.bytes = value["bytes"]
                        .as_u64()
                        .unwrap_or(message.bytes)
                        .min(crate::socket::PAYLOAD_LIMIT as u64 * 16);
                    message.truncated |= value["truncated"].as_bool().unwrap_or(false);
                    state.store.socket_message(id, message);
                }
                _ => {}
            }
        }
        _ => return false,
    }
    true
}

pub async fn action(
    app: tauri::AppHandle,
    id: u64,
    action: String,
    payload: String,
    binary: bool,
) -> Result<(), String> {
    if !["send", "inject"].contains(&action.as_str()) {
        return Err("Unknown WebSocket action".into());
    }
    if payload.len() > crate::socket::PAYLOAD_LIMIT * 2 {
        return Err("Payload exceeds 64 KiB".into());
    }
    let size = if binary {
        STANDARD
            .decode(&payload)
            .map_err(|_| "Enter valid Base64")?
            .len()
    } else {
        payload.len()
    };
    if size > crate::socket::PAYLOAD_LIMIT {
        return Err("Payload exceeds 64 KiB".into());
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        SESSION.with(|slot| {
            let Some(root) = slot.borrow().clone() else {
                let _ = sender.send(Err("Open an application first".into()));
                return;
            };
            let mut sessions = vec![root.clone()];
            sessions.extend(root.borrow().children.values().cloned());
            let target = sessions.into_iter().find_map(|session| {
                let state = session.borrow();
                let key = state
                    .sockets
                    .iter()
                    .find(|(_, (entry, _))| *entry == id)
                    .map(|(key, _)| key)?;
                let (js_id, context) = state.socket_controls.get(key)?;
                let valid = state.store.traffic.lock().unwrap().iter().any(|entry| {
                    entry.id == id && entry.body_state == "open" && entry.socket_control
                });
                let unique = state.socket_contexts.get(context)?.clone();
                valid.then(|| (state.core.clone(), js_id.clone(), unique))
            });
            let Some((core, js_id, context)) = target else {
                let _ = sender.send(Err(
                    "Socket is closed or not controllable. Open a new connection.".into(),
                ));
                return;
            };
            let expression = format!(
                "globalThis.__wireforgeSocketControl_v1.act({},{},{},{})",
                json!(js_id),
                json!(action),
                json!(payload),
                binary
            );
            call(
                &core,
                "Runtime.evaluate",
                json!({"expression":expression,"uniqueContextId":context,"returnByValue":true}),
                move |result| {
                    let result = checked(result).and_then(|value| {
                        if value["result"]["value"] == true {
                            Ok(())
                        } else {
                            Err("Socket action was not completed".into())
                        }
                    });
                    let _ = sender.send(result);
                },
            );
        });
    })
    .map_err(|e| e.to_string())?;
    tokio::time::timeout(std::time::Duration::from_secs(5), receiver)
        .await
        .map_err(|_| "Socket action timed out; check traffic before retrying".to_string())?
        .map_err(|e| e.to_string())?
}

pub async fn sync_rules(app: tauri::AppHandle) -> Result<(), String> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    app.run_on_main_thread(move || {
        SESSION.with(|slot| {
            let Some(root) = slot.borrow().clone() else {
                let _ = sender.send(Ok(()));
                return;
            };
            let mut sessions = vec![root.clone()];
            sessions.extend(root.borrow().children.values().cloned());
            let remaining = Rc::new(RefCell::new((sessions.len(), Some(sender), None::<String>)));
            for session in sessions {
                let remaining = remaining.clone();
                install(session, move |result| {
                    let mut state = remaining.borrow_mut();
                    if let Err(error) = result {
                        state.2 = Some(error);
                    }
                    state.0 -= 1;
                    if state.0 == 0 {
                        if let Some(sender) = state.1.take() {
                            let result = state.2.take().map_or(Ok(()), Err);
                            let _ = sender.send(result);
                        }
                    }
                });
            }
        })
    })
    .map_err(|e| e.to_string())?;
    tokio::time::timeout(std::time::Duration::from_secs(10), receiver)
        .await
        .map_err(|_| "Updating socket controllers timed out".to_string())?
        .map_err(|e| e.to_string())?
}
