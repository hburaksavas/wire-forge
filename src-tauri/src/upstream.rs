use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, Request, Response};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct Upstream {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub password_available: bool,
    pub basic_auth: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamInput {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub basic_auth: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamView {
    enabled: bool,
    host: String,
    port: u16,
    username: String,
    basic_auth: bool,
    password_configured: bool,
}

impl Upstream {
    pub fn view(&self) -> UpstreamView {
        UpstreamView {
            enabled: self.enabled,
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            basic_auth: self.basic_auth,
            password_configured: self.password_available,
        }
    }

    pub fn updated(&self, input: UpstreamInput) -> Result<Self, String> {
        let host = input
            .host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        if input.enabled {
            if host.is_empty()
                || input.port == 0
                || host
                    .chars()
                    .any(|c| c.is_whitespace() || "/@?#\\".contains(c))
            {
                return Err(
                    "Enter a proxy hostname or IP address and a port from 1 to 65535.".into(),
                );
            }
            let valid = if host.contains(':') {
                host.parse::<std::net::Ipv6Addr>().is_ok()
            } else {
                host.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
            };
            if !valid {
                return Err("Enter a hostname or IP address without a URL scheme.".into());
            }
            if input.port == 8080
                && ["localhost", "127.0.0.1", "::1"].contains(&host.to_lowercase().as_str())
            {
                return Err("The upstream proxy cannot point to WireForge itself.".into());
            }
            if input.basic_auth
                && (input.username.is_empty()
                    || input.username.contains(':')
                    || input.username.chars().any(char::is_control))
            {
                return Err("Basic authentication requires a username without colons or control characters.".into());
            }
        }
        if input.basic_auth
            && input.password.is_none()
            && (host != self.host || input.port != self.port || input.username != self.username)
        {
            return Err(
                "Re-enter the password when changing the proxy host, port or username.".into(),
            );
        }
        Ok(Self {
            enabled: input.enabled,
            host,
            port: input.port,
            username: input.username,
            password_available: input.basic_auth
                && (input.password.is_some() || self.password_available),
            password: if input.basic_auth {
                input.password.unwrap_or_else(|| self.password.clone())
            } else {
                String::new()
            },
            basic_auth: input.basic_auth,
        })
    }

    // Called only after removing client-supplied hop-by-hop credentials.
    fn authorize(&self, request: &mut Request<Full<Bytes>>) {
        if self.basic_auth {
            let token = STANDARD.encode(format!("{}:{}", self.username, self.password));
            let mut value =
                hyper::header::HeaderValue::from_str(&format!("Basic {token}")).unwrap();
            value.set_sensitive(true);
            request
                .headers_mut()
                .insert(header::PROXY_AUTHORIZATION, value);
        }
    }

    pub async fn send(
        &self,
        mut request: Request<Full<Bytes>>,
        cancel: CancellationToken,
        upgrade: bool,
    ) -> Result<Response<Incoming>, Box<dyn std::error::Error + Send + Sync>> {
        let stream = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        self.authorize(&mut request);
        if !upgrade {
            request.headers_mut().insert(
                header::CONNECTION,
                hyper::header::HeaderValue::from_static("close"),
            );
        }
        tokio::spawn(async move {
            tokio::select! {
                _ = cancel.cancelled() => {},
                _ = connection.with_upgrades() => {},
            }
        });
        Ok(sender.send_request(request).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> UpstreamInput {
        UpstreamInput {
            enabled: true,
            host: "proxy.company.local".into(),
            port: 3128,
            username: "developer".into(),
            password: Some("session-secret".into()),
            basic_auth: true,
        }
    }

    #[test]
    fn validates_endpoint_and_never_serializes_password() {
        let saved = Upstream::default().updated(input()).unwrap();
        let view = serde_json::to_string(&saved.view()).unwrap();
        assert!(!view.contains("session-secret"));
        assert!(!view.contains("\"password\":"));
        assert!(view.contains("passwordConfigured"));
        assert!(saved
            .updated(UpstreamInput {
                host: "http://proxy.company.local".into(),
                ..input()
            })
            .is_err());
        assert!(saved
            .updated(UpstreamInput {
                host: "127.0.0.1".into(),
                port: 8080,
                ..input()
            })
            .is_err());
        assert!(saved
            .updated(UpstreamInput {
                username: "bad:user".into(),
                ..input()
            })
            .is_err());
        let unchanged = saved
            .updated(UpstreamInput {
                password: None,
                ..input()
            })
            .unwrap();
        assert_eq!(unchanged.password, "session-secret");
        assert!(saved
            .updated(UpstreamInput {
                host: "different.company.local".into(),
                password: None,
                ..input()
            })
            .is_err());
        assert!(saved
            .updated(UpstreamInput {
                enabled: false,
                host: "different.company.local".into(),
                password: None,
                ..input()
            })
            .is_err());
    }

    #[tokio::test]
    async fn anonymous_proxy_receives_no_proxy_authorization() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
            }
            assert!(!String::from_utf8(headers)
                .unwrap()
                .to_lowercase()
                .contains("proxy-authorization:"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let upstream = Upstream {
            enabled: true,
            host: "127.0.0.1".into(),
            port: address.port(),
            ..Default::default()
        };
        let request = Request::builder()
            .uri("http://destination.invalid/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            upstream.send(request, CancellationToken::new(), false),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.status(), hyper::StatusCode::OK);
        task.await.unwrap();
    }
}
