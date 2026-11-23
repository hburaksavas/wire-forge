use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use zeroize::Zeroizing;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsSettings {
    pub enabled: bool,
    pub all_hosts: bool,
    pub targets: Vec<String>,
}

impl TlsSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.targets.len() > 100 {
            return Err("Use at most 100 exact host:port targets.".into());
        }
        if self.enabled && !self.all_hosts && self.targets.is_empty() {
            return Err("Add at least one exact host:port target.".into());
        }
        if self.all_hosts {
            return Ok(());
        }
        for target in &self.targets {
            let authority: hyper::http::uri::Authority = target.parse().map_err(|_| {
                "Use exact host:port entries, for example api.company.local:443.".to_string()
            })?;
            if authority.port_u16().is_none_or(|port| port == 0)
                || authority.host().is_empty()
                || target.contains('@')
                || target.contains('*')
            {
                return Err(
                    "Use exact host:port entries, for example api.company.local:443.".into(),
                );
            }
            let host = authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            if rustls::pki_types::ServerName::try_from(host).is_err() {
                return Err(
                    "Use a valid DNS hostname or IP address in each inspection target.".into(),
                );
            }
        }
        Ok(())
    }

    pub fn matches(&self, target: &str) -> bool {
        self.enabled
            && (self.all_hosts
                || self
                    .targets
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(target)))
    }
}

#[derive(Serialize, Deserialize)]
struct SavedCa {
    certificate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protected_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protection: Option<String>,
}

impl SavedCa {
    fn protected(certificate: String, key: &str) -> Result<Self, String> {
        let encrypted = crate::key_protection::protect(key.as_bytes())?;
        Ok(Self {
            certificate,
            private_key: None,
            protected_key: Some(STANDARD.encode(&encrypted)),
            protection: Some("windows-dpapi-user-v1".into()),
        })
    }

    fn open_key(&mut self) -> Result<Zeroizing<String>, String> {
        match (
            &self.protection,
            &self.protected_key,
            self.private_key.take(),
        ) {
            (None, None, Some(legacy)) => Ok(Zeroizing::new(legacy)),
            (Some(mode), Some(encoded), None) if mode == "windows-dpapi-user-v1" => {
                if encoded.len() > 44 * 1024 {
                    return Err("The protected CA key exceeds the size limit.".into());
                }
                let encrypted = STANDARD
                    .decode(encoded)
                    .map_err(|_| "Invalid protected CA key encoding.".to_string())?;
                let decrypted = crate::key_protection::unprotect(&encrypted).map_err(|_| "The CA key could not be opened by this Windows user. Restore it under the original user profile.".to_string())?;
                let text = std::str::from_utf8(&decrypted)
                    .map_err(|_| "The protected CA key is invalid.".to_string())?;
                Ok(Zeroizing::new(text.to_owned()))
            }
            (_, _, legacy) => {
                let _erase = legacy.map(Zeroizing::new);
                Err("Unsupported or ambiguous inspection CA key format.".into())
            }
        }
    }

    fn persist(&self, directory: &Path) -> Result<(), String> {
        let mut temporary =
            tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
        serde_json::to_writer(temporary.as_file_mut(), self).map_err(|e| e.to_string())?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|e| e.to_string())?;
        temporary
            .persist(directory.join("inspection-ca.json"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaInfo {
    pub certificate_path: String,
    pub certificate_pem: String,
    pub fingerprint: String,
    pub key_protection: String,
}

pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    pub info: CaInfo,
    pub client_config: Arc<rustls::ClientConfig>,
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

fn client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        return Err(
            "No trusted upstream TLS roots were found in the system certificate store.".into(),
        );
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

impl Authority {
    pub fn replay_config(&self) -> Result<Arc<rustls::ClientConfig>, String> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in rustls_pemfile::certs(&mut self.info.certificate_pem.as_bytes()) {
            roots
                .add(certificate.map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
    pub fn load(directory: &Path) -> Result<Option<Self>, String> {
        let path = directory.join("inspection-ca.json");
        let bytes = match std::fs::read(path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let mut saved: SavedCa = serde_json::from_slice(&bytes)
            .map_err(|_| "The saved inspection CA could not be loaded.".to_string())?;
        let legacy = saved.private_key.is_some();
        let key = saved.open_key()?;
        let authority = Self::from_pem(&saved.certificate, &key, directory)?;
        if legacy {
            SavedCa::protected(saved.certificate.clone(), &key)?.persist(directory)?;
        }
        Ok(Some(authority))
    }

    pub fn prepare(directory: &Path) -> Result<Self, String> {
        if let Some(authority) = Self::load(directory)? {
            return Ok(authority);
        }
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "WireForge Local Inspection CA");
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
        let certificate = cert.pem();
        let private_key = Zeroizing::new(key.serialize_pem());
        let authority = Self::from_pem(&certificate, &private_key, directory)?;
        SavedCa::protected(certificate, &private_key)?.persist(directory)?;
        Ok(authority)
    }

    fn from_pem(certificate: &str, private_key: &str, directory: &Path) -> Result<Self, String> {
        let key = KeyPair::from_pem(private_key)
            .map_err(|_| "The inspection CA key could not be read.".to_string())?;
        let certificates: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut certificate.as_bytes())
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
        let root = certificates
            .first()
            .ok_or("The inspection CA certificate is missing.")?;
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            certificates.clone(),
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .map_err(|_| "The inspection CA certificate and key do not match.".to_string())?;
        let fingerprint = Sha256::digest(root.as_ref())
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let issuer = Issuer::from_ca_cert_pem(certificate, key).map_err(|e| e.to_string())?;
        let path = directory.join("wireforge-ca.pem");
        let mut public_file =
            tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
        public_file
            .write_all(certificate.as_bytes())
            .map_err(|e| e.to_string())?;
        public_file
            .as_file_mut()
            .sync_all()
            .map_err(|e| e.to_string())?;
        public_file.persist(&path).map_err(|e| e.to_string())?;
        Ok(Self {
            issuer,
            info: CaInfo {
                certificate_path: path.display().to_string(),
                certificate_pem: certificate.to_owned(),
                key_protection: "DPAPI".into(),
                fingerprint,
            },
            client_config: client_config()?,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        let mut cache = self.cache.lock().map_err(|e| e.to_string())?;
        if let Some(config) = cache.get(host) {
            return Ok(config.clone());
        }
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).map_err(|e| e.to_string())?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(7);
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|e| e.to_string())?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .map_err(|e| e.to_string())?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if cache.len() >= 128 {
            cache.clear();
        }
        cache.insert(host.to_owned(), config.clone());
        Ok(config)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::proxy::{MockRule, Proxy, Store};
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{header, Request};
    use hyper_util::rt::TokioIo;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    fn trust(ca: &Authority) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.info.certificate_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    async fn read_headers(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
        let mut result = Vec::new();
        while !result.ends_with(b"\r\n\r\n") {
            result.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(result).unwrap()
    }

    async fn get(
        address: std::net::SocketAddr,
        destination: &str,
        config: Arc<rustls::ClientConfig>,
        path: &str,
    ) -> Result<(u16, String), String> {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut stream = TcpStream::connect(address)
                .await
                .map_err(|e| e.to_string())?;
            stream
                .write_all(
                    format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .map_err(|e| e.to_string())?;
            let headers = read_headers(&mut stream).await;
            if !headers.starts_with("HTTP/1.1 200") {
                return Err(headers);
            }
            let authority: hyper::http::uri::Authority = destination.parse().unwrap();
            let host = authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            let name = rustls::pki_types::ServerName::try_from(host).unwrap();
            let tls = tokio_rustls::TlsConnector::from(config)
                .connect(name, stream)
                .await
                .map_err(|e| e.to_string())?;
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|e| e.to_string())?;
            let mut driver = tokio::task::JoinSet::new();
            driver.spawn(connection);
            let request = Request::builder()
                .uri(path)
                .header(header::HOST, destination)
                .header(header::CONNECTION, "close")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status().as_u16();
            let bytes = response
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok((status, String::from_utf8(bytes.to_vec()).unwrap()))
        })
        .await
        .map_err(|_| "TLS test timed out".to_string())?
    }

    #[test]
    fn ca_identity_persists_and_public_certificate_excludes_signing_key() {
        let directory = tempfile::tempdir().unwrap();
        let first = Authority::prepare(directory.path()).unwrap();
        let fingerprint = first.info.fingerprint.clone();
        assert_eq!(first.info.key_protection, "DPAPI");
        let stored = std::fs::read_to_string(directory.path().join("inspection-ca.json")).unwrap();
        assert!(!stored.contains("PRIVATE KEY"));
        let stored: serde_json::Value = serde_json::from_str(&stored).unwrap();
        assert!(stored.get("private_key").is_none());
        assert_eq!(stored["protection"], "windows-dpapi-user-v1");
        assert!(!first.info.certificate_pem.contains("PRIVATE KEY"));
        assert_eq!(
            std::fs::read_to_string(&first.info.certificate_path).unwrap(),
            first.info.certificate_pem
        );
        drop(first);
        let second = Authority::prepare(directory.path()).unwrap();
        assert_eq!(second.info.fingerprint, fingerprint);
        assert!(second.server_config("localhost").is_ok());
        assert!(second.server_config("127.0.0.1").is_ok());
    }

    #[test]
    fn migrates_legacy_key_without_changing_ca_identity() {
        let directory = tempfile::tempdir().unwrap();
        let first = Authority::prepare(directory.path()).unwrap();
        let path = directory.path().join("inspection-ca.json");
        let mut saved: SavedCa = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let key = saved.open_key().unwrap();
        let legacy =
            serde_json::json!({"certificate": saved.certificate, "private_key": key.as_str()});
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let loaded = Authority::load(directory.path()).unwrap().unwrap();
        assert_eq!(loaded.info.fingerprint, first.info.fingerprint);
        let migrated: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(migrated.get("private_key").is_none());
        assert_eq!(migrated["protection"], "windows-dpapi-user-v1");
        assert!(Authority::prepare(directory.path()).is_ok());
    }

    #[test]
    fn corrupted_key_is_preserved_and_ca_is_not_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let ca = Authority::prepare(directory.path()).unwrap();
        let path = directory.path().join("inspection-ca.json");
        let mut saved: SavedCa = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut encrypted = STANDARD
            .decode(saved.protected_key.as_ref().unwrap())
            .unwrap();
        let middle = encrypted.len() / 2;
        encrypted[middle] ^= 0x5a;
        saved.protected_key = Some(STANDARD.encode(encrypted));
        let corrupted = serde_json::to_vec(&saved).unwrap();
        std::fs::write(&path, &corrupted).unwrap();
        assert!(Authority::prepare(directory.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupted);
        assert_eq!(
            std::fs::read_to_string(&ca.info.certificate_path).unwrap(),
            ca.info.certificate_pem
        );
    }

    #[test]
    fn all_hosts_mode_requires_enabled_inspection() {
        let mut settings = TlsSettings {
            enabled: true,
            all_hosts: true,
            targets: vec![],
        };
        assert!(settings.validate().is_ok());
        assert!(settings.matches("any.example:443"));
        assert!(settings.matches("localhost:8443"));
        settings.enabled = false;
        assert!(!settings.matches("any.example:443"));
    }

    #[test]
    fn targets_require_exact_explicit_ports() {
        assert!(TlsSettings {
            all_hosts: false,
            enabled: true,
            targets: vec!["api.company.local:443".into()]
        }
        .validate()
        .is_ok());
        for target in [
            "*.company.local:443",
            "company.local",
            "user@company.local:443",
            "company.local:0",
        ] {
            assert!(
                TlsSettings {
                    all_hosts: false,
                    enabled: true,
                    targets: vec![target.into()]
                }
                .validate()
                .is_err(),
                "{target}"
            );
        }
        let settings = TlsSettings {
            all_hosts: false,
            enabled: true,
            targets: vec!["api.company.local:443".into()],
        };
        assert!(settings.matches("API.COMPANY.LOCAL:443"));
        assert!(!settings.matches("other.company.local:443"));
    }

    #[tokio::test]
    async fn trusted_client_can_mock_and_capture_https_without_contacting_target() {
        let directory = tempfile::tempdir().unwrap();
        let ca = Arc::new(Authority::prepare(directory.path()).unwrap());
        let client = trust(&ca);
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(ca);
        *store.tls.lock().unwrap() = TlsSettings {
            all_hosts: true,
            enabled: true,
            targets: vec![],
        };
        store.rules.lock().unwrap().push(MockRule {
            content_type: "application/json".into(),
            id: "tls".into(),
            method: "GET".into(),
            path: "/secure".into(),
            body: "{\"secure\":true}".into(),
            status: 201,
            enabled: true,
        });
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let (status, body) = get(proxy.address, "mock.invalid:443", client.clone(), "/secure")
            .await
            .unwrap();
        assert_eq!(status, 201);
        assert_eq!(body, "{\"secure\":true}");
        let traffic = store.traffic.lock().unwrap().back().unwrap().clone();
        assert_eq!(traffic.url, "https://mock.invalid:443/secure");
        assert_eq!(traffic.source, "mock");
        assert_eq!(traffic.response_body, body);
        let (status, _) = get(
            proxy.address,
            "mock.invalid:443",
            client,
            "https://different.invalid/secure",
        )
        .await
        .unwrap();
        assert_eq!(status, 421);
        proxy.stop().await;
    }

    #[tokio::test]
    async fn inspected_https_uses_authenticated_upstream_connect() {
        secure_chain(false, false).await;
    }

    #[tokio::test]
    async fn https_replay_uses_authenticated_upstream_connect() {
        secure_chain(true, false).await;
    }

    #[tokio::test]
    async fn binary_https_replay_uses_authenticated_upstream_connect() {
        secure_chain(true, true).await;
    }

    async fn secure_chain(replay: bool, binary: bool) {
        let origin_directory = tempfile::tempdir().unwrap();
        let origin_ca = Authority::prepare(origin_directory.path()).unwrap();
        let origin_config = origin_ca.server_config("localhost").unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let destination = format!("localhost:{}", origin_address.port());
        let origin_task = tokio::spawn(async move {
            let (socket, _) = origin.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(origin_config)
                .accept(socket)
                .await
                .unwrap();
            let request = read_headers(&mut tls).await.to_lowercase();
            assert!(request.starts_with(if binary {
                "post /secure http/1.1"
            } else {
                "get /secure http/1.1"
            }));
            if binary {
                let mut body = [0u8; 6];
                tls.read_exact(&mut body).await.unwrap();
                assert_eq!(body, [0, 255, 128, 13, 10, 65]);
            }
            assert!(!request.contains("proxy-authorization:"));
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").await.unwrap();
            tls.flush().await.unwrap();
        });
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let expected = destination.clone();
        let upstream_task = tokio::spawn(async move {
            let (mut client, _) = upstream.accept().await.unwrap();
            let request = read_headers(&mut client).await;
            assert!(request.starts_with(&format!("CONNECT {expected} HTTP/1.1")));
            assert!(request
                .to_lowercase()
                .contains("proxy-authorization: basic"));
            let mut origin = TcpStream::connect(origin_address).await.unwrap();
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
        });
        let directory = tempfile::tempdir().unwrap();
        let mut ca = Authority::prepare(directory.path()).unwrap();
        let client_config = trust(&ca);
        ca.client_config = trust(&origin_ca);
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(Arc::new(ca));
        *store.tls.lock().unwrap() = TlsSettings {
            all_hosts: false,
            enabled: true,
            targets: vec![destination.clone()],
        };
        *store.upstream.lock().unwrap() = crate::upstream::Upstream {
            enabled: true,
            host: "127.0.0.1".into(),
            port: upstream_address.port(),
            username: "developer".into(),
            password: "test-only".into(),
            password_available: true,
            basic_auth: true,
        };
        let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
        let (status, body) = if replay {
            let status = crate::replay::send(
                proxy.address,
                crate::replay::ReplayInput {
                    body_encoding: if binary {
                        crate::replay::BodyEncoding::Base64
                    } else {
                        crate::replay::BodyEncoding::Text
                    },
                    method: if binary { "POST" } else { "GET" }.into(),
                    url: format!("https://{destination}/secure"),
                    headers: vec![],
                    body: if binary {
                        STANDARD.encode([0, 255, 128, 13, 10, 65])
                    } else {
                        String::new()
                    },
                },
                store.clone(),
            )
            .await
            .unwrap();
            let body = store
                .traffic
                .lock()
                .unwrap()
                .back()
                .unwrap()
                .response_body
                .clone();
            (status, body)
        } else {
            get(proxy.address, &destination, client_config, "/secure")
                .await
                .unwrap()
        };
        assert_eq!(status, 200);
        assert_eq!(body, "{\"ok\":true}");
        let entry = store.traffic.lock().unwrap().back().unwrap().clone();
        assert_eq!(entry.source, "forwarded");
        assert!(entry.url.starts_with("https://localhost:"));
        assert_eq!(entry.response_body, body);
        origin_task.await.unwrap();
        proxy.stop().await;
        tokio::time::timeout(std::time::Duration::from_secs(2), upstream_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn client_with_unrelated_ca_rejects_inspection() {
        let directory = tempfile::tempdir().unwrap();
        let ca = Arc::new(Authority::prepare(directory.path()).unwrap());
        let other_directory = tempfile::tempdir().unwrap();
        let other_ca = Authority::prepare(other_directory.path()).unwrap();
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(ca);
        *store.tls.lock().unwrap() = TlsSettings {
            all_hosts: false,
            enabled: true,
            targets: vec!["mock.invalid:443".into()],
        };
        let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
        assert!(get(
            proxy.address,
            "mock.invalid:443",
            trust(&other_ca),
            "/secure"
        )
        .await
        .is_err());
        proxy.stop().await;
    }

    #[tokio::test]
    async fn unselected_target_remains_a_byte_tunnel() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let destination = listener.local_addr().unwrap();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            });
            let store = Arc::new(Store::default());
            *store.tls.lock().unwrap() = TlsSettings {
                all_hosts: false,
                enabled: true,
                targets: vec!["different.invalid:443".into()],
            };
            let proxy = Proxy::start("127.0.0.1:0", store.clone()).await.unwrap();
            let mut client = TcpStream::connect(proxy.address).await.unwrap();
            client
                .write_all(
                    format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            assert!(read_headers(&mut client).await.starts_with("HTTP/1.1 200"));
            client.write_all(b"ping").await.unwrap();
            let mut result = [0; 4];
            client.read_exact(&mut result).await.unwrap();
            assert_eq!(&result, b"ping");
            assert_eq!(
                store.traffic.lock().unwrap().back().unwrap().source,
                "tunnel"
            );
            origin.await.unwrap();
            proxy.stop().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn inspected_https_reports_upstream_authentication_failure() {
        let directory = tempfile::tempdir().unwrap();
        let ca = Arc::new(Authority::prepare(directory.path()).unwrap());
        let client_config = trust(&ca);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            assert!(read_headers(&mut stream)
                .await
                .starts_with("CONNECT mock.invalid:443 HTTP/1.1"));
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(ca);
        *store.tls.lock().unwrap() = TlsSettings {
            all_hosts: false,
            enabled: true,
            targets: vec!["mock.invalid:443".into()],
        };
        *store.upstream.lock().unwrap() = crate::upstream::Upstream {
            enabled: true,
            host: "127.0.0.1".into(),
            port: address.port(),
            ..Default::default()
        };
        let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
        let (status, body) = get(proxy.address, "mock.invalid:443", client_config, "/secure")
            .await
            .unwrap();
        assert_eq!(status, 502);
        assert!(body.contains("407"));
        task.await.unwrap();
        proxy.stop().await;
    }

    #[tokio::test]
    async fn upstream_certificate_validation_failure_returns_gateway_error() {
        let origin_directory = tempfile::tempdir().unwrap();
        let origin_ca = Authority::prepare(origin_directory.path()).unwrap();
        let config = origin_ca.server_config("localhost").unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let destination = format!("localhost:{}", address.port());
        let origin_task = tokio::spawn(async move {
            let (socket, _) = origin.accept().await.unwrap();
            assert!(tokio_rustls::TlsAcceptor::from(config)
                .accept(socket)
                .await
                .is_err());
        });
        let directory = tempfile::tempdir().unwrap();
        let ca = Arc::new(Authority::prepare(directory.path()).unwrap());
        let client = trust(&ca);
        let store = Arc::new(Store::default());
        *store.authority.lock().unwrap() = Some(ca);
        *store.tls.lock().unwrap() = TlsSettings {
            all_hosts: false,
            enabled: true,
            targets: vec![destination.clone()],
        };
        let proxy = Proxy::start("127.0.0.1:0", store).await.unwrap();
        let (status, body) = get(proxy.address, &destination, client, "/secure")
            .await
            .unwrap();
        assert_eq!(status, 502);
        assert!(body.contains("TLS validation"));
        origin_task.await.unwrap();
        proxy.stop().await;
    }
}
