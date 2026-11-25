use crate::proxy::{validate_rules, MockRule};
use crate::tls::TlsSettings;
use crate::upstream::{Upstream, UpstreamInput};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SavedUpstream {
    enabled: bool,
    host: String,
    port: u16,
    username: String,
    basic_auth: bool,
}

impl SavedUpstream {
    fn from_runtime(config: &Upstream) -> Self {
        Self {
            enabled: config.enabled,
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            basic_auth: config.basic_auth,
        }
    }

    pub fn restore(self) -> Result<Upstream, String> {
        let mut restored = Upstream::default().updated(UpstreamInput {
            enabled: self.enabled,
            host: self.host,
            port: self.port,
            username: self.username,
            basic_auth: self.basic_auth,
            password: Some(String::new()),
        })?;
        restored.password_available = false;
        Ok(restored)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedWorkspace {
    #[serde(default)]
    pub socket_rules: Vec<crate::socket::SocketRule>,
    #[serde(default = "version")]
    version: u32,
    #[serde(default)]
    pub rules: Vec<MockRule>,
    #[serde(default)]
    pub upstream: SavedUpstream,
    #[serde(default)]
    pub tls: TlsSettings,
}

fn version() -> u32 {
    1
}

impl Default for SavedWorkspace {
    fn default() -> Self {
        Self {
            socket_rules: Vec::new(),
            version: version(),
            rules: Vec::new(),
            upstream: SavedUpstream::default(),
            tls: TlsSettings::default(),
        }
    }
}

pub struct WorkspaceFile {
    path: PathBuf,
    _lock: File,
    load_error: Option<String>,
}

impl WorkspaceFile {
    pub fn open(directory: &Path) -> Result<(Self, SavedWorkspace), String> {
        std::fs::create_dir_all(directory)
            .map_err(|e| format!("Could not create workspace directory: {e}"))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("workspace.lock"))
            .map_err(|e| e.to_string())?;
        lock.try_lock_exclusive().map_err(|_| {
            "This workspace is already open in another WireForge instance.".to_string()
        })?;
        let path = directory.join("workspace.json");
        let mut file = Self {
            path,
            _lock: lock,
            load_error: None,
        };
        match file.read() {
            Ok(saved) => Ok((file, saved)),
            Err(error) => {
                file.load_error = Some(format!("Could not load {}. {error} Repair or move this file before restarting WireForge. Saving is disabled to preserve it.", file.path.display()));
                Ok((file, SavedWorkspace::default()))
            }
        }
    }

    fn read(&self) -> Result<SavedWorkspace, String> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SavedWorkspace::default())
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut bytes = Vec::new();
        file.take(210 * 1024 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let saved: SavedWorkspace = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if saved.version != version() {
            return Err("Unsupported workspace version.".into());
        }
        validate_rules(&saved.rules)?;
        crate::socket::validate(&saved.socket_rules)?;
        saved.tls.validate()?;
        // Validate the connection before accepting any of the saved workspace.
        Upstream::default().updated(UpstreamInput {
            enabled: saved.upstream.enabled,
            host: saved.upstream.host.clone(),
            port: saved.upstream.port,
            username: saved.upstream.username.clone(),
            basic_auth: saved.upstream.basic_auth,
            password: Some(String::new()),
        })?;
        Ok(saved)
    }

    pub fn warning(&self) -> Option<String> {
        self.load_error.clone()
    }
    pub fn path(&self) -> String {
        self.path.display().to_string()
    }

    pub fn save(
        &self,
        rules: &[MockRule],
        upstream: &Upstream,
        tls: &TlsSettings,
        socket_rules: &[crate::socket::SocketRule],
    ) -> Result<(), String> {
        if let Some(error) = &self.load_error {
            return Err(error.clone());
        }
        let saved = SavedWorkspace {
            socket_rules: socket_rules.to_vec(),
            version: version(),
            rules: rules.to_vec(),
            upstream: SavedUpstream::from_runtime(upstream),
            tls: tls.clone(),
        };
        let directory = self.path.parent().ok_or("Invalid workspace path")?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
        serde_json::to_writer_pretty(temporary.as_file_mut(), &saved).map_err(|e| e.to_string())?;
        temporary
            .as_file_mut()
            .write_all(b"\n")
            .map_err(|e| e.to_string())?;
        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|e| e.to_string())?;
        temporary
            .persist(&self.path)
            .map_err(|e| format!("Could not save workspace: {}", e.error))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> MockRule {
        MockRule {
            content_type: "application/json".into(),
            id: "one".into(),
            method: "GET".into(),
            path: "/saved".into(),
            body: "{\"saved\":true}".into(),
            status: 200,
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn saves_replaces_and_restores_rules_without_password() {
        let directory = tempfile::tempdir().unwrap();
        let (file, initial) = WorkspaceFile::open(directory.path()).unwrap();
        assert!(initial.rules.is_empty());
        let config = Upstream::default()
            .updated(UpstreamInput {
                enabled: true,
                host: "proxy.company.local".into(),
                port: 3128,
                username: "developer".into(),
                password: Some("must-not-reach-disk".into()),
                basic_auth: true,
            })
            .unwrap();
        let socket_rules = vec![crate::socket::SocketRule {
            id: "socket".into(),
            url: "wss://api.company.local/socket".into(),
            direction: "out".into(),
            match_text: "request".into(),
            response_text: "reply".into(),
            enabled: true,
        }];
        file.save(&[rule()], &config, &TlsSettings::default(), &socket_rules)
            .unwrap();
        file.save(
            &[
                rule(),
                MockRule {
                    path: "/second".into(),
                    id: "two".into(),
                    ..rule()
                },
            ],
            &config,
            &TlsSettings {
                all_hosts: false,
                enabled: true,
                targets: vec!["api.company.local:443".into()],
            },
            &socket_rules,
        )
        .unwrap();
        let content = std::fs::read_to_string(directory.path().join("workspace.json")).unwrap();
        assert!(!content.contains("must-not-reach-disk"));
        assert!(!content.contains("password"));
        drop(file);
        let (_, saved) = WorkspaceFile::open(directory.path()).unwrap();
        assert_eq!(saved.rules.len(), 2);
        assert_eq!(saved.socket_rules.len(), 1);
        assert_eq!(saved.socket_rules[0].response_text, "reply");
        assert_eq!(saved.rules[1].path, "/second");
        assert!(saved.tls.enabled);
        assert_eq!(saved.tls.targets, vec!["api.company.local:443"]);
        let restored = saved.upstream.restore().unwrap();
        assert!(restored.enabled && restored.basic_auth);
        assert!(!restored.password_available);
        assert!(restored.password.is_empty());
    }

    #[test]
    fn malformed_or_future_workspace_is_preserved() {
        let directory = tempfile::tempdir().unwrap();
        for content in ["invalid JSON", "{\"version\":99}"] {
            std::fs::write(directory.path().join("workspace.json"), content).unwrap();
            let (file, saved) = WorkspaceFile::open(directory.path()).unwrap();
            assert!(file.warning().is_some());
            assert!(saved.rules.is_empty());
            assert!(file
                .save(
                    &[rule()],
                    &Upstream::default(),
                    &TlsSettings::default(),
                    &[]
                )
                .is_err());
            assert_eq!(
                std::fs::read_to_string(directory.path().join("workspace.json")).unwrap(),
                content
            );
        }
    }

    #[test]
    fn prevents_concurrent_instances_and_releases_lock_on_close() {
        let directory = tempfile::tempdir().unwrap();
        let (file, _) = WorkspaceFile::open(directory.path()).unwrap();
        assert!(WorkspaceFile::open(directory.path()).is_err());
        drop(file);
        assert!(WorkspaceFile::open(directory.path()).is_ok());
    }

    #[test]
    fn loads_workspace_with_missing_optional_fields() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("workspace.json"), "{}").unwrap();
        let (file, saved) = WorkspaceFile::open(directory.path()).unwrap();
        assert!(file.warning().is_none());
        assert!(saved.rules.is_empty());
        assert!(!saved.upstream.restore().unwrap().enabled);
    }
}
