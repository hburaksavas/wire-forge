use serde::{Deserialize, Serialize};

pub const PAYLOAD_LIMIT: usize = 64 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SocketRule {
    pub id: String,
    pub url: String,
    pub direction: String,
    pub match_text: String,
    pub response_text: String,
    pub enabled: bool,
}

pub fn validate(rules: &[SocketRule]) -> Result<(), String> {
    if rules.len() > 100 {
        return Err("At most 100 WebSocket rules are supported".into());
    }
    let mut keys = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for rule in rules {
        let url = tauri::Url::parse(&rule.url).map_err(|_| "Enter an absolute WebSocket URL")?;
        if !matches!(url.scheme(), "ws" | "wss")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.as_str() != rule.url
            || rule.url.len() > 8192
        {
            return Err(
                "Use a canonical ws:// or wss:// URL without credentials or fragments".into(),
            );
        }
        if !["in", "out"].contains(&rule.direction.as_str())
            || rule.id.is_empty()
            || rule.id.len() > 128
            || rule.match_text.len() > PAYLOAD_LIMIT
            || rule.response_text.len() > PAYLOAD_LIMIT
        {
            return Err("Invalid WebSocket rule or payload over 64 KiB".into());
        }
        if !keys.insert((&rule.url, &rule.direction, &rule.match_text)) || !ids.insert(&rule.id) {
            return Err("Duplicate WebSocket match".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_socket_targets_payload_limits_and_unique_matches() {
        let rule = SocketRule {
            id: "rule".into(),
            url: "wss://api.test/socket?q=1".into(),
            direction: "out".into(),
            match_text: "request".into(),
            response_text: "reply".into(),
            enabled: true,
        };
        assert!(validate(&[rule.clone()]).is_ok());
        for url in [
            "http://api.test/socket",
            "wss://user:secret@api.test/socket",
            "wss://api.test/socket#fragment",
            "wss://api.test",
        ] {
            let mut invalid = rule.clone();
            invalid.url = url.into();
            assert!(validate(&[invalid]).is_err());
        }
        let mut large = rule.clone();
        large.response_text = "é".repeat(PAYLOAD_LIMIT / 2 + 1);
        assert!(validate(&[large]).is_err());
        let mut duplicate = rule.clone();
        duplicate.id = "other".into();
        assert!(validate(&[rule.clone(), duplicate]).is_err());
        let mut duplicate_id = rule.clone();
        duplicate_id.match_text = "different".into();
        assert!(validate(&[rule, duplicate_id]).is_err());
    }
}

#[cfg(windows)]
pub fn script(rules: &[SocketRule]) -> String {
    format!(
        "({})({})",
        include_str!("socket-control.js"),
        serde_json::to_string(rules).unwrap()
    )
}
