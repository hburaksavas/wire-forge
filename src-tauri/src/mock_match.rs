// Mock rule matching: exact, wildcard and regex paths plus request header conditions.
use crate::proxy::{MatchType, MockRule};
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const REGEX_SIZE_LIMIT: usize = 1 << 20;
const REGEX_CACHE: usize = 512;

/// Compiles a rule pattern as a full match against the path and query.
pub fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(&format!("^(?:{pattern})$"))
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
}

fn regex_matches(pattern: &str, text: &str) -> bool {
    static CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let cached = cache.lock().unwrap().get(pattern).cloned();
    let regex = match cached {
        Some(regex) => regex,
        None => {
            let Ok(regex) = compile(pattern) else {
                return false;
            };
            let mut map = cache.lock().unwrap();
            if map.len() >= REGEX_CACHE {
                map.clear();
            }
            map.insert(pattern.to_string(), regex.clone());
            regex
        }
    };
    regex.is_match(text)
}

/// `*` matches any sequence, including `/` and `?`. Other characters match literally.
pub fn glob(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            mark = t;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(position) = star {
            p = position + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

pub fn path_matches(rule: &MockRule, path: &str) -> bool {
    match rule.match_type {
        MatchType::Exact => rule.path == path,
        MatchType::Wildcard => glob(&rule.path, path),
        MatchType::Regex => regex_matches(&rule.path, path),
    }
}

fn headers_match(rule: &MockRule, headers: &[(String, String)]) -> bool {
    rule.request_headers.iter().all(|condition| {
        headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(&condition.name)
                && (condition.value.is_empty() || glob(&condition.value, value))
        })
    })
}

/// Exact rules win over pattern rules; otherwise the first matching rule in list order wins.
/// `headers` of `None` skips header conditions (used for CORS preflight requests).
pub fn find<'a>(
    rules: &'a [MockRule],
    method: &str,
    path: &str,
    headers: Option<&[(String, String)]>,
) -> Option<&'a MockRule> {
    let candidate = |rule: &&MockRule| {
        rule.enabled
            && (rule.method == method || rule.method == "ANY")
            && path_matches(rule, path)
            && headers.is_none_or(|headers| headers_match(rule, headers))
    };
    rules
        .iter()
        .filter(|rule| rule.match_type == MatchType::Exact)
        .find(candidate)
        .or_else(|| {
            rules
                .iter()
                .filter(|rule| rule.match_type != MatchType::Exact)
                .find(candidate)
        })
}

pub fn header_list(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{validate_rules, HeaderPair};

    fn rule(method: &str, match_type: MatchType, path: &str) -> MockRule {
        MockRule {
            id: path.into(),
            method: method.into(),
            path: path.into(),
            body: "{}".into(),
            content_type: "application/json".into(),
            status: 200,
            enabled: true,
            match_type,
            ..Default::default()
        }
    }

    #[test]
    fn glob_matches_segments_and_queries() {
        assert!(glob("/api/*", "/api/users/7?x=1"));
        assert!(glob("/api/*/orders", "/api/7/orders"));
        assert!(!glob("/api/*/orders", "/api/7/orders/1"));
        assert!(glob("*", ""));
        assert!(glob("/a*b*c", "/aXXbYYc"));
        assert!(!glob("/a*b*c", "/aXXbYY"));
        assert!(glob("/exact", "/exact"));
    }

    #[test]
    fn regex_is_anchored_and_exact_rules_win() {
        let rules = vec![
            rule("GET", MatchType::Regex, r"/users/\d+"),
            rule("GET", MatchType::Exact, "/users/1"),
        ];
        assert_eq!(
            find(&rules, "GET", "/users/1", Some(&[])).unwrap().id,
            "/users/1"
        );
        assert_eq!(
            find(&rules, "GET", "/users/42", Some(&[])).unwrap().id,
            r"/users/\d+"
        );
        assert!(find(&rules, "GET", "/users/42/x", Some(&[])).is_none());
        assert!(find(&rules, "GET", "/v2/users/42", Some(&[])).is_none());
    }

    #[test]
    fn any_method_and_header_conditions() {
        let mut tenant = rule("ANY", MatchType::Wildcard, "/api/*");
        tenant.request_headers = vec![
            HeaderPair {
                name: "X-Tenant".into(),
                value: "acme-*".into(),
            },
            HeaderPair {
                name: "Authorization".into(),
                value: String::new(),
            },
        ];
        let rules = vec![tenant];
        let good = vec![
            ("x-tenant".to_string(), "acme-eu".to_string()),
            ("authorization".to_string(), "Bearer t".to_string()),
        ];
        assert!(find(&rules, "DELETE", "/api/x", Some(&good)).is_some());
        assert!(find(&rules, "GET", "/api/x", Some(&good[..1])).is_none());
        let wrong = vec![
            ("x-tenant".to_string(), "other".to_string()),
            ("authorization".to_string(), "Bearer t".to_string()),
        ];
        assert!(find(&rules, "GET", "/api/x", Some(&wrong)).is_none());
        assert!(find(&rules, "GET", "/api/x", None).is_some());
    }

    #[test]
    fn validation_covers_patterns_and_headers() {
        assert!(validate_rules(&[rule("ANY", MatchType::Regex, r"/users/\d+")]).is_ok());
        assert!(validate_rules(&[rule("GET", MatchType::Regex, "/users/(")]).is_err());
        assert!(validate_rules(&[rule("GET", MatchType::Regex, "")]).is_err());
        assert!(validate_rules(&[rule("GET", MatchType::Wildcard, "api/*")]).is_err());
        assert!(validate_rules(&[rule("TRACE", MatchType::Exact, "/x")]).is_err());
        let mut headers = rule("GET", MatchType::Exact, "/x");
        headers.response_headers = vec![HeaderPair {
            name: "X-Mock".into(),
            value: "1".into(),
        }];
        assert!(validate_rules(&[headers.clone()]).is_ok());
        for name in [
            "Content-Length",
            "content-type",
            "Transfer-Encoding",
            "bad name",
        ] {
            headers.response_headers = vec![HeaderPair {
                name: name.into(),
                value: "1".into(),
            }];
            assert!(validate_rules(&[headers.clone()]).is_err(), "{name}");
        }
        let mut condition = rule("GET", MatchType::Exact, "/x");
        condition.request_headers = vec![HeaderPair {
            name: "bad name".into(),
            value: String::new(),
        }];
        assert!(validate_rules(&[condition]).is_err());
        let first = rule("GET", MatchType::Wildcard, "/x*");
        assert!(validate_rules(&[first.clone(), rule("GET", MatchType::Exact, "/x*")]).is_ok());
        assert!(validate_rules(&[first.clone(), first]).is_err());
    }
}
