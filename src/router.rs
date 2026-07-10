//! SNI -> backend matching. First matching route wins.
//!
//! Wildcard semantics must stay in lockstep with `config::validate::covers`,
//! which uses the same rules to detect unreachable (shadowed) routes:
//! - `*`            matches anything, including a connection with no SNI;
//! - `*.example.com` matches any subdomain of any depth, but NOT the apex;
//! - anything else is an exact, case-insensitive match.

use crate::config::Route;

/// Return the backend name of the first route matching `sni`.
///
/// Pass `""` for a connection that had no usable SNI — only a `*` route can
/// match it.
pub fn pick<'a>(routes: &'a [Route], sni: &str) -> Option<&'a str> {
    routes
        .iter()
        .find(|r| matches(&r.sni, sni))
        .map(|r| r.backend.as_str())
}

/// Does route pattern `pattern` match the concrete server name `sni`?
pub fn matches(pattern: &str, sni: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        // "*.example.com" -> suffix ".example.com": require at least one label
        // in front of the dot so the apex "example.com" does not match.
        return sni.len() > suffix.len() && sni.to_ascii_lowercase().ends_with(suffix);
    }
    pattern.eq_ignore_ascii_case(sni)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_is_case_insensitive() {
        assert!(matches("Example.com", "example.com"));
        assert!(!matches("example.com", "evil.com"));
    }

    #[test]
    fn wildcard_matches_subdomains_not_apex() {
        assert!(matches("*.example.com", "a.example.com"));
        assert!(matches("*.example.com", "deep.sub.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn catch_all_matches_everything_including_empty() {
        assert!(matches("*", "anything.com"));
        assert!(matches("*", ""));
    }

    #[test]
    fn empty_sni_only_hits_catch_all() {
        assert!(!matches("example.com", ""));
        assert!(!matches("*.example.com", ""));
    }

    #[test]
    fn pick_returns_first_match() {
        let routes = vec![
            Route { sni: "api.example.com".into(), backend: "api".into() },
            Route { sni: "*.example.com".into(), backend: "web".into() },
            Route { sni: "*".into(), backend: "default".into() },
        ];
        assert_eq!(pick(&routes, "api.example.com"), Some("api"));
        assert_eq!(pick(&routes, "other.example.com"), Some("web"));
        assert_eq!(pick(&routes, "elsewhere.org"), Some("default"));
        assert_eq!(pick(&routes, ""), Some("default"));
    }

    #[test]
    fn pick_none_without_catch_all() {
        let routes = vec![Route { sni: "example.com".into(), backend: "web".into() }];
        assert_eq!(pick(&routes, "other.com"), None);
    }
}
