//! `mode: redirect_https` — a small plaintext-HTTP responder (typically on
//! `:80`). With no `http_rules` it 301-redirects every request to the `https://`
//! equivalent (the common one-liner). With `http_rules` it applies them, so the
//! same `respond` (e.g. 404) and `redirect` (e.g. 301) rules used in terminate
//! backends also work here — synthetic responses are not tied to a port/mode.
//!
//! Answers one request per connection and closes (bodies are ignored), which is
//! all a redirect/404 endpoint needs.

use crate::config::{HttpAction, HttpRule};
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use std::io;

const HEAD_MAX: usize = 16 * 1024;

/// Read the request head (continuing from `prefix`), pick a response per
/// `rules`, write it, and close. Returns the number of response bytes written.
pub async fn handle(prefix: &[u8], client: &mut TcpStream, rules: &[HttpRule]) -> io::Result<u64> {
    let mut buf = prefix.to_vec();
    while find(&buf, b"\r\n\r\n").is_none() && buf.len() < HEAD_MAX {
        let tmp = vec![0u8; 2048];
        let (r, tmp) = client.read(tmp).await;
        let n = r?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }

    let resp = build_response(rules, &buf);
    let n = resp.len() as u64;
    let (r, _) = client.write_all(resp).await;
    r?;
    let _ = client.shutdown().await;
    Ok(n)
}

/// Decide the response bytes for a plaintext request `head` under `rules`.
fn build_response(rules: &[HttpRule], head: &[u8]) -> Vec<u8> {
    let host = crate::terminate::request_host(head);
    let path = crate::terminate::request_path(head);

    // No rules: the simple preset — 301 to the https:// equivalent.
    if rules.is_empty() {
        if host.is_empty() || !path.starts_with('/') {
            return simple(400, "Bad Request", "bad request\n");
        }
        let location = format!("https://{host}{path}");
        return format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
    }

    match crate::terminate::match_rule(rules, path) {
        Some(rule) if rule.action != HttpAction::Forward => {
            // A dynamic `https` redirect needs the Host; without it, 400.
            let dynamic_https = rule.action == HttpAction::Redirect
                && rule.to.as_deref().unwrap_or("https") == "https";
            if dynamic_https && (host.is_empty() || !path.starts_with('/')) {
                return simple(400, "Bad Request", "bad request\n");
            }
            crate::terminate::synthetic_response(rule, host, path, false)
        }
        // No matching rule (or a `forward` rule with no upstream here): 404.
        _ => simple(404, "Not Found", "not found\n"),
    }
}

fn simple(status: u16, reason: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(path: &str, action: HttpAction) -> HttpRule {
        HttpRule {
            path: path.into(),
            action,
            status: None,
            body: String::new(),
            content_type: None,
            to: None,
        }
    }

    #[test]
    fn default_redirects_to_https() {
        let out = String::from_utf8(build_response(&[], b"GET /a?b=1 HTTP/1.1\r\nHost: ex.com\r\n\r\n"))
            .unwrap();
        assert!(out.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{out}");
        assert!(out.contains("Location: https://ex.com/a?b=1\r\n"), "{out}");
    }

    #[test]
    fn default_missing_host_is_400() {
        let out = String::from_utf8(build_response(&[], b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n")).unwrap();
        assert!(out.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{out}");
    }

    #[test]
    fn rules_can_respond_404_on_plaintext() {
        let mut r = rule("/blocked", HttpAction::Respond);
        r.status = Some(404);
        r.body = "nope\n".into();
        let head = b"GET /blocked HTTP/1.1\r\nHost: ex.com\r\n\r\n";
        let out = String::from_utf8(build_response(std::slice::from_ref(&r), head)).unwrap();
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"), "{out}");
        assert!(out.ends_with("\r\n\r\nnope\n"), "{out}");
    }

    #[test]
    fn unmatched_rule_is_404() {
        let r = rule("/only", HttpAction::Forward);
        let head = b"GET /other HTTP/1.1\r\nHost: ex.com\r\n\r\n";
        let out = String::from_utf8(build_response(std::slice::from_ref(&r), head)).unwrap();
        assert!(out.starts_with("HTTP/1.1 404 Not Found\r\n"), "{out}");
    }
}
