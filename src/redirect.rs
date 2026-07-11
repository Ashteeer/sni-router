//! `mode: redirect_https` — answer plaintext HTTP (typically on `:80`) with a
//! `301` to the `https://` equivalent. No backend, no TLS; a tiny stateless
//! responder that reuses the bytes already buffered while probing for a SNI.

use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::TcpStream;
use std::io;

const HEAD_MAX: usize = 16 * 1024;

/// Read the request head (continuing from `prefix`, the bytes already read off
/// the socket), then reply with a redirect to the `https://` URL for the same
/// Host and path. Returns the number of response bytes written.
pub async fn handle(prefix: &[u8], client: &mut TcpStream) -> io::Result<u64> {
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

    let resp = match redirect_target(&buf) {
        Some(location) => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        ),
        None => "HTTP/1.1 400 Bad Request\r\nContent-Length: 12\r\n\
                 Connection: close\r\n\r\nbad request\n"
            .to_string(),
    };
    let n = resp.len() as u64;
    let (r, _) = client.write_all(resp.into_bytes()).await;
    r?;
    let _ = client.shutdown().await;
    Ok(n)
}

/// Build the `https://host/path` target from a request head, or `None` if the
/// request line or Host header is missing/unusable.
fn redirect_target(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    // "GET /path?q HTTP/1.1"
    let path = request_line.split_whitespace().nth(1)?;
    if !path.starts_with('/') {
        return None; // not an origin-form request target
    }
    let host = lines.find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim().eq_ignore_ascii_case("host").then(|| value.trim())
    })?;
    if host.is_empty() || host.contains('/') {
        return None;
    }
    Some(format!("https://{host}{path}"))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_https_target() {
        let head = b"GET /a/b?c=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(redirect_target(head).unwrap(), "https://example.com/a/b?c=1");
    }

    #[test]
    fn host_is_case_insensitive() {
        let head = b"GET / HTTP/1.1\r\nhOsT:  ex.org \r\n\r\n";
        assert_eq!(redirect_target(head).unwrap(), "https://ex.org/");
    }

    #[test]
    fn missing_host_is_none() {
        let head = b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
        assert!(redirect_target(head).is_none());
    }

    #[test]
    fn non_origin_target_is_none() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(redirect_target(head).is_none());
    }
}
