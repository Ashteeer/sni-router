//! Self-update: fetch the latest release from the project's GitHub and replace
//! the running binary in place. Shared by the CLI (`-u`/`--update`) and the API
//! (`POST /update`).
//!
//! Downloads happen via `curl`/`wget` + `tar` (the same tools the installer
//! needs), so no HTTP/TLS/gzip/tar crates are pulled into the binary. Only the
//! project's official release assets are ever fetched — the repo is fixed here,
//! never taken from a request — so an update can only ever install an official
//! build, not arbitrary code.
//!
//! Replacing the binary needs write access to the directory it lives in (the
//! new file is staged there and atomically renamed over the old one). The
//! installer puts the binary in a directory owned by the service user precisely
//! so `POST /update` works unprivileged; the CLI `-u` works when run as a user
//! who can write that directory (e.g. root).

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The official repository. Fixed on purpose — updates never follow a URL from
/// a request, only this repo's releases.
const REPO: &str = "Ashteeer/sni-router";

/// The current compiled-in version (`Cargo.toml`).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// What an update check decided.
pub enum Plan {
    /// Running version already matches the latest release.
    AlreadyLatest { version: String },
    /// A newer (or, with `--force`, different) release is available.
    Available { from: String, to: String, tag: String, arch: &'static str },
}

fn arch() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        other => Err(format!("unsupported architecture: {other}")),
    }
}

/// Look up the latest release and compare it to the running version. This is
/// the fast, network-only part (no download) — safe to run under a short
/// request deadline.
pub fn check(force: bool) -> Result<Plan, String> {
    let arch = arch()?;
    let tag = latest_tag()?; // e.g. "v1.4.0"
    let latest = tag.strip_prefix('v').unwrap_or(&tag).to_string();
    let current = current_version().to_string();
    // Only move when the release is strictly newer; `--force` reinstalls the
    // latest regardless (e.g. to downgrade a dev build to a published one).
    if !force && semver(&latest) <= semver(&current) {
        Ok(Plan::AlreadyLatest { version: current })
    } else {
        Ok(Plan::Available { from: current, to: latest, tag, arch })
    }
}

/// Best-effort `x.y.z` → comparable tuple. Non-numeric or missing parts read as
/// 0, so a malformed tag never panics — it just sorts low.
fn semver(v: &str) -> (u64, u64, u64) {
    let mut it = v.split('.').map(|p| {
        p.trim()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or("")
            .parse::<u64>()
            .unwrap_or(0)
    });
    (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// Download the release `tag` for `arch`, then atomically replace the running
/// binary. On any failure nothing is changed. Does not restart anything — the
/// caller decides (CLI prints a hint / restarts the service; the API re-execs).
pub fn apply(tag: &str, arch: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate current binary: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "binary path has no parent directory".to_string())?
        .to_path_buf();

    let work = scratch_dir()?;
    let staged = dir.join(format!(".sni-router.update.{}", std::process::id()));
    let asset = format!("sni-router-{tag}-{arch}-linux.tar.gz");
    let url = format!("https://github.com/{REPO}/releases/download/{tag}/{asset}");
    let tarball = work.join(&asset);

    let result = (|| {
        http_download(&url, &tarball)?;
        // Verify the download against the release's SHA256SUMS before trusting
        // it. TLS to github.com is not enough on its own (a corp MITM CA, a
        // swapped asset, or a compromised transport would all pass): the binary
        // about to overwrite the running one must match the manifest the release
        // published, or we refuse to install it.
        verify_sha256(&tarball, tag, &asset)?;
        run(Command::new("tar").arg("-xzf").arg(&tarball).arg("-C").arg(&work))
            .map_err(|e| format!("tar extract failed: {e}"))?;
        let new_bin = work.join("sni-router");
        if !new_bin.exists() {
            return Err("release tarball did not contain a sni-router binary".to_string());
        }
        // Stage in the target directory (same filesystem) so the rename is atomic.
        std::fs::copy(&new_bin, &staged)
            .map_err(|e| format!("cannot stage new binary in {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("cannot chmod staged binary: {e}"))?;
        }
        std::fs::rename(&staged, &exe)
            .map_err(|e| format!("cannot replace {}: {e}", exe.display()))?;
        Ok(())
    })();

    let _ = std::fs::remove_dir_all(&work);
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Verify `tarball` against the release's `SHA256SUMS` manifest. The manifest is
/// a required release asset (one `<sha256>  <filename>` line per asset); a
/// release without it, or without a line for `asset`, or a hash mismatch, all
/// abort the update. Fetched from the same fixed repo as everything else.
fn verify_sha256(tarball: &Path, tag: &str, asset: &str) -> Result<(), String> {
    let url = format!("https://github.com/{REPO}/releases/download/{tag}/SHA256SUMS");
    let manifest = http_get(&url).map_err(|e| {
        format!("cannot fetch SHA256SUMS (release integrity manifest) for {tag}: {e}")
    })?;
    let expected = expected_hash(&manifest, asset)
        .ok_or_else(|| format!("SHA256SUMS has no entry for {asset}"))?;

    let data = std::fs::read(tarball).map_err(|e| format!("cannot read downloaded asset: {e}"))?;
    let got = hex(Sha256::digest(&data));
    if got != expected {
        return Err(format!(
            "checksum mismatch for {asset}: manifest says {expected}, download is {got} — \
             refusing to install a binary that doesn't match the published release"
        ));
    }
    Ok(())
}

/// The expected hash for `asset` from a `SHA256SUMS` manifest ("<hex>␠␠<name>"
/// per line; the name may carry a leading `*` for binary mode). Lowercased.
fn expected_hash(manifest: &str, asset: &str) -> Option<String> {
    manifest.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let hash = it.next()?;
        let name = it.next()?;
        (name.trim_start_matches('*') == asset).then(|| hash.to_ascii_lowercase())
    })
}

/// Lowercase hex of a byte slice.
fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.as_ref().len() * 2);
    for b in bytes.as_ref() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// CLI entry point for `sni-router -u` / `--update`.
pub fn run_cli(force: bool) -> ExitCode {
    match check(force) {
        Ok(Plan::AlreadyLatest { version }) => {
            println!("sni-router is already at the latest version ({version})");
            ExitCode::SUCCESS
        }
        Ok(Plan::Available { from, to, tag, arch }) => {
            println!("updating sni-router {from} -> {to} ...");
            match apply(&tag, arch) {
                Ok(()) => {
                    println!("updated to {to}");
                    // Best effort: if systemd is managing an active service, swing
                    // it onto the new binary. Harmless (and silent) otherwise.
                    if Command::new("systemctl")
                        .args(["try-restart", "sni-router"])
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false)
                    {
                        println!("restarted the running service onto the new binary");
                    } else {
                        println!("restart the service to apply: systemctl restart sni-router");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("update failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(e) => {
            eprintln!("update check failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Fetch the latest release tag (`"v1.4.0"`) from the GitHub API.
fn latest_tag() -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body = http_get(&url)?;
    // Dependency-free extraction of "tag_name": "…" (same approach as install.sh).
    let key = "\"tag_name\"";
    let i = body.find(key).ok_or("no tag_name in GitHub response (no releases yet?)")?;
    let rest = &body[i + key.len()..];
    let start = rest.find('"').ok_or("malformed tag_name in GitHub response")? + 1;
    let end = rest[start..].find('"').ok_or("malformed tag_name in GitHub response")? + start;
    Ok(rest[start..end].to_string())
}

/// GET a URL to a string via curl/wget. A User-Agent is required by the GitHub
/// API (it 403s requests without one).
fn http_get(url: &str) -> Result<String, String> {
    let out = if have("curl") {
        Command::new("curl")
            .args(["-fsSL", "-H", "User-Agent: sni-router", url])
            .output()
    } else if have("wget") {
        Command::new("wget")
            .args(["-qO-", "--header=User-Agent: sni-router", url])
            .output()
    } else {
        return Err("neither curl nor wget is available".into());
    }
    .map_err(|e| format!("failed to run downloader: {e}"))?;
    if !out.status.success() {
        return Err(format!("download failed ({}): {url}", out.status));
    }
    String::from_utf8(out.stdout).map_err(|_| "non-UTF8 response from GitHub".into())
}

/// Download a URL to a file via curl/wget.
fn http_download(url: &str, dest: &std::path::Path) -> Result<(), String> {
    let status = if have("curl") {
        Command::new("curl")
            .args(["-fsSL", "-H", "User-Agent: sni-router", "-o"])
            .arg(dest)
            .arg(url)
            .status()
    } else if have("wget") {
        Command::new("wget")
            .args(["-q", "--header=User-Agent: sni-router", "-O"])
            .arg(dest)
            .arg(url)
            .status()
    } else {
        return Err("neither curl nor wget is available".into());
    }
    .map_err(|e| format!("failed to run downloader: {e}"))?;
    if !status.success() {
        return Err(format!("download failed ({status}): {url}"));
    }
    Ok(())
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let st = cmd.status().map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("exited with {st}"))
    }
}

fn scratch_dir() -> Result<PathBuf, String> {
    let d = std::env::temp_dir().join(format!("sni-router-update.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).map_err(|e| format!("cannot create temp dir: {e}"))?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::{expected_hash, hex, semver};

    #[test]
    fn sha256sums_parsing_picks_the_right_asset() {
        let manifest = "\
aaaa1111  sni-router-v1.7.0-aarch64-linux.tar.gz
BBBB2222 *sni-router-v1.7.0-x86_64-linux.tar.gz
cccc3333  SHA256SUMS
";
        // Exact asset match, binary-mode '*' stripped, hash lowercased.
        assert_eq!(
            expected_hash(manifest, "sni-router-v1.7.0-x86_64-linux.tar.gz").as_deref(),
            Some("bbbb2222")
        );
        assert_eq!(
            expected_hash(manifest, "sni-router-v1.7.0-aarch64-linux.tar.gz").as_deref(),
            Some("aaaa1111")
        );
        // No entry -> None (an update would abort rather than install unverified).
        assert_eq!(expected_hash(manifest, "sni-router-v9.9.9-x86_64-linux.tar.gz"), None);
    }

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex([0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn version_ordering() {
        assert!(semver("1.4.0") > semver("1.3.0"));
        assert!(semver("1.10.0") > semver("1.9.0")); // numeric, not lexicographic
        assert!(semver("2.0.0") > semver("1.9.9"));
        assert_eq!(semver("1.4.0"), semver("1.4.0"));
        assert!(semver("v1.4.0".trim_start_matches('v')) == semver("1.4.0"));
        // malformed never panics, sorts low
        assert_eq!(semver("garbage"), (0, 0, 0));
    }
}
