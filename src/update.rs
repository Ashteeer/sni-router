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

use std::path::PathBuf;
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
    if !force && latest == current {
        Ok(Plan::AlreadyLatest { version: current })
    } else {
        Ok(Plan::Available { from: current, to: latest, tag, arch })
    }
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
