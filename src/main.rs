mod config;
mod protocol;
mod router;

use config::validate::{Diagnostic, Level};
use std::io::IsTerminal;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
sni-router - SNI-based L4 router (TCP/UDP/QUIC passthrough)

USAGE:
    sni-router [-c <config>]                      run the router
    sni-router -t [<config>] [--check-backends]   validate config and exit

OPTIONS:
    -t, --test-config [PATH]   validate configuration and exit (like `nginx -t`)
    -c, --config PATH          path to the config file
        --check-backends       with -t: also try a real TCP connect to every backend server
        --no-color             disable colored output
    -V, --version              print version
    -h, --help                 print this help

Config path resolution: explicit path > $SNI_ROUTER_CONFIG > /etc/sni-router/sni-router.yaml
";

struct Cli {
    test: bool,
    path: Option<PathBuf>,
    check_backends: bool,
    no_color: bool,
}

// ponytail: hand-rolled arg parsing, ~40 lines; switch to a CLI crate when flags outgrow it
fn parse_args() -> Result<Cli, String> {
    let mut cli = Cli { test: false, path: None, check_backends: false, no_color: false };
    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-t" | "--test-config" => {
                cli.test = true;
                if let Some(next) = args.peek() {
                    if !next.starts_with('-') {
                        cli.path = Some(PathBuf::from(args.next().unwrap()));
                    }
                }
            }
            "-c" | "--config" => {
                let v = args.next().ok_or_else(|| format!("{a} requires a path argument"))?;
                cli.path = Some(PathBuf::from(v));
            }
            "--check-backends" => cli.check_backends = true,
            "--no-color" => cli.no_color = true,
            "-V" | "--version" => {
                println!("sni-router {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument \"{other}\" (see --help)")),
        }
    }
    Ok(cli)
}

fn main() -> ExitCode {
    let cli = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let color = !cli.no_color
        && std::env::var_os("NO_COLOR").is_none()
        && std::io::stdout().is_terminal();

    let path = match config::resolve_config_path(cli.path.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    if cli.test {
        return test_config(&path, cli.check_backends, color);
    }

    // Run mode: refuse to start on an invalid config, reusing the same validation.
    let cfg = match config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let diags = config::validate::validate(&cfg);
    for d in &diags {
        eprintln!("{}{}: {}", tag(d.level, color), d.path, d.message);
    }
    if diags.iter().any(|d| d.level == Level::Error) {
        eprintln!("refusing to start with an invalid configuration");
        return ExitCode::FAILURE;
    }
    eprintln!("run mode is not implemented yet — this build only supports --test-config / -t");
    ExitCode::from(2)
}

fn test_config(path: &Path, check_backends: bool, color: bool) -> ExitCode {
    let cfg = match config::load(path) {
        Ok(c) => c,
        Err(e) => {
            println!("{}{e}", tag(Level::Error, color));
            println!("configuration file {} test failed", path.display());
            return ExitCode::FAILURE;
        }
    };

    let mut diags = config::validate::validate(&cfg);
    let static_errors = diags.iter().filter(|d| d.level == Level::Error).count();
    if check_backends && static_errors == 0 {
        diags.extend(probe_backends(&cfg));
    }

    for d in &diags {
        println!("{}{}: {}", tag(d.level, color), d.path, d.message);
    }

    let errors = diags.iter().filter(|d| d.level == Level::Error).count();
    let warnings = diags.len() - errors;
    if errors > 0 {
        println!("configuration file test failed with {errors} error(s), {warnings} warning(s)");
        ExitCode::FAILURE
    } else {
        println!("configuration file {} test is successful", path.display());
        ExitCode::SUCCESS
    }
}

/// Colored diagnostic tag, padded so messages align (`[ERROR]` + 3, `[WARNING]` + 1).
fn tag(level: Level, color: bool) -> &'static str {
    match (level, color) {
        (Level::Error, true) => "\x1b[31m[ERROR]\x1b[0m   ",
        (Level::Error, false) => "[ERROR]   ",
        (Level::Warning, true) => "\x1b[33m[WARNING]\x1b[0m ",
        (Level::Warning, false) => "[WARNING] ",
    }
}

/// `--check-backends`: real TCP connect to every backend server (network side effect,
/// therefore opt-in only, like `nginx -t` never probing upstreams).
fn probe_backends(cfg: &config::Config) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for (name, b) in &cfg.backends {
        for (i, s) in b.servers.iter().enumerate() {
            let Ok(addr) = s.parse::<SocketAddr>() else { continue };
            if let Err(e) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                out.push(Diagnostic::error(
                    format!("backends.{name}.servers[{i}]"),
                    format!("\"{s}\" is not reachable: {e}"),
                ));
            }
        }
    }
    out
}
