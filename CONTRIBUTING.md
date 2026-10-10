# Contributing

Bug reports, focused fixes and documentation improvements are welcome. For a
large change to the configuration format or forwarding behavior, open an
issue describing the use case before building it.

## Build on Linux

The forwarding code depends on Linux sockets, io_uring and splice. Use a
Linux host or Linux VM for development and validation; native Windows is not
a supported build target. A normal Linux kernel is also needed to test the
actual io_uring path. A successful fallback run does not verify it.

Install stable Rust through rustup, plus a C compiler and build tools for
`ring`. The project uses Rust edition 2021 and does not currently declare a
minimum supported Rust version. Use the committed `Cargo.lock` for
reproducible dependency resolution.

```sh
git clone https://github.com/Ashteeer/sni-router.git
cd sni-router
cargo build --locked
cargo test --locked
cargo build --release --locked
./target/release/sni-router --help
```

For a remote Linux build host, `scripts/deploy.sh` copies `git archive HEAD`
over SSH and builds there. Set `SSH_DEST`, and optionally `SSH_PORT` and
`REMOTE_DIR`, in your shell or local `.env`, then run:

```sh
bash scripts/deploy.sh --test
```

The script sends only the committed tree: uncommitted edits and untracked
files are not included. Despite its name, it builds the binary without
installing it or restarting a running service. Keep `.env` and credentials
out of commits; use your local Git exclude file for machine-specific files.

## Checks

Run the relevant checks on a Linux development host:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets
cargo test --locked
```

Keep changes in the style of the surrounding module. Use `snake_case` for
functions and configuration fields, `UpperCamelCase` for Rust types, and
descriptive names for listeners and backends. Avoid mixing a behavior change
with unrelated formatting or dependency updates. If a check already reports
an issue on the base revision, distinguish it from a new regression in the
pull request.

Tests should reproduce a behavior, not require a particular machine or a
live external service. A test that needs an optional kernel feature or an
external fixture should detect its availability and skip with a reason when
it is absent. For manual networking tests, use an isolated configuration and
free ports; clean up the test process, keys and temporary files afterwards.

The forwarding backpressure regression uses Python 3, a C compiler and an
isolated child process on ephemeral loopback ports:

```sh
python3 tests/forwarder-backpressure/check.py ./target/release/sni-router
```

It injects temporary `EAGAIN` results while sockets remain writable, checks
that retries stay bounded, and verifies byte integrity and TCP half-closes
for both splice and the copy fallback. It skips unsupported hosts, including
WSL1. The preload library is applied only to the test child.

There is no GitHub Actions build/test workflow in this repository. Include
the commands you ran and their results in the pull request, along with any
checks you could not run.

## Parser changes

The release profile uses `panic = "abort"`, so a panic while parsing client
bytes terminates the process. Changes to the TLS or QUIC parsers need unit
tests for the affected boundary conditions and a 60-second run of each fuzz
target:

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly
cargo +nightly fuzz run tls_sni -- -max_total_time=60
cargo +nightly fuzz run tls_fragmented -- -max_total_time=60
cargo +nightly fuzz run quic_initial -- -max_total_time=60
```

| Target | Coverage |
| --- | --- |
| `tls_sni` | TLS record framing and ClientHello extensions |
| `tls_fragmented` | Incremental input split across reads and records |
| `quic_initial` | Initial headers, decryption, CRYPTO frames and reassembly offsets |

A crash is written under `fuzz/artifacts/<target>/`. For example, to replay a
TLS parser crash, replace the filename below with the artifact's actual name:

```sh
cargo +nightly fuzz run tls_sni fuzz/artifacts/tls_sni/crash-HASH
```

Turn a confirmed failure into a small regression test. Keep generated fuzz
corpora and build artifacts out of the pull request.

The optional [Technitium interoperability check](tests/technitium-interop/README.md)
tests UDP PROXY framing against the upstream parser. It needs the .NET 10 SDK
and a TechnitiumLibrary checkout; it is separate from `cargo test`.

## Documentation changes

README is the entry point; detailed behavior belongs in `docs/`, and complete
YAML examples belong in `config/examples/`. Use English in public
documentation, with commands and examples that can be copied without
reconstructing missing sections.

Check defaults and mode restrictions against `src/config/mod.rs` and
`src/config/validate.rs`. Follow the runtime implementation when comments or
old documentation disagree. A new field or behavior needs its reference,
relevant guide and example updated in the same change.

Validate example files with the built binary:

```sh
./target/release/sni-router -t config/examples/passthrough.yaml
```

TLS examples deliberately use certificate paths that must be replaced with
readable test files before validation. `-t` does not bind ports or connect to
backends. `--check-backends` performs real TCP probes, so use it only against
destinations you intend to test. Check relative Markdown links and keep real
addresses, API tokens and private keys out of examples.

## Pull requests and releases

Keep the title specific to the resulting behavior. Explain the problem,
the change, its compatibility impact and the checks performed. Update the
documentation when a user would need to change how they configure or operate
the router.

Release versions must agree across `Cargo.toml`, the package entry in
`Cargo.lock`, `snap/snapcraft.yaml` and the `vX.Y.Z` Git tag. A release includes
the Linux binary archive named `sni-router-vX.Y.Z-x86_64-linux.tar.gz` and a
`SHA256SUMS` asset: the self-updater requires the checksum manifest. Publishing
releases and Snap revisions is handled by the maintainer.

Contributions are licensed under the project's [Apache-2.0 license](LICENSE).
