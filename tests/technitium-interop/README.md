# Technitium interop check

Proves that the datagrams `sni-router` puts on the wire for `proto: udp` +
`proxy_protocol: v1|v2` are accepted by **Technitium's own PROXY protocol
parser** — the one its `DNS-over-UDP-PROXY` listener runs on every datagram.

It is not a copy of their parser: the `.csproj` compiles
`TechnitiumLibrary.Net/ProxyProtocol/ProxyProtocolStream.cs` straight out of a
[TechnitiumLibrary](https://github.com/TechnitiumSoftware/TechnitiumLibrary)
checkout, so the check goes red if their format expectations ever move.

The header bytes are pinned to the same literal as the Rust test
`proxy_protocol::tests::v2_udp_wire_bytes_are_pinned`. Two tests, two languages,
one constant — drift on either side shows up immediately.

## Running it

Needs the .NET 10 SDK and a TechnitiumLibrary checkout next to this repo
(`../TechnitiumLibrary`):

```sh
dotnet run --project tests/technitium-interop
```

Elsewhere, point it at the checkout:

```sh
dotnet run --project tests/technitium-interop -p:TechnitiumLibraryDir=/path/to/TechnitiumLibrary
```

Exit code `0` means every case behaved as expected. Optional — it is not part of
`cargo test` and nothing in the build depends on it.

## What it covers

| case | expectation |
|---|---|
| v2 header on a datagram, IPv4 client | parses; client IP/port recovered; DNS query byte-exact after `DataOffset` |
| the same on a following datagram | parses identically — no state carried from the first |
| v2 header, IPv6 client | parses; 36-byte address block |
| v1 (text) header | parses |
| bare query, no header | **rejected** — this is what every datagram after the first looked like before 1.8.0 |
| header alone in a datagram | parses but carries zero payload — the other half of the pre-1.8.0 failure |

The last two are the regression proof: together they are exactly why a
Technitium backend saw complete silence rather than an error.
