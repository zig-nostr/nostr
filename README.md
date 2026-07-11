# nostr

The [Nostr](https://nostr.com) protocol library for [Zig](https://ziglang.org).

[![CI](https://github.com/zig-nostr/nostr/actions/workflows/ci.yml/badge.svg)](https://github.com/zig-nostr/nostr/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`zig-nostr/nostr` aims to be the foundational Nostr implementation for Zig,
in the spirit of [`rust-nostr`](https://github.com/rust-nostr/nostr) for
Rust: keys and encoding, event construction and BIP-340 signatures, relay
transport with the outbox model, NIP-44/NIP-17 encrypted messaging, and a
zero-copy local event store modeled on
[nostrdb](https://github.com/damus-io/nostrdb).

**Status: pre-alpha, `v0.3.1`.** The library core, relay transport, the
local-first event store, and the NIP-46 signer protocol layer have shipped:

- **Milestone A2 — library core:** secp256k1 keys and BIP-340 Schnorr
  signatures (audited libsecp256k1 binding, full official test-vector suite
  passing), the NIP-01 event model with canonical id hashing and signing,
  NIP-19 bech32 entity encoding, NIP-06 mnemonic-based key derivation, and
  NIP-49 encrypted key storage.
- **Milestone A3 — transport:** RFC 6455 WebSocket framing and handshake, a
  relay connection state machine with NIP-01 subscriptions, a live TCP/TLS
  dialer, and NIP-65 relay lists with outbox routing.
- **Milestone A4 — local-first store:** a zero-copy, memory-mapped LMDB event
  store with secondary indexes and a filter-driven query API, validate-on-
  insert ingestion (dedup, replaceable/parameterized, NIP-09 deletion), a
  direct-message conversation index, local-first reconciliation, and a
  size-cap cache.
- **Milestone A5 (in progress) — signer protocol layer:** NIP-44 v2 payload
  encryption and the NIP-46 remote-signing ("bunker") protocol — the
  request/response messages, the `kind:24133` envelope, a transport-agnostic
  dispatcher behind an approval policy, and the `bunker://` / `nostrconnect://`
  connection URIs. The native signer app is being built in
  [`zig-nostr/signer`](https://github.com/zig-nostr/signer).

Native signer, messenger, and reader showcases land in upcoming milestones —
see [`CURRENT_STATE.md`](CURRENT_STATE.md) for what's in progress and the
[project board](https://github.com/orgs/zig-nostr/projects) for the full
milestone roadmap.

## Install

```sh
zig fetch --save https://github.com/zig-nostr/nostr/archive/refs/tags/v0.3.1.tar.gz
```

Then in `build.zig`:

```zig
const nostr = b.dependency("nostr", .{ .target = target, .optimize = optimize });
your_module.addImport("nostr", nostr.module("nostr"));
```

## Development

```sh
zig build        # build the library
zig build test   # run the test suite
zig fmt --check . # verify formatting
```

Zig version is pinned in [`.zigversion`](.zigversion).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the branch/PR/commit workflow,
and [`AGENTS.md`](AGENTS.md) for a contributor- and agent-facing overview of
the codebase.

## License

MIT — see [`LICENSE`](LICENSE).
