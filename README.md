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

**Status: pre-alpha.** The repository currently contains only workflow and
build scaffolding (Milestone A1). No protocol functionality has shipped yet
— see [`CURRENT_STATE.md`](CURRENT_STATE.md) for what's in progress and the
[project board](https://github.com/orgs/zig-nostr/projects) for the full
milestone roadmap.

## Install

Not yet published. Once Milestone A2 ships an installable module:

```
zig fetch --save https://github.com/zig-nostr/nostr/archive/<ref>.tar.gz
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
