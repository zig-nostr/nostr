# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: breaking changes bump the minor version, features/fixes bump the patch version).

## [Unreleased]

## [0.3.1] - 2026-07-11

### Fixed

- `relay.dial` now resolves relay hostnames with the system resolver (libc
  `getaddrinfo`) instead of std's built-in resolver. std reads nameservers from
  `/etc/resolv.conf`, which is empty on macOS, so it fell back to a dead
  `127.0.0.1:53` and a hostname lookup hung indefinitely. The live dialer now
  connects by hostname on both macOS and Linux. (#41)

## [0.3.0] - 2026-07-11

Milestone A5 groundwork: NIP-44 v2 encryption and the NIP-46 remote-signing
("bunker") protocol layer, so a signer can hold the user's key and sign for
remote clients over a relay.

### Added

- NIP-44 v2 payload encryption (`src/nip44.zig`): ChaCha20 + HMAC-SHA256 with
  HKDF-derived message keys over a libsecp256k1 ECDH shared secret, spec
  padding, and a constant-time MAC that fails closed. Verified against the
  official NIP-44 test vectors — conversation keys, message keys, padding, and
  encrypt/decrypt round-trips. Adds `keys.Signer.sharedSecretX` (raw-x ECDH via
  a custom libsecp256k1 hash callback). (#37)
- NIP-46 remote signing (`src/nip46.zig`): the request/response messages and
  their JSON, the `kind:24133` NIP-44 envelope (`seal`/`open`), and a
  transport-agnostic `Bunker` dispatcher — `connect`, `sign_event`, `ping`,
  `get_public_key`, `nip44_encrypt`, `nip44_decrypt` — behind an injectable
  approval `Policy`, keeping the connection key separate from the user key.
  (#38)
- NIP-46 `bunker://` and `nostrconnect://` connection URIs (`src/nip46.zig`):
  parse and build with RFC 3986 percent-coding, verified against the spec's
  example token. (#39)

## [0.2.1] - 2026-07-11

### Changed

- `Store.query` now answers from a bounded newest-first index merge — one
  reverse cursor per index prefix, k-way merged on the order-preserving
  `[time][id]` key suffix, stopping at `limit` — so query cost is proportional
  to the events returned, not the total matching history. A 500-note,
  20-author home feed over 100k stored events dropped from ~26 ms to ~0.28 ms.
  Ordering and filter semantics are unchanged. (#33, #35)

### Added

- A multi-author home-feed shape in the store benchmark (`src/bench.zig`),
  alongside the single-author profile query. (#34)

## [0.2.0] - 2026-07-10

Milestones A3 (relay transport) and A4 (the local-first event store).

### Added

- Relay transport (A3): RFC 6455 WebSocket framing and handshake
  (`src/websocket.zig`), a stream-generic relay connection state machine with
  NIP-01 subscriptions and a live TCP/TLS dialer (`src/relay.zig`), and the
  NIP-01 filter and client/relay message wire types (`src/filter.zig`,
  `src/message.zig`).
- Outbox model (A3): NIP-65 relay lists (`kind:10002`) with read/write routing
  and zero hardcoded relays (`src/nip65.zig`).
- Local-first event store (A4): a zero-copy, memory-mapped LMDB store
  (`src/store.zig`) with a compact binary event record, secondary indexes
  (author / kind / created_at / single-letter tags), and a filter-driven query
  API that reuses the subscription matching semantics. Validate-on-insert
  ingestion with replaceable and parameterized-replaceable "latest-wins"
  upserts and NIP-09 deletion, a direct-message conversation index,
  local-first reconciliation helpers, a size-cap cache, and batched bulk
  insert with a benchmark (`src/bench.zig`).

### Fixed

- `nostr.version` now reports the package version; the `v0.1.0` release shipped
  with the placeholder `0.0.0`. (#17)

## [0.1.0] - 2026-07-10

Milestone A2: the cryptographic and data foundation of the library —
keys, encoding, events, and signatures, all verified against official
spec test vectors.

### Added

- Repository and workflow scaffolding (Milestone A1): build system, CI,
  contributor docs, issue/PR templates.
- NIP-19 bech32-encoded entities: `npub`/`nsec`/`note` bare encoding,
  `nprofile`/`nevent`/`naddr`/`nrelay` TLV encoding, and NIP-21 `nostr:`
  URIs, verified against the official NIP-19 spec vectors.
- NIP-49 encrypted private key storage (`ncryptsec`): scrypt + XChaCha20-
  Poly1305, verified against the official NIP-49 decryption vector. Password
  Unicode NFKC normalization is not implemented (documented limitation).
- NIP-01 event model: `Event` struct, canonical serialization for id
  hashing (strict escaping per spec), sha256 id computation, and
  wire-format JSON encode/decode.
- secp256k1 keys and BIP-340 Schnorr signatures: keypair generation,
  x-only public keys, and sign/verify, bound to bitcoin-core's audited
  libsecp256k1 (compiled from source, pinned in `build.zig.zon`). Passes the
  full official BIP-340 test-vector suite (all 19 vectors, signing and
  verification).
- Event-level signing: `event.create` builds and signs an event from a
  keypair; `event.verify` recomputes the canonical id from the event's own
  fields (rejecting any mismatch) and checks the signature against it.
- NIP-06 key derivation: BIP-39 mnemonic generation/parsing/checksum
  (embedded official English wordlist) and BIP-32 HD derivation for path
  `m/44'/1237'/<account>'/0/0`, verified against both official NIP-06 test
  vectors (secret key and public key, byte-for-byte). Password/mnemonic
  Unicode NFKD normalization is not implemented (same documented limitation
  as NIP-49's NFKC gap).
