# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: breaking changes bump the minor version, features/fixes bump the patch version).

## [Unreleased]

## [0.3.6] - 2026-07-21

### Added

- Signer support (experimental, pre-1.0), so a NIP-46 signer is a thin shell
  over the library rather than a fork of it: a `keystore` module for the
  encrypted key at rest (NIP-49 `ncryptsec` plus a `0600` key file), a `signer`
  module with the transport serve loop that answers kind:24133 requests over any
  relay connection (with NIP-42 auth), and `nip46.PolicyConfig` for
  least-privilege method and event-kind allowlists. The serve loop is proven
  hermetically against an in-memory connection. The loopback IPC wire types are
  intentionally deferred until an HTTP signer consumes them, so the library ships
  no unused surface.

### Fixed

- NIP-49 now Unicode-NFKC-normalizes the password before the scrypt KDF, as the
  spec requires (`src/nip49.zig`). Previously non-ASCII passwords were passed
  through unnormalized, so this library and another NIP-49 implementation could
  derive different keys from the same password typed in a different Unicode form
  — a silent decryption failure. Normalization uses the pure-Zig `zg` Unicode
  library and keeps an allocation-free fast path for ASCII passwords (#18).

## [0.3.5] - 2026-07-12

### Added

- NIP-42 authentication of clients to relays (`src/nip42.zig`): `authEvent`
  builds and signs the `kind:22242` event (a `relay` tag and the relay's
  `challenge`) that answers a relay's `["AUTH", <challenge>]`. `message.zig`
  parses that challenge into a new `RelayMessage.auth` variant (it previously
  returned `InvalidMessage`, dropping the connection) and `encodeAuth` emits the
  client's `["AUTH", <event>]` reply; `Connection.authenticate` /
  `Relay.authenticate` send it. This lets a signer serve NIP-46 over relays that
  gate reads/writes behind authentication. Verified live against a relay
  requiring NIP-42 (`nak serve --auth`): full round-trip, valid signed event.

### Fixed

- The WebSocket opening handshake now includes a non-default port in the `Host`
  header (RFC 9110 §7.2) — `Host: relay.example.com:8443`, not just
  `Host: relay.example.com`. Relays that derive their canonical URL from `Host`
  compare it against a NIP-42 auth event's `relay` tag; omitting the port made
  them mismatch and reject the authentication. Default ports (80/443) stay
  omitted, so standard `ws://`/`wss://` relays are unaffected. Adds
  `relay.Url.hostHeader`.

## [0.3.4] - 2026-07-12

### Fixed

- The live relay connection no longer stalls request delivery over `wss://`.
  `IoStream.read` returned bytes via the generic `readVec` into the full 4 KiB
  receive buffer, which greedily keeps reading until that buffer fills — so a
  relay message that had already arrived was drained into the buffer and then
  the read *blocked on the next TLS record* to fill the remaining space,
  withholding the message until unrelated later traffic (a client retry, a
  relay ping) happened to arrive. Every NIP-46 request to a running signer
  stalled behind the following record — tens of seconds, or indefinitely. It
  now serves already-buffered bytes and otherwise does exactly one underlying
  read (`fillMore`), so each message surfaces the moment its record lands, on
  both `ws://` and `wss://`. This was the real cause of non-delivery over public
  relays like `relay.damus.io` (not NIP-42 AUTH); verified live with a full
  NIP-46 round-trip completing in ~3 s at sub-second per-request latency.
  Supersedes the #44 / #46 read iterations, which fixed the handshake but left
  this receive-path stall. (#49)

## [0.3.3] - 2026-07-12

### Fixed

- The live relay connection no longer fails the TLS websocket handshake. The
  v0.3.2 read fix returned after a single `readVec`, but a `readVec` of *zero*
  bytes means "no application data yet", not end-of-stream — a TLS record can
  carry none — so reporting it as EOF failed the handshake against real `wss://`
  relays (it was fine for plaintext `ws://`). `IoStream.read` now retries past a
  bare zero read and returns only on the first real bytes or a genuine end of
  stream. Verified live: `ws://` and `wss://` both complete the handshake and a
  full request round-trip over a local relay. (#46)

## [0.3.2] - 2026-07-12

### Fixed

- The live relay connection no longer deadlocks the websocket opening
  handshake. `IoStream.read` used `readSliceShort`, which blocks until it has
  filled the *whole* read buffer — so reading a short `101 Switching Protocols`
  response (~129 bytes) into a 4 KiB buffer waited forever for bytes the relay
  only sends after we subscribe, and `dial` never returned. It now reads once
  and returns whatever is available (`readVec`), like a POSIX `read`. This was
  why a running signer connected to relays but never received any requests.
  Adds a regression test pinning the read primitive. (#44)

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
