# Current State

Updated inside every PR that changes it. Never updated locally after merge.

## Version

`v0.2.1` — Milestones A2 (library core), A3 (transport), and A4 (local-first
event store) complete, plus the bounded-query performance patch (#33).

## Active milestone

**A5 — Showcase 1: native Signer + NIP-46 bunker.** (In progress — the
library-side cryptographic groundwork is landing first.)

## What's done

- Build system: `nostr` module, `zig build test` wired up.
- CI: Linux + macOS matrix running build/test/fmt.
- Contributor docs: `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODEOWNERS`, issue and PR templates.
- GitHub labels, milestones A1–A8, issues, and public project board.
- NIP-19 bech32 entity encoding (`npub`/`nsec`/`note` bare,
  `nprofile`/`nevent`/`naddr`/`nrelay` TLV) + NIP-21 `nostr:` URIs, verified
  against the official spec vectors (`src/bech32.zig`, `src/nip19.zig`).
- NIP-49 encrypted private key storage (`ncryptsec`): scrypt +
  XChaCha20-Poly1305, verified against the official decryption vector
  (`src/nip49.zig`). Password NFKC normalization not implemented (documented
  limitation — Zig std has no Unicode normalization).
- NIP-01 event model: `Event` struct, canonical serialization, sha256 id
  computation, wire JSON encode/decode (`src/hex.zig`, `src/event.zig`),
  verified against hand-computed sha256 oracle vectors.
- secp256k1 keys + BIP-340 Schnorr sign/verify (`src/keys.zig`), bound to
  bitcoin-core/libsecp256k1 (compiled from source, pinned in
  `build.zig.zon`). Passes the full official BIP-340 test-vector suite
  (all 19 vectors). This is the credibility-anchor deliverable.
- Event-level signing (`event.create`/`event.verify`): builds and signs an
  event from a keypair, and verifies an event by recomputing its canonical
  id from its own fields (rejecting id/content mismatches) before checking
  the signature.
- NIP-06 key derivation (`src/bip39.zig`, `src/nip06.zig`): BIP-39 mnemonic
  generate/parse/checksum (embedded official English wordlist) and BIP-32
  HD derivation for `m/44'/1237'/<account>'/0/0`, verified against both
  official NIP-06 test vectors byte-for-byte.
- **Tagged `v0.1.0`** — Milestone A2 complete, issue #2 closed.
- Relay transport (A3): RFC 6455 WebSocket framing + handshake
  (`src/websocket.zig`), a stream-generic relay connection state machine with
  NIP-01 subscriptions (`src/relay.zig`), a live TCP/TLS dialer, and the
  NIP-01 filter/message wire types (`src/filter.zig`, `src/message.zig`).
- Outbox model (A3): NIP-65 relay lists (`kind:10002`) with read/write
  routing and zero hardcoded relays (`src/nip65.zig`).
- Local-first event store (A4): a zero-copy, memory-mapped LMDB store
  (`src/store.zig`) with a compact binary event record, secondary indexes
  (author/kind/created_at/tag) and a filter-driven query API, validate-on-
  insert ingestion with replaceable/parameterized-replaceable upserts and
  NIP-09 deletion, a direct-message conversation index, local-first
  reconciliation, a size-cap cache, and a benchmark (`src/bench.zig`).
- **Tagged `v0.2.0`** — Milestones A3 and A4 complete, issues #3 and #4 closed.
- Bounded query planning (#33): `query` walks the indexes newest-first via
  reverse cursors and a k-way merge, stopping at `limit` — a 500-note
  20-author home feed at 100k stored events dropped from ~26 ms to ~0.28 ms;
  the multi-author feed shape is covered in `src/bench.zig`.
- **Tagged `v0.2.1`** — bounded-query performance patch.
- NIP-44 v2 encryption (`src/nip44.zig`): ChaCha20 + HMAC-SHA256 with
  HKDF-derived keys over a libsecp256k1 ECDH shared secret, verified against
  the official NIP-44 test vectors (conversation keys, message keys, padding,
  and encrypt/decrypt round-trips). Groundwork for the A5 NIP-46 bunker.
- NIP-46 remote signing (`src/nip46.zig`): the request/response messages and
  JSON, the kind:24133 NIP-44 envelope (`seal`/`open`), a transport-agnostic
  `Bunker` dispatcher (connect/sign_event/ping/get_public_key/nip44_encrypt/
  nip44_decrypt) behind an injectable approval `Policy`, and the `bunker://` /
  `nostrconnect://` connection URIs (parse + build, percent-decoding, verified
  against the spec's example token). Relay I/O is left to the app.

## What's in progress

- A5 (Showcase 1): the NIP-46 library layer is complete — NIP-44 v2 encryption,
  the messages, the kind:24133 envelope, the bunker dispatch, and the
  connection URIs. Next: the native signer app in its own repo
  (`zig-nostr/signer`), which needs two decisions — creating that public repo
  and the macOS GUI approach.

## What's next

1. A5: native key manager — create/import key, NIP-49 at-rest encryption, a
   local signing API.
2. A5: NIP-46 bunker (`sign_event`/`get_public_key`/`nip44_encrypt`/
   `nip44_decrypt`/`ping`) with per-request approval.
3. A6+: NIP-44 v2 encryption and NIP-17 private messaging, then the read-only
   outbox client — see the project board for the full roadmap.

## Known blockers / pending decisions

- None. (The `bitcoin-core/secp256k1` dependency — tag `v0.7.1`, commit
  `1a53f496` — was approved and is now pinned in `build.zig.zon`.)
- Note for future randomness-needing APIs: Zig 0.16 removed the
  `std.crypto.random` global; secure randomness threads an `std.Io` instance
  through the call (`io.randomSecure(buffer)`), as in `nip49.encrypt` and
  `keys.Signer.generateKeyPair`/`initRandomized`.

## Package status

| Area | Status |
|---|---|
| Repo/CI scaffolding | done |
| NIP-19/21 encoding | done |
| NIP-49 encrypted key storage | done |
| NIP-01 event model | done |
| secp256k1 keys + BIP-340 sign/verify | done |
| Event-level sign/verify glue | done |
| NIP-06 derivation | done |
| Transport & outbox (NIP-65) | done |
| Local event store | done |
| NIP-44 v2 encryption | done |
| NIP-46 remote signing (protocol + URIs) | done |
| NIP-17/59 + signer interface | not started |
