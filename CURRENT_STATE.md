# Current State

Updated inside every PR that changes it. Never updated locally after merge.

## Version

Unreleased (pre-`v0.1.0`).

## Active milestone

**A2 — Library core: keys, encoding, events, signatures** (targets `v0.1.0`).

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
  official NIP-06 test vectors byte-for-byte. This closes out A2's Tier-1
  scope — all acceptance criteria in issue #2 are now met except the
  version tag.

## What's in progress

- A2: nothing left but tagging `v0.1.0` (issue #2's acceptance criteria are
  all met: BIP-340 suite, NIP-19 round trips, NIP-06 + NIP-49 tests, NIP-01
  id-hash tests).

## What's next

1. Tag `v0.1.0`, close issue #2, write release notes.
2. Start A3 (transport: relays, subscriptions, outbox routing).

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
| Transport & outbox (NIP-65) | not started |
| Local event store | not started |
| Encryption (NIP-44/17/59) + signer interface | not started |
