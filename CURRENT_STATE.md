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

## What's in progress

- A2: NIP-01 event struct, canonical serialization, id hashing, and the
  secp256k1/BIP-340 binding — both next up (secp256k1 dependency pin is
  pending explicit user approval, see below).

## What's next

1. A2: NIP-01 event struct, canonical serialization, id hashing.
2. A2: secp256k1 keypair generation + BIP-340 Schnorr sign/verify via a
   `bitcoin-core/secp256k1` binding, full official test-vector suite passing.
3. A2: NIP-06 derivation (also depends on secp256k1 for non-hardened HD
   derivation steps, which require EC point multiplication).

## Known blockers / pending decisions

- Adding `bitcoin-core/secp256k1` as a compiled `build.zig.zon` dependency
  needs explicit user sign-off before it's pinned (proposed: tag `v0.7.1`,
  commit `1a53f496`). Blocks BIP-340 signing and NIP-06 derivation.
- Zig 0.16 removed the `std.crypto.random` global; secure randomness now
  requires threading an `std.Io` instance through any function that needs
  fresh entropy (`io.randomSecure(buffer)`), e.g. `nip49.encrypt`. Future
  randomness-needing APIs (keygen, gift-wrap disposable keys, signing
  aux_rand) should follow the same pattern.

## Package status

| Area | Status |
|---|---|
| Repo/CI scaffolding | done |
| NIP-19/21 encoding | done |
| NIP-49 encrypted key storage | done |
| Keys, signatures (BIP-340), NIP-06 | not started (blocked on secp256k1 dependency approval) |
| Events & signatures (NIP-01) | not started |
| Transport & outbox (NIP-65) | not started |
| Local event store | not started |
| Encryption (NIP-44/17/59) + signer interface | not started |
