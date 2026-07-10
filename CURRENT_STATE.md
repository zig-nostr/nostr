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

## What's in progress

- A2: NIP-01 event struct, canonical serialization, id hashing — next up.

## What's next

1. A2: NIP-01 event struct, canonical serialization, id hashing.
2. A2: secp256k1 keypair generation + BIP-340 Schnorr sign/verify via a
   `bitcoin-core/secp256k1` binding, full official test-vector suite passing.
3. A2: NIP-06 derivation, NIP-49 encrypted-nsec-at-rest.

## Known blockers / pending decisions

- None.

## Package status

| Area | Status |
|---|---|
| Repo/CI scaffolding | done |
| NIP-19/21 encoding | done |
| Keys & derivation (NIP-06/49) | not started |
| Events & signatures (NIP-01, BIP-340) | not started |
| Transport & outbox (NIP-65) | not started |
| Local event store | not started |
| Encryption (NIP-44/17/59) + signer interface | not started |
