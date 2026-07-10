# Current State

Updated inside every PR that changes it. Never updated locally after merge.

## Version

Unreleased (pre-`v0.1.0`).

## Active milestone

**A1 — Repository & workflow scaffolding.** Next up: **A2 — Library core:
keys, encoding, events, signatures** (targets `v0.1.0`).

## What's done

- Build system: `nostr` module, `zig build test` wired up, zero features.
- CI: Linux + macOS matrix running build/test/fmt.
- Contributor docs: `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODEOWNERS`, issue and PR templates.
- GitHub labels, milestones A1–A8, and the initial issue set filed.

## What's in progress

- Nothing yet — A1 scaffolding is landing as the first PR.

## What's next

1. A2: secp256k1 keypair generation, x-only pubkeys.
2. A2: NIP-19 bech32 encoding (`npub`/`nsec`/`note`/`nprofile`/`nevent`/`naddr`/`nrelay`).
3. A2: NIP-01 event struct, canonical serialization, id hashing.
4. A2: BIP-340 Schnorr sign/verify via a `bitcoin-core/secp256k1` binding,
   full official test-vector suite passing.
5. A2: NIP-06 derivation, NIP-49 encrypted-nsec-at-rest.

## Known blockers / pending decisions

- None.

## Package status

| Area | Status |
|---|---|
| Repo/CI scaffolding | done |
| Keys & encoding (NIP-19/06/49) | not started |
| Events & signatures (NIP-01, BIP-340) | not started |
| Transport & outbox (NIP-65) | not started |
| Local event store | not started |
| Encryption (NIP-44/17/59) + signer interface | not started |
