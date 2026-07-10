# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately via GitHub Security
Advisories rather than opening a public issue:

**https://github.com/zig-nostr/nostr/security/advisories/new**

This applies especially to anything touching key handling, signing, or
encryption (BIP-340, NIP-44, NIP-49). We aim to acknowledge reports within a
few days.

## Scope

This library binds to audited upstream cryptography (`bitcoin-core/secp256k1`
for Schnorr signing/verification) rather than implementing signing primitives
from scratch. Vulnerabilities in those upstream libraries should also be
reported to their respective maintainers.

## Supported versions

Pre-1.0: only the latest tagged release is supported.
