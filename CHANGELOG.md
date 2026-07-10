# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: breaking changes bump the minor version, features/fixes bump the patch version).

## [Unreleased]

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
