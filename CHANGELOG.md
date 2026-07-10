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
