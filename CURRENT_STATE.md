# Current state

A snapshot for somebody reading this repo. The
[roadmap](https://zignostr.com/roadmap) is the plan and the
[milestones](https://github.com/zig-nostr/plaza/milestones) are the tracker; this
file only says where things stand today.

## The library

`v0.4.0`. Shipped and covered by tests:

- **Core**: secp256k1 keys, BIP-340 Schnorr signatures against the official
  vectors, the NIP-01 event model, NIP-19/21 encoding, NIP-06 derivation, NIP-49
  encrypted keys.
- **Transport**: RFC 6455 WebSocket, a relay connection state machine, a live
  TCP/TLS dialer, NIP-42 authentication, and the NIP-65 outbox model with no
  hardcoded relays.
- **Store**: a memory-mapped LMDB event store with a bounded, newest-first query
  planner. A 500-note feed query is 0.28 ms at 100,000 stored events, and a
  profile read is 8 microseconds.
- **Signing**: NIP-44 v2, and the NIP-46 bunker protocol as both client and
  server, so a signer is a shell over the library rather than its own
  implementation.

APIs may still change. There is no 1.0 date, and tagging one is deliberately not
on the roadmap while groups, messages, media and payments are still landing.

## The apps

- **[Notary](https://github.com/zig-nostr/notary)** `v0.3.0`: a native macOS
  NIP-46 signer. Your key lives in a local daemon, nothing signs without your
  approval, and the `nsec` never enters a client.
- **[Plaza](https://github.com/zig-nostr/plaza)** `v0.2.0`: the flagship client.
  Read without an account, post in four clicks, with the feed rendered from
  disk. Reads
  every account you follow, with no cap on how far you can scroll.

Both are downloadable. What comes next lands inside them rather than as new apps.

## What is next

The ten milestones, in order, are on the
[roadmap](https://zignostr.com/roadmap). The first is notifications: who acted,
what they did, and the note it was about, which the current one-line row does not
say.

That page also lists what is deliberately **not** being built, and why. Reading
the second half is the faster way to understand the first.
