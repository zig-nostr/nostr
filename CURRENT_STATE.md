# Current state

A snapshot for somebody reading this repo. The
[roadmap](https://zignostr.com/roadmap) says what comes next; this file only says
where things stand today.

Version numbers are deliberately not repeated here. This file went nine releases
out of date saying them, and a stale number is worse than no number: it is
readable, specific and wrong. Each project's own releases page is the answer.

## The library

[Latest release](https://github.com/zig-nostr/nostr/releases). Shipped and
covered by tests:

- **Core**: secp256k1 keys, BIP-340 Schnorr signatures against the official
  vectors, the NIP-01 event model, NIP-19/21 encoding, NIP-06 derivation, NIP-49
  encrypted keys.
- **Transport**: RFC 6455 WebSocket, a relay connection state machine, a live
  TCP/TLS dialer, NIP-42 authentication, and the NIP-65 outbox model with no
  hardcoded relays. A read can carry a deadline, so a thread serving a quiet
  relay can still notice that its pool changed, and a failed dial can report the
  HTTP status the relay answered the upgrade with.
- **Store**: a memory-mapped LMDB event store with a bounded, newest-first query
  planner. A 500-note feed query is 0.28 ms at 100,000 stored events, and a
  profile read is 8 microseconds. A NIP-50 `search` on a filter is sent to relays
  as is, and the store applies it as a case-insensitive substring of the content.
- **Signing**: NIP-44 v2, and the NIP-46 bunker protocol as both client and
  server, so a signer is a shell over the library rather than its own
  implementation.

The library builds for macOS, Linux and Windows (x86_64 and aarch64 on each). CI builds and runs the tests on Linux, macOS and Windows. On Windows, hostnames resolve through std's resolver and both the wait for bytes before a read's deadline and the wait for room before a pong are a poll request to the AFD driver; the other platforms keep libc `getaddrinfo`, a timed peek and `poll`.

The parsers that read bytes from outside (frames, relay messages, events, NIP-19, NIP-44, NIP-46, connection URIs, key files) have fuzz targets that run over a seed corpus in every `zig build test` and can be fuzzed for real. [`ARCHITECTURE.md`](ARCHITECTURE.md) says how the pieces fit.

APIs may still change. There is no 1.0 date, and tagging one is deliberately not
on the roadmap while groups, messages, media and payments are still landing.

## The apps

- **[Notary](https://github.com/zig-nostr/notary)**: a native NIP-46 signer.
  Your key lives in a local daemon, nothing signs without your approval, and the
  `nsec` never enters a client.
- **[Plaza](https://github.com/zig-nostr/plaza)**: the flagship client. Read
  without an account, post in four clicks, with the feed rendered from disk.
  Reads every account you follow, with no cap on how far you can scroll.

Both are downloadable for macOS (Apple Silicon) and Linux (x86_64 and aarch64).
Off macOS there is no platform text layer, so both draw every glyph from faces
they carry: emoji are drawn in colour, and scripts those faces do not cover are
not drawn at all.

## What is next

For the library:

- A C ABI over keys, events, NIP-19, NIP-44, relay reads and the local store, with a C header, and Swift bindings published as a Swift package. Both are tested in CI.
- An app engine extracted from Plaza: sync, relay and outbox routing, signer sessions, caches for profiles, follow lists and relay lists, and content parsing into structured data. It has no views and no UI templates, so an app gets data and draws its own interface. Plaza moves onto it, and new small apps can be built on it, each with its own interface.
- An Android proof of concept that uses the library through the C ABI to read a feed into a local store on a phone. It is a proof of concept, not a store release.

Around the library: Notary packaged for Windows, so the library, deed and Notary are each tested on Windows, macOS and Linux; `deed mcp`, which puts deed's verbs behind the Model Context Protocol so an agent can read relays, query the local store and verify events, with signing only through a NIP-46 signer that asks first; and Plaza 1.0. Plaza's own next features, such as zaps you can send, notifications and private messages, are on the [roadmap](https://zignostr.com/roadmap) too.

That page also lists what is deliberately **not** being built, and why. Reading
the second half is the faster way to understand the first.
