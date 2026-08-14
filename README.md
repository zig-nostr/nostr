# nostr

**The Nostr protocol, natively in Zig.**

[![CI](https://github.com/zig-nostr/nostr/actions/workflows/ci.yml/badge.svg)](https://github.com/zig-nostr/nostr/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`nostr` is a foundational [Nostr](https://nostr.com) protocol library for
[Zig](https://ziglang.org): keys and signatures, events, relay transport with
the outbox model, a zero-copy local-first event store, and the NIP-46
remote-signing protocol. It's the base layer a fast, native Nostr app is built
on: no browser, no Electron, the protocol running close to the metal.

It's also the core of a small ecosystem: the library, plus native apps built on
it like [Notary](https://github.com/zig-nostr/notary), a remote signer that keeps
your key off every client. Full docs, benchmarks, and the ecosystem overview
live at [zignostr.com](https://zignostr.com).

> **Status: early (`v0.10.0`).** The library core, transport, local-first store
> and signer protocol have shipped and are covered by tests. Two native apps run
> on it today. APIs may still change before 1.0.

## Highlights

- **🔑 Credible crypto core**: secp256k1 keys and BIP-340 Schnorr signatures
  via bitcoin-core's `libsecp256k1`, passing the full official test-vector suite
  (19/19).
- **⚡ Local-first store**: a zero-copy, memory-mapped LMDB event store with a
  bounded, newest-first query planner: sub-millisecond feeds that stay flat as
  the store grows.
- **🧭 Outbox model**: NIP-65 relay lists with read/write routing and zero
  hardcoded relays; events go where they belong.
- **🔌 Live transport**: RFC 6455 WebSocket over TCP/TLS with NIP-01
  subscriptions, and a keepalive that separates a connection which has died from
  one that is merely quiet. A socket that stops answering is noticed rather than
  believed.
- **🔒 Encrypted payloads**: NIP-44 v2 authenticated encryption
  (ChaCha20 + HMAC-SHA256), verified against the official vectors.
- **🛡️ Remote signing**: the NIP-46 "bunker" protocol plus NIP-42 relay auth,
  so a key can sign for any client without ever entering it.
- **🔐 Portable keys**: NIP-06 mnemonic derivation and NIP-49 (`ncryptsec`)
  encrypted key storage, NFKC-normalized for cross-app interop.

## Performance

Performance is a design goal, not an afterthought. These are the library's own
numbers, measured with the in-repo benchmark and reproducible on your machine
(Apple Silicon, `ReleaseFast`, warm cache, best of 50; events spread across 100
authors; a 20-author `kind:1` feed returning 500 notes):

| Store size | Feed query (500 notes) | Timeline query (1 author) | Profile query | Ingest |
|----|----|----|----|----|
| 20,000 events | 0.25 ms | 0.09 ms | 0.007 ms | ~170k events/s |
| 100,000 events | 0.28 ms | 0.24 ms | 0.008 ms | ~149k events/s |

The headline isn't the ~0.28 ms feed query, it's that 5x more stored events
barely moves it. The bounded query planner walks the indexes newest-first and
stops at `limit`, so latency tracks the page size you ask for, not the size of
the store.

The profile query is the same point made sharply. Fetching one account's
`kind:0` out of a hundred thousand events reads exactly one index entry, no
matter how much that account has posted since they set it, because a filter
naming both authors and kinds is served by an index on the pair. The benchmark
prints that entry count next to the latency: it is the part a stopwatch cannot
tell you.

```sh
BENCH_N=100000 zig build bench -Doptimize=ReleaseFast
```

Methodology and the full write-up are on the
[benchmarks page](https://zignostr.com/performance).

## Quickstart

Add the library to your `build.zig.zon`:

```sh
zig fetch --save https://github.com/zig-nostr/nostr/archive/refs/tags/v0.10.0.tar.gz
```

Wire the module in `build.zig`:

```zig
const nostr = b.dependency("nostr", .{ .target = target, .optimize = optimize });
your_module.addImport("nostr", nostr.module("nostr"));
```

Sign and verify an event:

```zig
const std = @import("std");
const nostr = @import("nostr");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // A Signer wraps the libsecp256k1 context; deinit it when done.
    var signer = nostr.keys.Signer.init();
    defer signer.deinit();

    // Load a keypair from a 32-byte secret key.
    const secret: nostr.keys.SecretKey = your_secret_key; // 32 bytes
    const keypair = try signer.keyPairFromSecretKey(secret);

    // Build and sign a kind:1 text note.
    const note = try nostr.event.create(
        allocator, signer, keypair,
        std.time.timestamp(), 1, &.{}, "hello from zig-nostr", null,
    );

    // Verify: recompute the canonical id, then check the Schnorr signature.
    std.debug.assert(try nostr.event.verify(allocator, signer, note));

    // Serialize to the wire JSON form.
    const json = try nostr.event.toJson(allocator, note);
    std.debug.print("{s}\n", .{json});
}
```

The `nostr` module re-exports focused namespaces: `keys`, `event`,
`nip19`/`bech32`, `nip06`/`bip39`, `nip49`, `nip44`, `nip46`, `nip42`,
`relay`/`websocket`/`message`/`filter`, `nip65`, and `store`. See the
[getting-started guide](https://zignostr.com/getting-started) for more.

## NIP support

Every "done" NIP is covered by tests; the cryptographic ones are verified
against their official specification vectors.

| NIP | Title | Status |
|----|----|----|
| [01](https://github.com/nostr-protocol/nips/blob/master/01.md) | Basic protocol: events, signatures, subscriptions | ✅ |
| [06](https://github.com/nostr-protocol/nips/blob/master/06.md) | Key derivation from mnemonic seed | ✅ |
| [09](https://github.com/nostr-protocol/nips/blob/master/09.md) | Event deletion (ingestion) | ✅ |
| [19](https://github.com/nostr-protocol/nips/blob/master/19.md) | bech32-encoded entities | ✅ |
| [21](https://github.com/nostr-protocol/nips/blob/master/21.md) | `nostr:` URI scheme | ✅ |
| [42](https://github.com/nostr-protocol/nips/blob/master/42.md) | Client-to-relay authentication | ✅ |
| [44](https://github.com/nostr-protocol/nips/blob/master/44.md) | Encrypted payloads (v2) | ✅ |
| [46](https://github.com/nostr-protocol/nips/blob/master/46.md) | Nostr Connect, remote signing | ✅ |
| [49](https://github.com/nostr-protocol/nips/blob/master/49.md) | Private key encryption (`ncryptsec`) | ✅ |
| [65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay list metadata (outbox) | ✅ |
| [17](https://github.com/nostr-protocol/nips/blob/master/17.md) | Private direct messages | 🚧 planned |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap | 🚧 planned |
| [10](https://github.com/nostr-protocol/nips/blob/master/10.md) | Reply threading | client-side |

NIP-17 and NIP-59 arrive together, in Plaza's private-messages milestone.

NIP-10 is marked differently on purpose. There is no `nip10` module here, because
threading is a decision about how to read `e` tags rather than a format to encode:
Plaza threads replies today and does it above the library. The same is true of
reactions, mentions and DNS identifiers, which is why they are not in this table.
It lists what you get by importing the library, not what an app on top of it can
do.

## Built with it

The library is proven by native apps built on it, the ecosystem forming around
one core:

- **[Notary](https://github.com/zig-nostr/notary)**: *shipped.* A native macOS
  remote signer (NIP-46 bunker): your key lives in a local daemon, every signing
  request waits for your approval, and the `nsec` never enters a client.
- **[Plaza](https://github.com/zig-nostr/plaza)**: *shipped.* The flagship: a
  fast, local-first client where you read without an account, post in four
  clicks, and the feed renders from disk. A downloadable macOS app.

Private messages, zaps and groups land inside Plaza rather than as separate apps.
A messenger you have to switch to is one you stop using.

## Roadmap

The library foundation has shipped: keys, transport, the local-first store and
the signer protocol. Both apps are downloadable and both keep growing, so what
comes next lands inside them rather than as new apps.

In spec terms, the library still owes NIP-17 private direct messages, with the
NIP-59 gift wrap that carries them, and a `search` field on `Filter` for NIP-50.
Most of what remains is app work on protocol the library already exports:
reactions, reposts and zap receipts behind notifications, NIP-51 bookmarks and
mutes, Blossom uploads so a picture can be posted, NIP-57 zaps paid through a
NIP-47 wallet, and NIP-29 groups. The [NIP support
page](https://zignostr.com/nips) maps each one to the milestone that lands it.

There are no dates. The [roadmap](https://zignostr.com/roadmap) is an order, and
it also names what is deliberately not being built (set-reconciliation sync,
NIP-77, is on that list), which is the half most roadmaps leave out.

See [`CURRENT_STATE.md`](CURRENT_STATE.md) for exactly what's in progress, the
[roadmap](https://zignostr.com/roadmap) for the sequence, and the
[project board](https://github.com/orgs/zig-nostr/projects) for the milestone
tracker.

## Development

```sh
zig build          # build the library
zig build test     # run the test suite
zig fmt --check .  # verify formatting
```

The Zig version is pinned in [`.zigversion`](.zigversion). The library vendors
and compiles `libsecp256k1` and LMDB from source, so no system packages are
required.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the branch/PR/commit workflow and
[`AGENTS.md`](AGENTS.md) for a contributor- and agent-facing tour of the
codebase.

## License

MIT, see [`LICENSE`](LICENSE).
