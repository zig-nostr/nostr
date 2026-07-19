# nostr

**The Nostr protocol, natively in Zig.**

[![CI](https://github.com/zig-nostr/nostr/actions/workflows/ci.yml/badge.svg)](https://github.com/zig-nostr/nostr/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`nostr` is a foundational [Nostr](https://nostr.com) protocol library for
[Zig](https://ziglang.org) — keys and signatures, events, relay transport with
the outbox model, a zero-copy local-first event store, and the NIP-46
remote-signing protocol. It's the base layer a fast, native Nostr app is built
on: no browser, no Electron, the protocol running close to the metal.

It's also the core of a small ecosystem — the library, plus native apps built on
it like [Signet](https://github.com/zig-nostr/signet), a remote signer that keeps
your key off every client. Full docs, benchmarks, and the ecosystem overview
live at [zignostr.com](https://zignostr.com).

> **Status: pre-alpha (`v0.3.5`).** The library core, transport, local-first
> store, and signer protocol have shipped and are covered by tests. APIs may
> still change before 1.0.

## Highlights

- **🔑 Credible crypto core** — secp256k1 keys and BIP-340 Schnorr signatures
  via bitcoin-core's `libsecp256k1`, passing the full official test-vector suite
  (19/19).
- **⚡ Local-first store** — a zero-copy, memory-mapped LMDB event store with a
  bounded, newest-first query planner: sub-millisecond feeds that stay flat as
  the store grows.
- **🧭 Outbox model** — NIP-65 relay lists with read/write routing and zero
  hardcoded relays; events go where they belong.
- **🔒 Encrypted payloads** — NIP-44 v2 authenticated encryption
  (ChaCha20 + HMAC-SHA256), verified against the official vectors.
- **🛡️ Remote signing** — the NIP-46 "bunker" protocol plus NIP-42 relay auth,
  so a key can sign for any client without ever entering it.
- **🔐 Portable keys** — NIP-06 mnemonic derivation and NIP-49 (`ncryptsec`)
  encrypted key storage, NFKC-normalized for cross-app interop.

## Performance

Performance is a design goal, not an afterthought. These are the library's own
numbers — measured with the in-repo benchmark and reproducible on your machine
(Apple Silicon, `ReleaseFast`, warm cache, best of 50; events spread across 100
authors; a 20-author `kind:1` feed returning 500 notes):

| Store size | Feed query (500 notes) | Profile query | Ingest |
|----|----|----|----|
| 20,000 events | 0.26 ms | 0.09 ms | ~135k events/s |
| 100,000 events | 0.28 ms | 0.25 ms | ~135k events/s |

The headline isn't the ~0.28 ms feed query — it's that 5× more stored events
barely moves it. The bounded query planner walks the indexes newest-first and
stops at `limit`, so latency tracks the page size you ask for, not the size of
the store.

```sh
BENCH_N=100000 zig build bench -Doptimize=ReleaseFast
```

Methodology and the full write-up are on the
[benchmarks page](https://zignostr.com/performance).

## Quickstart

Add the library to your `build.zig.zon`:

```sh
zig fetch --save https://github.com/zig-nostr/nostr/archive/refs/tags/v0.3.5.tar.gz
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
| [46](https://github.com/nostr-protocol/nips/blob/master/46.md) | Nostr Connect — remote signing | ✅ |
| [49](https://github.com/nostr-protocol/nips/blob/master/49.md) | Private key encryption (`ncryptsec`) | ✅ |
| [65](https://github.com/nostr-protocol/nips/blob/master/65.md) | Relay list metadata (outbox) | ✅ |
| [17](https://github.com/nostr-protocol/nips/blob/master/17.md) | Private direct messages | 🚧 planned |
| [59](https://github.com/nostr-protocol/nips/blob/master/59.md) | Gift wrap | 🚧 planned |
| [10](https://github.com/nostr-protocol/nips/blob/master/10.md) | Reply threading | 🚧 planned |

Planned NIPs arrive with the showcase apps below.

## Built with it

The library is proven by native apps built on it — the ecosystem forming around
one core:

- **[Signet](https://github.com/zig-nostr/signet)** — *shipped.* A native macOS
  remote signer (NIP-46 bunker): your key lives in a local daemon, every signing
  request waits for your approval, and the `nsec` never enters a client.
- **Plaza** — *in progress.* The flagship: a fast, local-first client where you
  browse and post within two minutes and the feed renders from disk.
- **Messenger** — *planned.* Private NIP-17 direct messages, signing through
  Signet.

## Roadmap

The library foundation has shipped — keys, transport, the local-first store, and
the signer protocol. The flagship client is in progress, followed by a one-year
roadmap of more NIPs, utility libraries, additional apps, and more platforms
(desktop and mobile).

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

MIT — see [`LICENSE`](LICENSE).
