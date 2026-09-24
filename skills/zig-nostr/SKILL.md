---
name: zig-nostr
description: Build nostr software in Zig with zig-nostr's `nostr` library. Use when a Zig project needs nostr keys and BIP-340 signatures, NIP-01 events (create, sign, verify, serialize), NIP-19 codes, NIP-44 encryption, NIP-46 remote signing, relay connections (dial, subscribe, publish, read with a deadline), the NIP-65 outbox model, or a local-first LMDB event store with fast queries. Also use when adding the library to build.zig.zon, or when porting Zig nostr code to Zig 0.16's std.Io.
---

# zig-nostr: the nostr library for Zig

`nostr` is a nostr protocol library for Zig 0.16: keys and BIP-340 Schnorr signatures (libsecp256k1, full official test vectors), NIP-01 events, NIP-19, NIP-44, NIP-46 as client and server, NIP-42, NIP-49, NIP-06, relay transport with deadlines, NIP-65, and a memory-mapped LMDB event store. libsecp256k1 and LMDB are compiled from source, so no system packages are needed. Pre-1.0: APIs can still change between minor versions.

## Add it

```sh
zig fetch --save https://github.com/zig-nostr/nostr/archive/refs/tags/v0.14.7.tar.gz
```

Check https://github.com/zig-nostr/nostr/releases for the latest tag. In `build.zig`:

```zig
const nostr = b.dependency("nostr", .{ .target = target, .optimize = optimize });
exe_mod.addImport("nostr", nostr.module("nostr"));
```

## Zig 0.16 basics this library assumes

Time, randomness, sockets and threads come from a `std.Io`. Make one once and pass it down:

```zig
var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{}); // needs a thread-safe allocator
defer threaded.deinit();
const io = threaded.io();
```

## Keys, events, NIP-19, NIP-44

Every snippet here was compiled and run against v0.14.7.

```zig
const std = @import("std");
const nostr = @import("nostr");

var signer = nostr.keys.Signer.init(); // wraps the libsecp256k1 context
defer signer.deinit();
const me = try signer.generateKeyPair(io);           // or signer.keyPairFromSecretKey(secret32)
const npub = try nostr.nip19.encodeNpub(allocator, me.public_key);
const pk = try nostr.nip19.decodeNpub(allocator, npub);

const now = std.Io.Timestamp.now(io, .real).toSeconds();
const tags = [_]nostr.event.Tag{&.{ "t", "zig" }};
const note = try nostr.event.create(allocator, signer, me, now, 1, &tags, "hello", null);
std.debug.assert(try nostr.event.verify(allocator, signer, note)); // recomputes the id, checks the signature
const json = try nostr.event.toJson(allocator, note);
var parsed = try nostr.event.fromJson(gpa, json); // parsed.value is the Event
defer parsed.deinit();

const payload = try nostr.nip44.encrypt(allocator, io, signer, me.secret_key, their_pubkey, "meet at six");
const plain = try nostr.nip44.decrypt(allocator, signer, my_secret_key, their_pubkey, payload);
```

`nip19` also has `encodeNsec`, `encodeNote`, `encodeNprofile`, `encodeNevent`, `encodeNaddr` and their `decode*` twins.

## Relays

```zig
const relay = try nostr.relay.dial(allocator, io, "wss://relay.example");
defer relay.deinit();
try relay.subscribe("feed", &.{.{ .kinds = &.{1}, .limit = 20 }});
while (true) {
    var msg = (relay.receiveTimeout(.{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } }) catch |e| switch (e) {
        error.Timeout => break, // nothing arrived in time; the connection is still usable
        else => return e,
    }) orelse break; // null: the relay closed the connection
    defer msg.deinit();
    switch (msg.value) {
        .event => |e| if (try nostr.event.verify(allocator, signer, e.event)) {
            // e.event is a verified event
        },
        .eose => break, // the relay has sent everything it had stored
        else => {},
    }
}
try relay.publish(note); // then read for the .ok message with that event's id
```

- **Verify what relays send.** A relay can send anything; check the signature before trusting an event.
- **Always read with a deadline** (`receiveTimeout`). `receive` waits forever.
- **`dial` takes no deadline.** To bound it, run it with `io.concurrent` and cancel it at the deadline; a cancelled dial stops and frees what it allocated. The name lookup is the one step a cancel cannot interrupt.
- A message the parser cannot read is skipped and counted (`relay.unreadable()`), and the connection carries on.

## The local store

```zig
var store = try nostr.store.Store.open("/path/to/events.mdb", .{});
defer store.deinit();
_ = try store.ingest(allocator, note, .{ .verify_with = signer }); // .added, .replaced, .duplicate, .stale, ...
var found = try store.query(allocator, .{ .kinds = &.{1}, .authors = &.{me.public_key}, .limit = 50 });
defer found.deinit(); // found.events is newest first
```

`ingest` handles replaceable and parameterized-replaceable events, NIP-09 deletions and ephemeral kinds. For many events at once, `ingestBatch` does the same in one transaction, which matters because every commit syncs to disk. Queries walk indexes newest-first and stop at `limit`, so a 500-note feed query takes about 0.28 ms at 100,000 stored events.

## Traps

- A nostr id is the SHA-256 of the canonical serialization; do not build it with a general JSON encoder. `event.create` and `event.computeId` do it right.
- On macOS, a `std.testing.allocator` passed to anything you cancel (a dial, a reader task) can swallow the cancel and hang the test. Use `std.heap.DebugAllocator(.{ .stack_trace_frames = 0 })` there.
- A task that catches a cancel and then does more blocking I/O can no longer be interrupted. After an error that might be a cancel, return.

## More

- Source and releases: https://github.com/zig-nostr/nostr
- Docs, NIP support table, benchmarks: https://zignostr.com
- `deed`, a command line built on this library: https://github.com/zig-nostr/deed
