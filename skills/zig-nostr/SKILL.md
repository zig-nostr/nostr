---
name: zig-nostr
description: Build nostr software in Zig with zig-nostr's `nostr` library. Use when a Zig project needs nostr keys and BIP-340 signatures, NIP-01 events (create, sign, verify, serialize), NIP-19 codes, NIP-44 encryption, NIP-50 search filters, NIP-46 remote signing as a signer or as a client, NIP-17 private messages and NIP-59 gift wrap, NIP-04, NIP-13 proof of work, NIP-77 negentropy sync, NIP-45 COUNT, NIP-05/NIP-11/NIP-98/NIP-86/Blossom HTTP codecs, writing a relay, relay connections (dial, subscribe, publish, read with a deadline), the NIP-65 outbox model, or a local-first LMDB event store with fast queries. Also use when adding the library to build.zig.zon, or when porting Zig nostr code to Zig 0.16's std.Io.
---

# zig-nostr: the nostr library for Zig

`nostr` is a nostr protocol library for Zig 0.16: keys and BIP-340 Schnorr signatures (libsecp256k1, full official test vectors), NIP-01 events, NIP-19, NIP-44, NIP-46 as client and server, NIP-42, NIP-49, NIP-06, NIP-59 and NIP-17 private messages, NIP-04, NIP-13, NIP-77 negentropy, NIP-45, relay transport with deadlines, NIP-65, codecs for NIP-05, NIP-11, NIP-98, NIP-86 and Blossom, and a memory-mapped LMDB event store. libsecp256k1 and LMDB are compiled from source, so no system packages are needed. It builds for macOS, Linux and Windows. Pre-1.0: APIs can still change between minor versions.

## Add it

```sh
zig fetch --save https://github.com/zig-nostr/nostr/archive/refs/tags/v0.16.0.tar.gz
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

Every snippet here was compiled and run against v0.16.0.

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

`nip19` also has `encodeNsec`, `encodeNote`, `encodeNprofile`, `encodeNevent`, `encodeNaddr` and their `decode*` twins. Decoders read an all-lowercase or all-uppercase code (a QR code usually carries the uppercase form) and refuse a mixed-case one with `error.MixedCase`. `nip19.fromNostrUri` strips a `nostr:` scheme in any case and returns the code after it.

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
- A relay that answers the upgrade with anything but 101 (503 when busy, 401 or 403, 429) fails `dial` with `HandshakeFailed`. `nostr.relay.dialDiagnosed(allocator, io, url, &diagnostic)` is `dial` that also fills `diagnostic.status` (a `relay.DialDiagnostic`) with the status the relay answered, or 0 if it never got that far.
- To reach a relay through a proxy or tunnel, connect the TCP stream yourself (to the relay's host and port, through the HTTP CONNECT or SOCKS5 exchange) and hand it to `dialOver`. It does the TLS handshake for `wss://` with the URL's host, then the upgrade, and owns the stream from then on: it closes it on every error, and `deinit` closes it after a success. `dialOverDiagnosed` reports the status like `dialDiagnosed`. Bound it the same way as `dial`.

```zig
// `tcp` is a std.Io.net.Stream already connected through the proxy to relay.example:443.
const relay = try nostr.relay.dialOver(allocator, io, "wss://relay.example", tcp);
defer relay.deinit(); // closes tcp too
```
- `Filter.search` is NIP-50 full-text search, sent to the relay as `"search"`. The relay does the matching, so `Filter.matches` ignores it.

## The local store

```zig
var store = try nostr.store.Store.open("/path/to/events.mdb", .{});
defer store.deinit();
_ = try store.ingest(allocator, note, .{ .verify_with = signer }); // .added, .replaced, .duplicate, .stale, ...
var found = try store.query(allocator, .{ .kinds = &.{1}, .authors = &.{me.public_key}, .limit = 50 });
defer found.deinit(); // found.events is newest first
```

`ingest` handles replaceable and parameterized-replaceable events, NIP-09 deletions and ephemeral kinds. For many events at once, `ingestBatch` does the same in one transaction, which matters because every commit syncs to disk. Queries walk indexes newest-first and stop at `limit`, so a 500-note feed query takes about 0.28 ms at 100,000 stored events. `Store.query` applies `Filter.search` as a substring of the content, ignoring ASCII case; no index serves it, so name the kinds you mean. On Windows a store takes its full map size on disk (1 GiB by default) from the first open.

## Private messages (NIP-17, NIP-59)

```zig
// Send: one gift wrap per recipient, plus one to yourself.
var dm = try nostr.nip59.privateDirectMessage(allocator, io, signer, me, &.{their_pubkey}, "hi", null, null);
defer dm.deinit();
for (dm.wraps) |w| {
    _ = w; // publish w to the inbox relays of the pubkey in its p tag
}

// Receive: a kind 1059 event addressed to you.
var opened = try nostr.nip59.unwrap(allocator, signer, my_secret_key, wrap_event);
defer opened.deinit();
// opened.rumor.content, opened.rumor.kind, opened.sender
```

`unwrap` checks the wrap, the seal and that the rumor's author is the seal's signer, and returns an error otherwise. `nip59.seal` and `nip59.wrap` are the single layers if you build a rumor yourself with `nip59.Rumor.init`. `nostr.nip04.encrypt` and `decrypt` take the same arguments as the `nip44` functions of those names for the legacy kind 4 messages; NIP-04 has no authentication, so a successful decrypt proves nothing about the sender.

## Remote signer client (NIP-46)

```zig
const Client = nostr.nip46_client.Client(*nostr.relay.Relay);
const client = try Client.initBunker(allocator, io, signer, "bunker://...", .{});
defer client.deinit();
// For each relay in the token: dial it, then client.attach(relay) and
// run client.run(relay, url) in its own task (io.concurrent): one reader per relay.
try client.connect();
const user = try client.getPublicKey();
var signed = try client.signEvent(.{ .kind = 1, .content = "hello", .created_at = now });
defer signed.deinit(); // the signature and author are already checked
```

For a `nostrconnect://` flow use `initNostrConnect(allocator, io, signer, relays, options)`, show the user `client.nostrConnectUri(allocator, .{ .name = "my app" })`, then `client.awaitNostrConnect()`. Every request has a deadline (`Options.timeout_ms`) and ends with `error.Canceled` if its task is cancelled.

## Negentropy sync (NIP-77)

```zig
var mine = try nostr.nip77.Storage.fromSlice(allocator, items); // items: []const nostr.nip77.Item, each .{ .created_at, .id }
defer mine.deinit(allocator);
var neg = try nostr.nip77.Initiator.init(&mine, .{});
const first = try neg.initiate(allocator);              // bytes
const hex = try nostr.nip77.toHex(allocator, first);     // the NEG-OPEN payload
// send NEG-OPEN, read the relay's NEG-MSG hex, nostr.nip77.fromHex it, then:
var r = try neg.reconcile(allocator, reply_bytes);
defer r.deinit(allocator);
// r.have: ids you hold and the relay lacks, r.need: the reverse, r.message: next round or null
```

`Storage.fromStore` builds the item set straight from a `Store` for a filter. Set `Options.frame_size_limit` on a side that talks to untrusted peers. On a connection, `Relay.negOpen`, `negMsg` and `negClose` send the envelopes, and the relay's replies arrive as `.neg_msg` and `.neg_err` relay messages. `Relay.count(sub_id, filters)` sends a NIP-45 COUNT and the answer arrives as `.count`.

## Proof of work (NIP-13)

```zig
var mined = try nostr.nip13.mine(allocator, io, .{ .pubkey = me.public_key, .created_at = now, .kind = 1, .content = "hello" }, .{ .target = 20, .threads = 4, .timeout_ms = 30_000 });
defer mined.deinit();
mined.event.sig = try signer.signId(mined.event.id, me, null); // mine returns the event unsigned
```

`nip13.difficulty(id)` counts leading zero bits and `committedTarget(ev)` reads the target an event claims. Check both when you require a difficulty from others, because a nonce tag alone proves nothing.

## HTTP codecs

None of these make a request. You fetch, they parse or build.

```zig
// NIP-05
const id = try nostr.nip05.parseIdentifier("bob@example.com");
const url = try nostr.nip05.wellKnownUrl(allocator, &id);
var who = try nostr.nip05.parseResponse(allocator, body, id.name()); // who.pubkey, who.relays
defer who.deinit();

// NIP-11: GET httpUrl(relay_url) with nip11.accept_header_name/value
var info = try nostr.nip11.parse(allocator, body); // info.name, info.supported_nips, info.limitation
defer info.deinit();

// NIP-98: sign a request, or check one on a server
const header = try nostr.nip98.authHeader(allocator, signer, me, now, url, "POST", body, null);
const author = try nostr.nip98.verifyHeader(allocator, signer, header_value, .{ .url = url, .method = "POST", .body = body, .now = now });

// Blossom: a kind 24242 token, and the descriptor a server answers with
const token = try nostr.blossom.buildAuthHeader(allocator, signer, me, now, .{ .action = .upload, .expiration = now + 300, .hashes = &.{blob_sha256} }, null);
var desc = try nostr.blossom.parseDescriptor(allocator, body); // desc.value.url, .sha256, .size
defer desc.deinit();
```

`nip86` is the relay management API: `encodeRequest(allocator, .{ .banpubkey = .{ .value = pubkey_hex } })` writes the JSON body, `authHeader(allocator, signer, me, now, url, body, null)` signs it with NIP-98, and `parseResponse(allocator, body)` reads `result` and `err`.

## Writing a relay

The library has no listener, but the pieces a relay is made of are here. Parse what a client sends, verify, store and answer:

```zig
var msg = try nostr.message.parseClientMessage(allocator, text);
defer msg.deinit();
switch (msg.value) {
    .event => |ev| {
        const ok = try nostr.event.verify(allocator, signer, ev);
        // store.ingest(...), then:
        const reply = try nostr.message.encodeOk(allocator, ev.id, ok, "");
        _ = reply;
    },
    .req => |r| {
        _ = r; // store.query for each r.filters entry, encodeEventMsg per event, then encodeEose
    },
    .count => |c| {
        _ = c; // encodeCountReply(allocator, c.subscription_id, n, null)
    },
    .neg_open => |n| {
        _ = n; // Storage.fromStore, Responder.reconcile, encodeNegMsg
    },
    else => {},
}
```

Set a frame size limit on the negentropy `Responder` when serving the public. `Store.remove(gpa, id)` and `removeMatching(gpa, filter)` delete events.

## Traps

- A nostr id is the SHA-256 of the canonical serialization; do not build it with a general JSON encoder. `event.create` and `event.computeId` do it right.
- On macOS, a `std.testing.allocator` passed to anything you cancel (a dial, a reader task) can swallow the cancel and hang the test. Use `std.heap.DebugAllocator(.{ .stack_trace_frames = 0 })` there.
- A task that catches a cancel and then does more blocking I/O can no longer be interrupted. After an error that might be a cancel, return.

## More

- Source and releases: https://github.com/zig-nostr/nostr
- Docs, NIP support table, benchmarks: https://zignostr.com
- `deed`, a command line built on this library: https://github.com/zig-nostr/deed
