# Architecture

How `nostr` is put together, and where to look first. For how to use it from another project, read the [README](README.md) and [`skills/zig-nostr/SKILL.md`](skills/zig-nostr/SKILL.md). For how to change it, read [`AGENTS.md`](AGENTS.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## What it is

A Nostr protocol library for Zig 0.16. It holds the parts every Nostr program needs: keys and signatures, events, the relay wire protocol, a relay connection, encrypted payloads, remote signing, and a local event store. It has no application in it. Other programs import it as the module `nostr` (`src/root.zig`), and only what `root.zig` re-exports is public.

Three things are compiled from source rather than written here: libsecp256k1 for BIP-340 signatures and ECDH, LMDB for the store, and the Normalize module from `zg` for NIP-49 passphrases. `build.zig` builds them and `build.zig.zon` pins them by commit. The WebSocket framing is written here, because the connection needs to decide when a frame becomes visible.

The library starts no threads and reads no clock or random source of its own. Anything that waits, sleeps or needs randomness takes a `std.Io`, which the caller makes (usually `std.Io.Threaded`).

## Modules

All under `src/`, one file each.

Keys and encodings

- `keys.zig`: secp256k1 keys, BIP-340 signing and verification, ECDH, over libsecp256k1.
- `hex.zig`, `bech32.zig`: the byte codecs.
- `nip19.zig`: npub, nsec, note, nprofile, nevent, naddr, nrelay, and `nostr:` URIs.
- `bip39.zig`, `nip06.zig`: mnemonics, and key derivation from one.
- `nip49.zig`: `ncryptsec` private key encryption (scrypt and XChaCha20-Poly1305).
- `nip44.zig`: NIP-44 v2 authenticated encryption.

Events and messages

- `event.zig`: the NIP-01 event, canonical serialization, id, signing, verification, and JSON in and out.
- `filter.zig`: subscription filters, their JSON, and local matching.
- `message.zig`: the messages a client sends and the ones a relay sends back.
- `json.zig`: the string escaper the encoders share.
- `nip42.zig`: the client's authentication event for a relay that asks.

Transport

- `websocket.zig`: RFC 6455 handshake and frame codec. No I/O.
- `relay.zig`: a relay connection. `Connection` is the protocol state machine, generic over a byte stream. `IoStream`, `dial` and `Relay` bind it to a TCP or TLS socket.
- `liveness.zig`: the policy for when a quiet connection should be pinged or given up on. Pure functions over two measurements.
- `nip65.zig`: relay lists, and the read and write routing of the outbox model.

Storage

- `store.zig`: the LMDB event store: record format, indexes, replaceable and deleted events, and the filter-driven query planner.

Remote signing

- `nip46.zig`: requests, responses, the kind 24133 envelope, `bunker://` and `nostrconnect://` URIs, and `Bunker`, which answers requests under an approval `Policy`.
- `signer.zig`: the loop that serves those requests over a relay connection.
- `keystore.zig`: the `ncryptsec` key file at rest.
- `signer_ipc.zig`: the bodies a key-holding daemon and its clients exchange over a local socket.

Not part of the library: `bench.zig` (store benchmark) and `fuzz.zig` (fuzz targets, test only).

## How data flows

Outbound, a program makes a `keys.Signer`, loads or generates a key pair, and calls `event.create`, which serializes the fields canonically, hashes them to the id and signs the id. `message.encodeEvent` and `message.encodeReq` turn events and filters into JSON text, `Connection` wraps each text in a masked WebSocket frame, and `IoStream` writes the frame to the socket, through TLS for `wss://`.

Inbound, bytes come off the socket into `Connection`'s receive buffer. `websocket.decodeFrame` takes whole frames from the front, answers pings, drops pongs, and reassembles fragments into one message. `message.parseRelayMessage` parses that text into an `EVENT`, `OK`, `EOSE`, `CLOSED`, `NOTICE` or `AUTH`, using `event.fromValueLeaky` for the event. Text that does not parse is counted in `unreadable` and skipped, so one bad message costs that message only.

Parsing does not verify. A caller decides where to verify, and `Store.ingest` can do it (`IngestOptions.verify_with`) before an event is stored. Ingest also applies the replaceable and deletion rules. Reads go the other way: `Store.query` takes the same `Filter` that was sent to the relay, picks the most selective index, walks it newest first and stops at `limit`, so a read costs the size of the page and not the size of the store.

Which relays to ask comes from `nip65`: parse a user's kind 10002 event, then `readRoutes` or `writeRoutes` group many users by relay, so one subscription per relay covers everyone routed there.

Remote signing sits beside this path. `signer.serve` subscribes for kind 24133 events addressed to the signer, `nip46.open` decrypts each one with NIP-44, `Bunker.handle` answers it under the policy, and `nip46.seal` encrypts and signs the reply, which goes back out through the same connection.

Parsed values that own memory (events from `fromJson`, relay messages, query results, URIs) carry their own arena and a `deinit`. One `deinit` frees everything the value borrows from.

## Threads and cancellation

The library leaves threading to the caller. These are the rules it is built around.

One thread reads each relay. `receive` and `receiveTimeout` are for that thread only, and the buffers and the `unreadable` counter behind them are not synchronized.

Other threads may write. `publish`, `subscribe`, `ping` and the rest go through a write lock that covers building the frame and flushing it all the way to the socket, because half a TLS record from one thread and half from another cannot be decrypted again.

A watcher can look at a connection without touching the reader. `idleMs` reads an atomic timestamp that every inbound byte updates. `liveness.action` turns that and the time since the last ping into leave it, ping, or give up. The watcher thread, the table of connections and what giving up means stay with the program.

Giving up is `Relay.shutdown`, which half-closes the socket so a blocked `receive` returns. It is not `deinit`: the reader still owns the `Relay` and unwinds through its own error path. A socket receive timeout is not used, because `std.Io` treats the resulting EAGAIN as a bug.

A reader that wants to come up for air without being torn down uses `receiveTimeout`. The `std.Io.Timeout` is turned into an absolute deadline once, and the wait is a readiness check that reads nothing, so when it returns `error.Timeout` the socket, the buffers and any TLS record state are exactly as they were and the call can be repeated. `Timeout` is a different value from `null`, which means the relay is gone. When a deadline is set, a pong is skipped if another write holds the lock or the socket has no room, so a peer that stopped reading cannot wedge the connection.

`dial` has no deadline of its own. To bound it, start it with `io.concurrent` and cancel it: a cancelled dial stops where it is and frees what it allocated. On POSIX the name lookup is a libc call and cannot be interrupted. On Windows the lookup goes through std and can.

Shared signer state is small and locked. `SeenRequests` (replay defence) and the authorized-clients record are shared across the reader threads of every relay a signer serves, behind short spin locks.

The store relies on LMDB for concurrency: many read transactions beside one write transaction. Each `Store` method opens and finishes its own transaction, and results are copied into an arena the caller frees.

## Platforms

macOS, Linux and Windows. On POSIX the dialer resolves names with `getaddrinfo` and waits for write room with `poll`. On Windows it resolves with std's resolver and waits with `WSAPoll`, and a key file takes its directory's default access list because there are no mode bits. `zig build` only compiles what the benchmark uses, so a cross-compile check has to build the tests: `zig build test -Dtarget=x86_64-windows-gnu` compiles every file for Windows, and a non-Windows host then cannot run the result.

## Where to start reading

1. `src/root.zig`, for what is public.
2. `src/event.zig` and `src/keys.zig`, the smallest complete path: make an event, sign it, verify it.
3. `src/message.zig` and `src/filter.zig`, then `src/relay.zig`: `Connection` first, then `IoStream`, `dial` and `Relay`.
4. `src/store.zig`: the doc comment at the top, then `ingestBatch` and `query`.
5. `src/nip46.zig`, then `src/signer.zig`, if you are interested in signing.

## How it is tested

`zig build test` runs everything. Tests sit beside the code in `test` blocks, and `root.zig` pulls every file in.

- Official vectors for the cryptography: the BIP-340 suite in `keys.zig`, the NIP-44 v2 vectors in `src/data/nip44_vectors.json`, and the NIP-19, NIP-49 and RFC 6455 worked examples.
- A scripted server for the transport. `Connection` is generic over its stream, so most relay tests drive it with an in-memory fake that plays a relay: handshake, fragments, pings, closes, auth. A few use a real socket on loopback to check the parts a fake cannot, such as a deadline on a quiet socket and cancelling a dial. A dial against a public relay is not part of the suite.
- A real LMDB file in a temporary directory for the store. `zig build bench` measures ingest and query latency.
- Fuzz targets in `src/fuzz.zig` for everything that parses bytes someone else wrote: WebSocket frames and handshake responses, relay messages, events, bech32 and NIP-19, NIP-44 payloads, NIP-46 messages and URIs, relay lists and URLs, mnemonics, `ncryptsec` files, filters. Each asserts that nothing crashes or leaks and, where one exists, an invariant: an event parsed, serialized and parsed again is the same event, a decoded frame lies inside its buffer, a bunker URI survives being rebuilt from its parts. Some build the outer layer themselves (a valid relay envelope, a valid bech32 checksum) so the fuzzed bytes reach the code behind it.

  In a plain `zig build test` each target runs once per entry of its seed corpus and once on empty input. `zig build test --fuzz -Doptimize=ReleaseSafe` fuzzes them until stopped. With Zig 0.16.0 the Debug build of the test runner does not compile in fuzz mode, and ReleaseSafe keeps the integer and bounds checks the fuzzer needs. A corpus entry has to be written in the encoding the fuzzer's `Smith` reads, which the `seed` helper in `fuzz.zig` does. A crash the fuzzer finds gets a regression test next to the code it was in, and the input goes in the corpus.
- `zig fmt --check .` for formatting. CI runs build, test and the format check on Linux and macOS, and build and test on Windows.
