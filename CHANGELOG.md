# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: breaking changes bump the minor version, features/fixes bump the patch version).

## [Unreleased]

## [0.14.1] - 2026-09-07

### Fixed

- `relay.Relay.deinit` frees the `Relay` itself. It freed the transport, the
  buffers and the connection and then left the struct `dial` allocated behind,
  so every dial leaked it. No caller could have covered for that: `dial` hands
  back a pointer and its own documentation says to free it with `deinit`, so
  nobody was destroying it separately, and neither app built on this library
  did. A client that reconnects on a dropped socket leaked one per reconnect,
  for the life of the process.

  Found by driving `receiveTimeout` against a live `wss://` relay under a
  leak-checking allocator, which is also the only way to see it: it takes a real
  dial, and a real dial takes a socket.

## [0.14.0] - 2026-09-07

### Added

- `relay.Relay.receiveTimeout` (and `Connection.receiveTimeout`): read the next
  relay message, or give up when a deadline passes.

  A reader blocked in `receive` cannot notice that anything changed behind it.
  Plaza's ingest threads check pause, the slot's URL and the follow generation
  at the top of their loop, and the loop only advances when the relay says
  something, so a relay the reader repointed or removed kept its socket and kept
  feeding the store until it happened to speak. The only lever over that thread
  was `shutdown`, which is a teardown: over TLS it leaves the session poisoned,
  so it cannot pause one subscription on a socket still serving others.

  A deadline that fires returns `error.Timeout`, never `null`, because `null`
  already means the relay is gone and every existing caller reads it that way.
  It consumes nothing, so calling again resumes on the same connection rather
  than resynchronising: the wait is a `MSG_PEEK` readiness check, not a read, so
  a frame half-arrived and a TLS record half-decrypted are both exactly as they
  were. A test drives a real socket pair, times a deadline out on a quiet
  connection, and then reads a message sent after it off the same socket.

  It is deliberately not `SO_RCVTIMEO`. That makes the read return `EAGAIN`, and
  this io model treats `EAGAIN` as a programmer bug and panics in Debug. It was
  tried once in a daemon built on this library: it compiled, passed every test,
  and panicked on the first wedged connection, turning a stall into a crash.

- `liveness`: when a relay connection has gone quiet, and what to do about it.
  `action(idle_ms, since_ping_ms)` returns `.leave_it`, `.ping` or `.give_up`,
  with the three intervals it enforces. Pure, so the policy is asserted without
  a socket, a thread or a clock.

  The numbers were already load-bearing in two products and written down in
  neither. They come from Amethyst's survey of 122 relays: idle timeouts cluster
  around 60, 120, 240, 300 and 600 seconds, and a ping only holds a connection
  open when its interval is at most about half the shortest tier. Ninety seconds
  is three missed answers. The table of connections and the thread that ticks
  stay with the product, because what "give up" means differs between a client
  and a signer.

### Changed

- **Breaking**, for anyone implementing the `Stream` a `Connection` is generic
  over: `read` takes a deadline. It was `fn read(self, buffer: []u8) !usize` and
  is now `fn read(self, buffer: []u8, deadline: ?std.Io.Clock.Timestamp)
  !usize`. A null deadline waits forever, which is what every caller did before,
  so an existing stream adapts by accepting and ignoring the argument. Users of
  `relay.dial` and `relay.Relay` are unaffected.

## [0.13.1] - 2026-09-07

### Changed

- Dependencies are fetched as HTTPS tarballs rather than over the git protocol.
  Zig's git client gives up under load with `unable to discover remote git
  server capabilities: ProtocolError`, which in one afternoon failed three CI
  jobs across two runner architectures in the apps built on this library and
  killed a release build outright, leaving a tag with no release behind it.

  Nothing about the dependencies changed. Every commit is the same one, pinned
  by full SHA, and every content hash is identical: `zig fetch` returns the same
  hash for the tarball and for the git checkout of all three. That identity is
  the proof this changes how the bytes arrive and not which bytes arrive.

## [0.13.0] - 2026-08-28

### Removed

- `signer_ipc.header_client`, `clientId`, `clientNameOk`, `client_name_max` and
  `reason_unnamed`. **Breaking**, and the reason is worth more than the API.

  They existed so a keyholder serving several local apps could tell them apart.
  A name in a header is a name the CALLER chose, and NIP-46 had already settled
  that question for its own case in the same words: client metadata is
  "client-supplied and unauthenticated", a display hint, and a signer "MUST NOT
  use it for authorization decisions". A self-declared name buys separable
  grants and an honest prompt; it never buys authorization.

  What settled it here is that the shape it was serving was wrong. A keyholder
  that any local app can reach has to answer "which app is this", and on the
  desktop nobody has. File permissions separate users, not apps. macOS Keychain
  access control and Touch ID both need a real code-signing identity. The Secure
  Enclave cannot hold a secp256k1 key at all. So the protocol stops pretending
  to carry an identity it cannot check.

  Who may reach a keyholder is now each product's own business, which is where
  it belongs: a credential, a pipe inherited from a parent, an operating system
  that names its callers. This module goes back to owning only what the bytes
  mean.

### Fixed

- `version` said `0.12.0` while the package said `0.12.2`. It is kept in step by
  hand and had drifted three releases, so anything that read it was told the
  wrong number.


## [0.12.2] - 2026-08-28

### Added

- `signer_ipc.header_client`, `clientId`, `clientNameOk`: a request that uses
  the key now names the app making it.

  Without a name, every app on a machine is one client to a keyholder, because
  they all present the same local credential. That makes a whole class of
  answer inexpressible: "the messenger may read my messages, my feed reader may
  not" cannot be said when there is only one client to say it about, and
  withdrawing permission from one app withdraws it from all of them.

  The name is filed under a domain-separated hash, so it drops straight into a
  permission store keyed by a nostr pubkey and cannot collide with one. An app
  that names itself with some relay client's hex must not inherit what that
  pubkey was allowed over a relay.

  It is self-declared, and the documentation says so rather than papering over
  it. Any process running as the same user can read the local credential, so
  any of them can claim any name. What it buys is the ability to answer
  separately, not proof of who is asking, and a keyholder that shows the name
  to a person has to phrase it that way: "an app calling itself Plaza" is the
  true sentence and is just as usable as the false one.

  Names are bounded and printable-ASCII only. The string goes on the row where
  somebody decides whether to allow a signature, and a name free to carry
  control characters can blank the line, redraw a terminal, or pad itself until
  the part a reader would recognise has scrolled off.

- `signer_ipc.reason_awaiting_approval`, `reason_refused`, `reason_locked`,
  `reason_unnamed`: the `Failure` strings a client has to tell apart to know
  what to do next, as constants rather than prose. They are matched by a
  program, which would break the first time one was reworded.


## [0.12.1] - 2026-08-28

### Added

- `signer_ipc.state_locked`: the state a keyholder is in when it holds a key it
  cannot use yet.

  The protocol could spell two states, no key and signing. A daemon that
  encrypts its key at rest has a third, and it is the one such a daemon reports
  every time it starts, before anybody has typed the passphrase. Without a word
  for it the daemon has to pick a lie, and the cheap-looking lie is the
  expensive one: reporting `state_uninitialized` while locked tells a client
  there is no key here, and a client that believes that offers to make one over
  the top of an identity somebody already has. A nostr key cannot be replaced.

  Additive, and safe for clients built against the two-state version: the rule
  written beside the constants is that an unrecognised state means "cannot
  sign", never "no key yet", which is what those clients already do by checking
  for `state_ready` rather than against `state_uninitialized`.

  A locked daemon still reports its pubkey. Whose key it is was never the
  secret, and a client that knows it can name the account it is asking to
  unlock instead of showing a passphrase box for nobody in particular.

## [0.12.0] - 2026-08-16

### Added

- `nip46.Permissions`, `nip46.Permission` and `nip46.Remember`: what each
  connected client has been allowed or refused, and for how long.

  It sits beside `AuthorizedClients` because connecting and being allowed to act
  are different questions and the library owns both. It is here rather than in a
  signer because both signers need exactly this, and a second copy of a security
  decision is a copy that drifts.

  Keyed the way Amber keys it, `(client, method, event kind)`, with a duration on
  every answer: once, an hour, a day, always. Per kind because signing a note and
  signing a contact list are different risks; a bad kind:3 write empties
  somebody's follow list, and "you allowed signing once" must not cover that.

  Two rules that are easy to get backwards, which is most of why this is one
  implementation and not two:

  - A LAPSED answer leaves the question open rather than becoming a denial. An
    hour running out means ask again, not that the answer turned into no.
  - `once` is not written down at all. The answer covered that request, and the
    next one is a fresh question.

  `forget` drops one client's answers, which is what revoking has to do:
  otherwise a client that reconnects acts on permissions granted to the session
  that was ended. `clear` drops all of them, for signing out.

## [0.11.0] - 2026-08-15

### Added

- `nip46.acceptNostrConnect`, which builds the event that answers a
  `nostrconnect://` invitation: the client-initiated half of NIP-46, where the
  client advertises itself and waits to be adopted rather than the user pasting
  a bunker token.

  The part that is not guessable from the flow, and that implementations get
  right only by being told: the URI's `secret` is NOT the connect method's
  secret, and the reply carries it as the RESULT, in place of `"ack"`. It is how
  the client knows the signer that answered is the one it invited. nsec.app says
  so in a comment where it fabricates the request; nostr-tools' client is the
  other half, adopting the first kind:24133 addressed to it whose decrypted
  `result` equals the secret it published, and taking that event's author as its
  signer. A reply of `"ack"` is ignored and the connection simply never
  completes, with nothing to see on either side.

  Authorizing the client is the caller's, deliberately: this builds an event and
  does not decide whether it is published.

## [0.10.0] - 2026-08-15

Both entries here are the same bug in two places, and neither is reachable by a
signer serving a single relay. Together they are what a signer needs before it
can listen on more than one.

A bunker URL names every relay the signer listens on, and a client publishes its
request to all of them: NDK builds a relay set from the whole URI and publishes
to the set. So one intent arrives as the same event id on every relay thread,
and which relay gets there first is nobody's choice.

### Fixed

- `signer.serve` kept its own record of the requests it had answered, so a
  signer on several relays kept one record per relay and each thread answered
  its own copy of the same request: two approval prompts for one question, and
  two signatures published for one intent. The record is now the caller's and
  shared across relays, and its lock covers the check and the record together,
  because a lock around only the write lets two threads both be told an id is
  new.
- The clients that had completed `connect` were held per `Bunker`, and a signer
  on several relays runs a thread per relay with its own bunker (each needs its
  own secp256k1 context). A client that connected over one relay and whose next
  request arrived on another was told "not connected". Fixing only the record
  above made that deterministic rather than intermittent.

### Added

- `nip46.AuthorizedClients`, the connect state as a thing of its own that
  several bunkers share, with `clear` for ending every session at once. That is
  what signing out of a signer has to do: a client still holding an
  authorization granted against a key that is no longer loaded is a session that
  outlived its account.

### Changed

- **Breaking.** `signer.serve` takes a `*signer.SeenRequests` as its last
  argument, and `nip46.Bunker.initSingleKey` takes a `*nip46.AuthorizedClients`.
  Create one of each and pass the same ones to every relay. A signer on a single
  relay behaves exactly as before.

## [0.9.0] - 2026-08-12

### Security

- `bip39.mnemonicToSeed` wrote a passphrase longer than 256 bytes past the end
  of a 264-byte stack array. The bound was a `std.debug.assert`, which states an
  invariant the caller is trusted to uphold and is compiled out of ReleaseFast
  along with the slice bounds check behind it. A passphrase is input, not an
  invariant. Measured on a ReleaseFast build: 300 bytes returned a seed and
  corrupted 44 bytes of stack silently, and 4096 bytes ended the process with
  SIGBUS. It now returns `error.PassphraseTooLong` rather than truncating,
  because a truncated passphrase derives a different key without saying so.
- `signer.worthAnswering` computed a NIP-46 request's age with a plain
  subtraction on a `created_at` chosen by the sender. A request stamped
  `minInt(i64)` made the difference wider than an `i64`, which wrapped to a
  negative age, which is not greater than the limit, so the staleness check
  accepted the one timestamp most obviously worth refusing. Now saturating.

### Added

- `src/fuzz.zig`: eight fuzz targets over the input the library does not get to
  assume anything about. A websocket frame, a relay message, a relay message
  inside a plausible envelope, an event and the id computation and filter
  matching that read one, a NIP-44 payload, a bech32 string, fixed-width hex,
  and a signature check over arbitrary bytes. They are ordinary tests, so
  `zig build test` runs them against their corpora with no new job or tool;
  `zig build test --fuzz` runs them as a fuzzing loop.

### Changed

- **Breaking.** `bip39.mnemonicToSeed` returns `SeedError![64]u8` rather than
  `[64]u8`, and `nip06.keyFromMnemonic` widens its error set by that one error.
  `bip39.max_passphrase_len` is public.

## [0.8.0] - 2026-08-11

### Added

- A relay connection can be kept alive, and can be told it is dead.
  `Relay.ping` sends a websocket ping, `Relay.idleMs` reports how long it has
  been since the last inbound byte (pongs included, because a pong is the
  evidence and it is not a message), and `Relay.shutdown` half-closes the
  socket so a `receive` blocked on another thread returns.

  Answering the relay's pings is not a substitute for sending our own: a
  relay's idle timer counts what it RECEIVES, so a pong sent in reply to its
  ping does not reset it. Amethyst measured that against a live relay.

  `shutdown` and not a socket receive timeout, deliberately. `SO_RCVTIMEO`
  makes the read return EAGAIN, and this io model treats EAGAIN as a
  programmer bug and panics, so a stalled relay would become a crash. That was
  tried in the signer and it passed every test before failing on the first
  real wedged connection.

### Changed

- Writes on a connection are serialized. A connection that is being kept alive
  has two users on two threads, and over TLS half a record from each is not an
  interleaved message, it is a session that cannot be decrypted again. The lock
  covers building a frame and flushing it to the socket; uncontended it is one
  atomic compare-exchange.

## [0.7.0] - 2026-08-11

### Changed

- A query no longer re-checks the constraints the index it chose has already
  enforced. Reaching an event through its author's index proves the author
  matches; reading it because its id was named proves the id does.
  `Filter.matches` compares against a list one entry at a time, so those checks
  were a scan of the whole list, per candidate: a feed over a two-thousand-name
  follow list re-scanned every name for every note it returned, and a client
  refreshing a feed by naming the ids it already holds paid it squared. Time
  bounds are still checked, because they cost nothing and they are a check on
  the index agreeing with the record it points at.

### Added

- `QueryResult.list_checks`: candidates read, times the combined length of the
  id and author lists still to be checked against each one. Zero for every
  filter an index can answer, the way `examined` is one for every filter served
  from an index that suits it. A stopwatch cannot tell a quadratic scan from a
  busy machine; this can.
- The benchmark measures the feed shape at the size a follow list actually is.
  `BENCH_AUTHORS` sizes the store's author spread and the wide feed's follow
  set together, `BENCH_FEED_LIMIT` sets how far the reader has scrolled, and
  `BENCH_IDS` sizes the by-id shape. The three original shapes and their
  defaults are unchanged, so their numbers stay comparable release to release.

## [0.6.0] - 2026-08-11

### Security

- **Behaviour change.** The signer refuses a request that is old or repeated.
  kind:24133 is public on the relay, so anyone can copy a client's sealed
  request and re-publish it; ephemeral events are not stored, so no relay
  deduplicates them, and the signer kept no record of what it had answered.
  Requests must now be within `signer.max_request_age_s` (120s) of now, and
  each event id is answered once per connection. The old freshness control was
  the subscription's `since`, which is the relay's to enforce.
- The websocket receive buffer is bounded, not only the assembled message. The
  1 MiB cap was checked only after a frame decoded, and a frame whose payload
  has not arrived does not decode, so a peer could declare a huge payload,
  send filler, and grow the buffer until allocation failed.
- The signer's audit line prints the recognised method name rather than the
  method string from the request, which is arbitrary bytes going to a terminal
  and could carry escape sequences that forge plausible log lines.

### Added

- `websocket.max_frame_header_len`, for callers bounding a receive buffer.

## [0.5.0] - 2026-08-11

### Changed

- **Breaking.** A `Policy` is told which client is asking:
  `decideFn` and `Policy.decide` take the requesting client's pubkey. A policy
  that cannot see who is asking cannot tell the user either, and an approval
  prompt that names a method and an event kind but not the requester asks a
  human to authorize a signature for a stranger with no way to notice. The
  built-in `PolicyConfig` ignores the new argument; an interactive policy is
  what needs it.

## [0.4.0] - 2026-08-10

### Security

- A remote signer answers only clients that have connected. The connect secret
  was checked inside the `connect` branch and nowhere else, and nothing recorded
  who had passed it, so a client could skip `connect` entirely and send
  `sign_event` as its first message. A signer's pubkey is published in the
  `bunker://` token it hands out, in the single-key setup it is the user's own
  pubkey, and the relays are in that token too, so everything needed to reach a
  signer is public by design and the secret was doing no work. `Bunker` now
  keeps the clients that completed a connect and refuses anything key-touching
  from one it has not heard of. `connect`, `ping` and `get_public_key` stay open
  (the first is how a client becomes known, the second touches nothing, and the
  third returns a value already printed in the connection token). `logout`
  forgets the client. The secret is compared without stopping at the first
  differing byte.

### Changed

- **Breaking.** `Bunker.handle` takes the requesting client's pubkey and a
  `*Bunker`, and `signer.serve` takes a `*nip46.Bunker`, because a bunker now
  keeps the set of connected clients. The serve loop already had the client
  pubkey in hand and passes it through; callers that drive `Bunker.handle`
  themselves need to supply the pubkey of the event that carried the request.

## [0.3.8] - 2026-08-05

### Changed

- The store benchmark fills a mixed-kind store and measures a real profile
  fetch. Every event it stored was `kind:1`, so no query in it ever had anything
  of the wrong kind to read past, and the row the README called the profile
  query was one author's timeline: authors only, no kind, 500 events. A store of
  a single kind cannot show whether a filter is answered from an index that
  suits it, which is why the cost of a profile fetch went unmeasured for as long
  as it did. Each author now has a `kind:0` buried under everything they have
  posted since, the timeline row is named for what it measures, and a third row
  fetches one profile: 7.4us reading a single index entry, against 392.2us
  reading a thousand of them on the author index.

  The benchmark reports entries examined next to each latency, which is the part
  a stopwatch on a shared machine cannot report.

### Fixed

- A filter naming both authors and kinds is served by its own
  `pubkey ++ kind ++ time ++ id` index instead of the author index, so it no
  longer reads past everything those authors wrote in other kinds and rejects
  each one after decoding it. Asking a store that holds 500 of an account's
  notes for that account's `kind:0` examined 501 index entries and now examines
  1. The shape is not unusual: a profile is written once and posted over ever
  since, so the cost of reading somebody's name used to grow with how much they
  had said since they set it. Refreshing profiles across a 1024-account follow
  list measured 11,457us and now measures 302us, and scales with the length of
  the list rather than with the length of those accounts' timelines.

  A filter broad enough that pairing every author with every kind would open
  more than 4096 cursors still reads the author index, because at that width
  most of what it yields is accepted anyway.

  Existing databases are filled on open. The index is rebuilt whenever it does
  not hold one entry per stored event, rather than on a recorded one-time
  upgrade, so a database an older build has written to since is repaired too.
  This is checked on every open because getting it wrong is silent: to a query,
  an index that is not there yet and an author who has written nothing are the
  same answer, and a reader would open the app to a blank feed and an empty
  contact list with nothing to suggest the events were still on disk.

  Ingest writes one more index entry per event, which measured 5.6% fewer
  events per second (153,370/s against 144,723/s, best of three runs at 100,000
  events). The store now opens ten named sub-databases rather than nine, so an
  `OpenOptions.max_dbs` set explicitly below ten no longer opens; the default of
  16 is unaffected.

### Added

- `QueryResult.examined`: how many index entries the merge popped to produce
  the results, including the ones it read and rejected. The gap between it and
  `events.len` is a query's waste, and it is what makes "this filter is being
  answered from an index that suits it" something a test can assert. Elapsed
  time cannot tell a wasted walk from a busy machine.

## [0.3.7] - 2026-07-22

### Added

- The signer loopback protocol's wire types (`src/signer_ipc.zig`, experimental,
  pre-1.0): the request/response bodies a keyholder daemon and its clients
  exchange over local HTTP, one shape per endpoint (`/pubkey`, `/setup`,
  `/sign`, and the batched `/nip44/encrypt` + `/nip44/decrypt`), plus the
  shared failure body. Living in the library means every product speaks the
  identical protocol without sharing a server; transport, ports, and
  authentication stay product concerns. Deferred from 0.3.6 until an HTTP
  signer consumed them; the Plaza helper now does.

## [0.3.6] - 2026-07-21

### Added

- Signer support (experimental, pre-1.0), so a NIP-46 signer is a thin shell
  over the library rather than a fork of it: a `keystore` module for the
  encrypted key at rest (NIP-49 `ncryptsec` plus a `0600` key file), a `signer`
  module with the transport serve loop that answers kind:24133 requests over any
  relay connection (with NIP-42 auth), and `nip46.PolicyConfig` for
  least-privilege method and event-kind allowlists. The serve loop is proven
  hermetically against an in-memory connection. The loopback IPC wire types are
  intentionally deferred until an HTTP signer consumes them, so the library ships
  no unused surface.

### Fixed

- NIP-49 now Unicode-NFKC-normalizes the password before the scrypt KDF, as the
  spec requires (`src/nip49.zig`). Previously non-ASCII passwords were passed
  through unnormalized, so this library and another NIP-49 implementation could
  derive different keys from the same password typed in a different Unicode form
  — a silent decryption failure. Normalization uses the pure-Zig `zg` Unicode
  library and keeps an allocation-free fast path for ASCII passwords (#18).

## [0.3.5] - 2026-07-12

### Added

- NIP-42 authentication of clients to relays (`src/nip42.zig`): `authEvent`
  builds and signs the `kind:22242` event (a `relay` tag and the relay's
  `challenge`) that answers a relay's `["AUTH", <challenge>]`. `message.zig`
  parses that challenge into a new `RelayMessage.auth` variant (it previously
  returned `InvalidMessage`, dropping the connection) and `encodeAuth` emits the
  client's `["AUTH", <event>]` reply; `Connection.authenticate` /
  `Relay.authenticate` send it. This lets a signer serve NIP-46 over relays that
  gate reads/writes behind authentication. Verified live against a relay
  requiring NIP-42 (`nak serve --auth`): full round-trip, valid signed event.

### Fixed

- The WebSocket opening handshake now includes a non-default port in the `Host`
  header (RFC 9110 §7.2) — `Host: relay.example.com:8443`, not just
  `Host: relay.example.com`. Relays that derive their canonical URL from `Host`
  compare it against a NIP-42 auth event's `relay` tag; omitting the port made
  them mismatch and reject the authentication. Default ports (80/443) stay
  omitted, so standard `ws://`/`wss://` relays are unaffected. Adds
  `relay.Url.hostHeader`.

## [0.3.4] - 2026-07-12

### Fixed

- The live relay connection no longer stalls request delivery over `wss://`.
  `IoStream.read` returned bytes via the generic `readVec` into the full 4 KiB
  receive buffer, which greedily keeps reading until that buffer fills — so a
  relay message that had already arrived was drained into the buffer and then
  the read *blocked on the next TLS record* to fill the remaining space,
  withholding the message until unrelated later traffic (a client retry, a
  relay ping) happened to arrive. Every NIP-46 request to a running signer
  stalled behind the following record — tens of seconds, or indefinitely. It
  now serves already-buffered bytes and otherwise does exactly one underlying
  read (`fillMore`), so each message surfaces the moment its record lands, on
  both `ws://` and `wss://`. This was the real cause of non-delivery over public
  relays like `relay.damus.io` (not NIP-42 AUTH); verified live with a full
  NIP-46 round-trip completing in ~3 s at sub-second per-request latency.
  Supersedes the #44 / #46 read iterations, which fixed the handshake but left
  this receive-path stall. (#49)

## [0.3.3] - 2026-07-12

### Fixed

- The live relay connection no longer fails the TLS websocket handshake. The
  v0.3.2 read fix returned after a single `readVec`, but a `readVec` of *zero*
  bytes means "no application data yet", not end-of-stream — a TLS record can
  carry none — so reporting it as EOF failed the handshake against real `wss://`
  relays (it was fine for plaintext `ws://`). `IoStream.read` now retries past a
  bare zero read and returns only on the first real bytes or a genuine end of
  stream. Verified live: `ws://` and `wss://` both complete the handshake and a
  full request round-trip over a local relay. (#46)

## [0.3.2] - 2026-07-12

### Fixed

- The live relay connection no longer deadlocks the websocket opening
  handshake. `IoStream.read` used `readSliceShort`, which blocks until it has
  filled the *whole* read buffer — so reading a short `101 Switching Protocols`
  response (~129 bytes) into a 4 KiB buffer waited forever for bytes the relay
  only sends after we subscribe, and `dial` never returned. It now reads once
  and returns whatever is available (`readVec`), like a POSIX `read`. This was
  why a running signer connected to relays but never received any requests.
  Adds a regression test pinning the read primitive. (#44)

## [0.3.1] - 2026-07-11

### Fixed

- `relay.dial` now resolves relay hostnames with the system resolver (libc
  `getaddrinfo`) instead of std's built-in resolver. std reads nameservers from
  `/etc/resolv.conf`, which is empty on macOS, so it fell back to a dead
  `127.0.0.1:53` and a hostname lookup hung indefinitely. The live dialer now
  connects by hostname on both macOS and Linux. (#41)

## [0.3.0] - 2026-07-11

Milestone A5 groundwork: NIP-44 v2 encryption and the NIP-46 remote-signing
("bunker") protocol layer, so a signer can hold the user's key and sign for
remote clients over a relay.

### Added

- NIP-44 v2 payload encryption (`src/nip44.zig`): ChaCha20 + HMAC-SHA256 with
  HKDF-derived message keys over a libsecp256k1 ECDH shared secret, spec
  padding, and a constant-time MAC that fails closed. Verified against the
  official NIP-44 test vectors — conversation keys, message keys, padding, and
  encrypt/decrypt round-trips. Adds `keys.Signer.sharedSecretX` (raw-x ECDH via
  a custom libsecp256k1 hash callback). (#37)
- NIP-46 remote signing (`src/nip46.zig`): the request/response messages and
  their JSON, the `kind:24133` NIP-44 envelope (`seal`/`open`), and a
  transport-agnostic `Bunker` dispatcher — `connect`, `sign_event`, `ping`,
  `get_public_key`, `nip44_encrypt`, `nip44_decrypt` — behind an injectable
  approval `Policy`, keeping the connection key separate from the user key.
  (#38)
- NIP-46 `bunker://` and `nostrconnect://` connection URIs (`src/nip46.zig`):
  parse and build with RFC 3986 percent-coding, verified against the spec's
  example token. (#39)

## [0.2.1] - 2026-07-11

### Changed

- `Store.query` now answers from a bounded newest-first index merge — one
  reverse cursor per index prefix, k-way merged on the order-preserving
  `[time][id]` key suffix, stopping at `limit` — so query cost is proportional
  to the events returned, not the total matching history. A 500-note,
  20-author home feed over 100k stored events dropped from ~26 ms to ~0.28 ms.
  Ordering and filter semantics are unchanged. (#33, #35)

### Added

- A multi-author home-feed shape in the store benchmark (`src/bench.zig`),
  alongside the single-author profile query. (#34)

## [0.2.0] - 2026-07-10

Milestones A3 (relay transport) and A4 (the local-first event store).

### Added

- Relay transport (A3): RFC 6455 WebSocket framing and handshake
  (`src/websocket.zig`), a stream-generic relay connection state machine with
  NIP-01 subscriptions and a live TCP/TLS dialer (`src/relay.zig`), and the
  NIP-01 filter and client/relay message wire types (`src/filter.zig`,
  `src/message.zig`).
- Outbox model (A3): NIP-65 relay lists (`kind:10002`) with read/write routing
  and zero hardcoded relays (`src/nip65.zig`).
- Local-first event store (A4): a zero-copy, memory-mapped LMDB store
  (`src/store.zig`) with a compact binary event record, secondary indexes
  (author / kind / created_at / single-letter tags), and a filter-driven query
  API that reuses the subscription matching semantics. Validate-on-insert
  ingestion with replaceable and parameterized-replaceable "latest-wins"
  upserts and NIP-09 deletion, a direct-message conversation index,
  local-first reconciliation helpers, a size-cap cache, and batched bulk
  insert with a benchmark (`src/bench.zig`).

### Fixed

- `nostr.version` now reports the package version; the `v0.1.0` release shipped
  with the placeholder `0.0.0`. (#17)

## [0.1.0] - 2026-07-10

Milestone A2: the cryptographic and data foundation of the library —
keys, encoding, events, and signatures, all verified against official
spec test vectors.

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
- NIP-06 key derivation: BIP-39 mnemonic generation/parsing/checksum
  (embedded official English wordlist) and BIP-32 HD derivation for path
  `m/44'/1237'/<account>'/0/0`, verified against both official NIP-06 test
  vectors (secret key and public key, byte-for-byte). Password/mnemonic
  Unicode NFKD normalization is not implemented (same documented limitation
  as NIP-49's NFKC gap).
