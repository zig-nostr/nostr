//! NIP-46 remote signer client: the app side of a bunker connection.
//!
//! EXPERIMENTAL (pre-1.0): the shape may still change.
//!
//! A `Client` asks a remote signer to do what the app cannot do itself
//! because it does not hold the user's key: sign events, encrypt and decrypt.
//! Every request is a kind:24133 event NIP-44 encrypted to the signer's
//! communication key and `p`-tagged to it, and every response comes back the
//! same way, addressed to the client's own throwaway key.
//!
//! There are two ways to meet a signer.
//!
//! - `bunker://`: the signer published its pubkey, relays and an optional
//!   secret. `initBunker` parses the token and `connect` sends `connect` with
//!   that secret, then `get_public_key`, because the key the signer signs with
//!   may differ from the key it talks with.
//! - `nostrconnect://`: the client publishes its own pubkey, relays, a fresh
//!   secret and what it wants. `initNostrConnect` makes the keys and the
//!   secret, `nostrConnectUri` renders the token for the user to carry over,
//!   and `awaitNostrConnect` waits for the signer whose reply carries the
//!   secret. That reply's author becomes the signer this client trusts.
//!
//! The client starts no threads and dials nothing, like the rest of the
//! library. The caller dials the relays (the URI's are in `relays`), hands
//! each connection to `attach`, which subscribes, and runs `run` on each one
//! in a task of its own: one reader per relay. A request publishes to every
//! attached relay and waits on its own slot for the reader that sees the
//! answer first, so several relays need no polling and a dead relay costs
//! nothing while another one answers.
//!
//! Every wait has a deadline (`Options.timeout_ms`) and is a cancelation
//! point: a request started with `io.concurrent` and cancelled ends with
//! `error.Canceled`, and so does a reader blocked in `run`.
//!
//! How answers are matched follows nostr-tools' `BunkerSigner` (nip46.ts): ids
//! are a random per-client prefix plus a serial, pending requests live in a
//! table keyed by id, and an `auth_url` reply carries the URL in its `error`
//! field. As in NDK's `NDKNostrRpc.sendRequest`, the request keeps waiting
//! after an `auth_url` for the real answer. A reply whose author is not the
//! signer is dropped before it is decrypted, and a signed event is checked
//! against the user key and the template before it is handed back.
//!
//! Secret material (the client key and the connect secret) is zeroed in
//! `deinit`, and request and response plaintexts are zeroed before they are
//! freed. Nothing here logs.

const std = @import("std");
const keys = @import("keys.zig");
const event = @import("event.zig");
const nip46 = @import("nip46.zig");
const nip42 = @import("nip42.zig");
const hex = @import("hex.zig");
const json = @import("json.zig");
const filter = @import("filter.zig");

/// The subscription id the client opens on each relay.
pub const subscription_id = "nostr-nip46-client";

/// How many requests may wait at once. Requests are human paced; this is a
/// bound, not a working size.
pub const max_pending = 32;

/// How many relays one client can be attached to.
pub const max_relays = 16;

/// The default deadline on a request, in milliseconds. A signer may be waiting
/// on a person to approve, so this is generous.
pub const default_timeout_ms: u32 = 30_000;

pub const Error = error{
    /// No answer arrived before the deadline.
    Timeout,
    /// The signer answered with an error (a wrong secret, a denial, an
    /// unsupported method). `call` returns the message instead.
    Rejected,
    /// The URI named no relay, or no connection is attached.
    NoRelays,
    /// `attach` was called more than `max_relays` times.
    TooManyRelays,
    /// `max_pending` requests are already waiting.
    TooManyPending,
    /// The request could not be published on any attached relay.
    PublishFailed,
    /// No signer is known yet (`awaitNostrConnect` has not succeeded), or no
    /// user key is known yet (`connect` has not succeeded).
    NotConnected,
    /// The signer answered something that does not fit the method: a ping
    /// that is not "pong", a pubkey that is not 64 hex characters, a signed
    /// event that is not an event.
    UnexpectedResult,
    /// A signed event came back with a different pubkey than the user's, or
    /// with different fields than the template asked for.
    WrongSigner,
    /// A signed event came back with a signature that does not verify.
    BadSignature,
    /// No secure random bytes were available for the client key, the secret,
    /// or the request ids.
    EntropyUnavailable,
} || nip46.Error || std.Io.Cancelable;

/// Told about an `auth_url` reply: the signer wants the user to open `url`
/// (to log in, or approve) before it answers request `request_id`. Called on
/// the reader's thread, once per request, and must not block for long. The
/// request keeps waiting meanwhile, under its original deadline.
pub const AuthUrlHandler = struct {
    context: ?*anyopaque = null,
    onAuthUrl: *const fn (context: ?*anyopaque, request_id: []const u8, url: []const u8) void,
};

pub const Options = struct {
    /// The deadline on each request, and on `awaitNostrConnect`.
    timeout_ms: u32 = default_timeout_ms,
    on_auth_url: ?AuthUrlHandler = null,
    /// A client key to reuse, so a signer that already knows this client does
    /// not have to approve it again. Null makes a fresh one.
    client_secret_key: ?keys.SecretKey = null,
    /// Permissions to ask for: the third `connect` param for a bunker, and the
    /// `perms` query parameter of a `nostrconnect://` token.
    perms: ?[]const u8 = null,
};

/// What `nostrConnectUri` puts in the token besides keys, relays, secret and
/// perms.
pub const AppInfo = struct {
    name: ?[]const u8 = null,
    url: ?[]const u8 = null,
    image: ?[]const u8 = null,
};

/// An unsigned event for `signEvent`. `created_at` is required: the client
/// stamps it, as NIP-46 says, and the library carries no clock of its own.
pub const Template = struct {
    kind: u16,
    content: []const u8 = "",
    tags: []const event.Tag = &.{},
    created_at: i64,
};

/// A signer's answer to `call`. One of `result` and `err` is empty. Both are
/// zeroed on `deinit`, because a decrypt's result is the plaintext.
pub const Reply = struct {
    gpa: std.mem.Allocator,
    result: []u8,
    err: []u8,

    pub fn deinit(self: *Reply) void {
        wipeFree(self.gpa, self.result);
        wipeFree(self.gpa, self.err);
        self.* = undefined;
    }
};

/// A client over connections of type `Conn`: a pointer to a `relay.Relay` in
/// production, or to an in-memory `relay.Connection` in tests. `Conn` must
/// have `subscribe`, `publish`, `receive` and `authenticate`, which both do.
/// `publish` may be called from a requesting thread while a reader sits in
/// `receive`, which the relay's write lock allows.
pub fn Client(comptime Conn: type) type {
    return struct {
        const Self = @This();

        gpa: std.mem.Allocator,
        io: std.Io,
        /// Borrowed. Shared by requesting threads and readers, the way
        /// `signer.serve` shares one across its relays.
        signer: keys.Signer,
        /// The client's own key: what it signs requests with and what the
        /// signer encrypts answers to. Zeroed in `deinit`.
        local: keys.KeyPair,
        /// The connect secret: the bunker's, or the one this client made for
        /// a `nostrconnect://` token. Owned, zeroed in `deinit`.
        secret: ?[]u8,
        perms: ?[]u8,
        /// The relays the URI named (bunker), or the ones the client invites
        /// the signer to (nostrconnect). Owned.
        relays: [][]u8,
        timeout_ms: u32,
        on_auth_url: ?AuthUrlHandler,

        /// Guards everything below.
        lock: std.Io.Mutex = .init,
        /// The signer's communication key. Known from the start for a bunker;
        /// learned from the reply that carries the secret for nostrconnect.
        remote: ?[32]u8,
        /// The key the signer signs with, from `get_public_key`.
        user: ?[32]u8 = null,
        /// Set when a nostrconnect signer has been adopted.
        adopted: std.Io.Event = .unset,
        conns: [max_relays]Conn = undefined,
        conn_count: usize = 0,
        slots: [max_pending]Slot = [_]Slot{.{}} ** max_pending,
        serial: u64 = 0,
        id_prefix: [16]u8,

        const Slot = struct {
            used: bool = false,
            id_buf: [40]u8 = undefined,
            id_len: usize = 0,
            done: std.Io.Event = .unset,
            /// Whether the caller has been told about an `auth_url` for this
            /// request. The same reply arrives once per relay.
            auth_told: bool = false,
            result: ?[]u8 = null,
            err: ?[]u8 = null,

            fn id(self: *const Slot) []const u8 {
                return self.id_buf[0..self.id_len];
            }
        };

        /// A client for a `bunker://` token. Call `attach` on a connection to
        /// each relay, run `run` on each, then `connect`.
        pub fn initBunker(
            gpa: std.mem.Allocator,
            io: std.Io,
            signer: keys.Signer,
            uri: []const u8,
            options: Options,
        ) Error!*Self {
            var parsed = try nip46.parseBunkerUri(gpa, uri);
            defer {
                if (parsed.value.secret) |s| std.crypto.secureZero(u8, @constCast(s));
                parsed.deinit();
            }
            if (parsed.value.relays.len == 0) return Error.NoRelays;
            const self = try create(gpa, io, signer, parsed.value.relays, options);
            errdefer self.deinit();
            self.remote = parsed.value.remote_signer_pubkey;
            if (parsed.value.secret) |s| self.secret = try gpa.dupe(u8, s);
            return self;
        }

        /// A client that invites a signer with a `nostrconnect://` token over
        /// `relays`. Call `attach` and `run` for each relay, show the user
        /// `nostrConnectUri`, then `awaitNostrConnect`.
        pub fn initNostrConnect(
            gpa: std.mem.Allocator,
            io: std.Io,
            signer: keys.Signer,
            relays: []const []const u8,
            options: Options,
        ) Error!*Self {
            if (relays.len == 0) return Error.NoRelays;
            const self = try create(gpa, io, signer, relays, options);
            errdefer self.deinit();
            var raw: [16]u8 = undefined;
            defer std.crypto.secureZero(u8, &raw);
            io.randomSecure(&raw) catch |err| return mapRandom(err);
            var text = std.fmt.bytesToHex(raw, .lower);
            defer std.crypto.secureZero(u8, &text);
            self.secret = try gpa.dupe(u8, &text);
            return self;
        }

        fn create(
            gpa: std.mem.Allocator,
            io: std.Io,
            signer: keys.Signer,
            relays: []const []const u8,
            options: Options,
        ) Error!*Self {
            var prefix_raw: [8]u8 = undefined;
            io.randomSecure(&prefix_raw) catch |err| return mapRandom(err);
            const local = if (options.client_secret_key) |sk|
                try signer.keyPairFromSecretKey(sk)
            else
                signer.generateKeyPair(io) catch return Error.EntropyUnavailable;

            const self = try gpa.create(Self);
            self.* = .{
                .gpa = gpa,
                .io = io,
                .signer = signer,
                .local = local,
                .secret = null,
                .perms = null,
                .relays = &.{},
                .timeout_ms = options.timeout_ms,
                .on_auth_url = options.on_auth_url,
                .remote = null,
                .id_prefix = std.fmt.bytesToHex(prefix_raw, .lower),
            };
            errdefer self.deinit();
            if (options.perms) |p| self.perms = try gpa.dupe(u8, p);
            const owned = try gpa.alloc([]u8, relays.len);
            for (owned) |*r| r.* = &.{};
            self.relays = owned;
            for (relays, 0..) |r, i| owned[i] = try gpa.dupe(u8, r);
            return self;
        }

        /// Zeroes the client key and the secret and frees everything. Stop
        /// every `run` and every request first.
        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            std.crypto.secureZero(u8, &self.local.secret_key);
            if (self.secret) |s| wipeFree(gpa, s);
            if (self.perms) |p| gpa.free(p);
            for (self.relays) |r| gpa.free(r);
            gpa.free(self.relays);
            for (&self.slots) |*slot| {
                if (slot.result) |r| wipeFree(gpa, r);
                if (slot.err) |e| wipeFree(gpa, e);
            }
            gpa.destroy(self);
        }

        /// The client's own pubkey, which the signer sees as the requester.
        pub fn clientPubkey(self: *const Self) [32]u8 {
            return self.local.public_key;
        }

        /// The signer's communication pubkey, once known.
        pub fn remotePubkey(self: *Self) ?[32]u8 {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            return self.remote;
        }

        /// The user's pubkey, once `connect` or `awaitNostrConnect` learned it.
        pub fn userPubkey(self: *Self) ?[32]u8 {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            return self.user;
        }

        /// The `nostrconnect://` token for this client, owned by the caller.
        /// It carries the secret, so zero it when it has been shown.
        pub fn nostrConnectUri(self: *const Self, gpa: std.mem.Allocator, app: AppInfo) std.mem.Allocator.Error![]u8 {
            const relays: []const []const u8 = @ptrCast(self.relays);
            return nip46.buildNostrConnectUri(gpa, self.local.public_key, .{
                .relays = relays,
                .secret = self.secret orelse "",
                .perms = self.perms,
                .name = app.name,
                .url = app.url,
                .image = app.image,
            });
        }

        /// Subscribes `conn` to the kind:24133 events addressed to this client
        /// and adds it to the relays requests go out on. Call it before the
        /// first request, so the answer cannot arrive before the subscription,
        /// and run `run` on the same connection.
        pub fn attach(self: *Self, conn: Conn) !void {
            {
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                if (self.conn_count == max_relays) return Error.TooManyRelays;
            }
            try self.subscribe(conn);
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            if (self.conn_count == max_relays) return Error.TooManyRelays;
            self.conns[self.conn_count] = conn;
            self.conn_count += 1;
        }

        fn subscribe(self: *Self, conn: Conn) !void {
            var mine = std.fmt.bytesToHex(self.local.public_key, .lower);
            const kinds = [_]u16{nip46.kind};
            const p_values = [_][]const u8{&mine};
            const tag_filters = [_]filter.TagFilter{.{ .letter = 'p', .values = &p_values }};
            // A minute back, for a relay whose clock runs behind ours. Older
            // answers cannot match anything: ids and secrets are this
            // client's own.
            const since = std.Io.Timestamp.now(self.io, .real).toSeconds() - 60;
            const filters = [_]filter.Filter{.{ .kinds = &kinds, .tags = &tag_filters, .since = since }};
            try conn.subscribe(subscription_id, &filters);
        }

        /// Reads `conn` until the relay closes it, handing every event to
        /// `dispatch`. Run one per attached relay, in its own task; cancel the
        /// task to stop it early. Answers a NIP-42 challenge with the client
        /// key and subscribes again once the relay accepts it, as
        /// `signer.serve` does on the other side.
        pub fn run(self: *Self, conn: Conn, relay_url: []const u8) !void {
            var auth_id: ?[32]u8 = null;
            while (true) {
                var msg = (try conn.receive()) orelse return;
                defer msg.deinit();
                switch (msg.value) {
                    .event => |e| self.dispatch(e.event),
                    .auth => |a| {
                        var arena = std.heap.ArenaAllocator.init(self.gpa);
                        defer arena.deinit();
                        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
                        const ev = try nip42.authEvent(arena.allocator(), self.signer, self.local, relay_url, a.challenge, now, null);
                        try conn.authenticate(ev);
                        auth_id = ev.id;
                    },
                    .ok => |o| if (auth_id) |id| {
                        if (std.mem.eql(u8, &o.event_id, &id)) {
                            if (o.accepted) try self.subscribe(conn);
                            auth_id = null;
                        }
                    },
                    // "auth-required" waits for the OK above. Any other close
                    // ends this relay's part; the others carry on.
                    .closed => |c| if (!std.mem.startsWith(u8, c.message, "auth-required")) return,
                    .eose, .notice, .count, .neg_msg, .neg_err => {},
                }
            }
        }

        /// Takes one event from a relay. `run` calls it; a caller with its own
        /// reader loop can call it directly. Never fails: anything that is
        /// not an answer for this client is dropped.
        pub fn dispatch(self: *Self, ev: event.Event) void {
            if (ev.kind != nip46.kind) return;
            if (!tagsP(ev, self.local.public_key)) return;

            const remote = blk: {
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                break :blk self.remote;
            };
            // Who sent it, before anything else, and before spending a decrypt
            // on it. Once the signer is known, nobody else can answer for it.
            if (remote) |r| {
                if (!std.mem.eql(u8, &ev.pubkey, &r)) return;
            } else if (self.secret == null) return;

            const plaintext = nip46.open(self.gpa, self.signer, self.local.secret_key, ev) catch return;
            defer wipeFree(self.gpa, plaintext);
            var parsed = nip46.parseResponse(self.gpa, plaintext) catch return;
            defer parsed.deinit();
            const reply = parsed.value;

            if (remote == null) return self.adopt(ev.pubkey, reply);

            if (std.mem.eql(u8, reply.result, "auth_url")) return self.tellAuthUrl(reply);

            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            const slot = self.findSlot(reply.id) orelse return;
            // The same answer arrives once per relay. The first one counts.
            if (slot.done.isSet()) return;
            const result = self.gpa.dupe(u8, reply.result) catch return;
            const err = self.gpa.dupe(u8, reply.err) catch {
                wipeFree(self.gpa, result);
                return;
            };
            slot.result = result;
            slot.err = err;
            slot.done.set(self.io);
        }

        /// A nostrconnect signer answers with the secret as its result, and
        /// its author is the signer from then on. Nothing else is accepted
        /// while no signer is known: not "ack", not an error.
        fn adopt(self: *Self, author: [32]u8, reply: nip46.Response) void {
            const want = self.secret orelse return;
            if (reply.err.len != 0 or !constantTimeEql(want, reply.result)) return;
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            if (self.remote != null) return;
            self.remote = author;
            self.adopted.set(self.io);
        }

        fn tellAuthUrl(self: *Self, reply: nip46.Response) void {
            const handler = self.on_auth_url orelse return;
            var id_copy: [40]u8 = undefined;
            const id_len = blk: {
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                const slot = self.findSlot(reply.id) orelse return;
                if (slot.auth_told or slot.done.isSet()) return;
                slot.auth_told = true;
                @memcpy(id_copy[0..slot.id_len], slot.id());
                break :blk slot.id_len;
            };
            // Outside the lock: the handler is the caller's code.
            handler.onAuthUrl(handler.context, id_copy[0..id_len], reply.err);
        }

        fn findSlot(self: *Self, id: []const u8) ?*Slot {
            for (&self.slots) |*slot| {
                if (slot.used and std.mem.eql(u8, slot.id(), id)) return slot;
            }
            return null;
        }

        /// Sends `method` with `params` and waits for the answer, under the
        /// client's deadline. A signer's error comes back in `Reply.err`
        /// rather than as `error.Rejected`, for a caller that wants to show
        /// it.
        pub fn call(self: *Self, method: []const u8, params: []const []const u8) !Reply {
            const remote = self.remotePubkey() orelse return Error.NotConnected;
            const index = try self.claimSlot();
            defer self.releaseSlot(index);
            const slot = &self.slots[index];

            const body = try (nip46.Request{ .id = slot.id(), .method = method, .params = params }).toJson(self.gpa);
            defer wipeFree(self.gpa, body);
            const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
            var sealed = try nip46.seal(self.gpa, self.io, self.signer, self.local, remote, body, now);
            defer sealed.deinit();

            var conns: [max_relays]Conn = undefined;
            const count = blk: {
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                @memcpy(conns[0..self.conn_count], self.conns[0..self.conn_count]);
                break :blk self.conn_count;
            };
            if (count == 0) return Error.NoRelays;
            // Every relay, as NDK and nostr-tools publish to the whole set: the
            // signer may be listening on any of them.
            var sent: usize = 0;
            for (conns[0..count]) |conn| {
                conn.publish(sealed.event) catch continue;
                sent += 1;
            }
            if (sent == 0) return Error.PublishFailed;

            try self.waitFor(&slot.done);

            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            const reply: Reply = .{ .gpa = self.gpa, .result = slot.result.?, .err = slot.err.? };
            slot.result = null;
            slot.err = null;
            return reply;
        }

        fn claimSlot(self: *Self) Error!usize {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            for (&self.slots, 0..) |*slot, i| {
                if (slot.used) continue;
                self.serial += 1;
                slot.* = .{ .used = true };
                const id = std.fmt.bufPrint(&slot.id_buf, "{s}-{d}", .{ &self.id_prefix, self.serial }) catch unreachable;
                slot.id_len = id.len;
                return i;
            }
            return Error.TooManyPending;
        }

        fn releaseSlot(self: *Self, index: usize) void {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            const slot = &self.slots[index];
            if (slot.result) |r| wipeFree(self.gpa, r);
            if (slot.err) |e| wipeFree(self.gpa, e);
            slot.* = .{};
        }

        /// Waits for `done` until the deadline. A wakeup that is not the event
        /// (the futex allows them) waits again for what is left.
        fn waitFor(self: *Self, done: *std.Io.Event) Error!void {
            const deadline = (std.Io.Timeout{ .duration = .{
                .raw = .fromMilliseconds(self.timeout_ms),
                .clock = .awake,
            } }).toTimestamp(self.io).?;
            while (true) {
                done.waitTimeout(self.io, .{ .deadline = deadline }) catch |err| switch (err) {
                    error.Timeout => {
                        const now = std.Io.Clock.Timestamp.now(self.io, deadline.clock);
                        if (now.raw.nanoseconds >= deadline.raw.nanoseconds) return Error.Timeout;
                        continue;
                    },
                    error.Canceled => return error.Canceled,
                };
                return;
            }
        }

        /// `call`, with a signer's error turned into `error.Rejected`. The
        /// result is owned by the caller.
        fn request(self: *Self, method: []const u8, params: []const []const u8) ![]u8 {
            var reply = try self.call(method, params);
            if (reply.err.len != 0) {
                reply.deinit();
                return Error.Rejected;
            }
            wipeFree(self.gpa, reply.err);
            return reply.result;
        }

        /// Connects to a bunker: `connect` with the URI's secret (and the
        /// requested perms), then `get_public_key`. A wrong secret comes back
        /// as `error.Rejected`.
        pub fn connect(self: *Self) !void {
            const remote = self.remotePubkey() orelse return Error.NotConnected;
            var remote_hex = std.fmt.bytesToHex(remote, .lower);
            const with_perms = [_][]const u8{ &remote_hex, self.secret orelse "", self.perms orelse "" };
            const params: []const []const u8 = if (self.perms != null) &with_perms else with_perms[0..2];
            const result = try self.request("connect", params);
            // "ack", or the secret echoed back by some signers. Either way it
            // is not an error, which is what the answer is for.
            wipeFree(self.gpa, result);
            _ = try self.getPublicKey();
        }

        /// Waits for the signer invited by `nostrConnectUri` to answer with
        /// the secret, under the client's deadline, then asks it for the user
        /// key.
        pub fn awaitNostrConnect(self: *Self) !void {
            try self.waitFor(&self.adopted);
            _ = try self.getPublicKey();
        }

        /// Asks the signer for the user's pubkey and remembers it.
        pub fn getPublicKey(self: *Self) ![32]u8 {
            const result = try self.request("get_public_key", &.{});
            defer wipeFree(self.gpa, result);
            const pubkey = hex.decodeFixed(32, result) catch return Error.UnexpectedResult;
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            self.user = pubkey;
            return pubkey;
        }

        pub fn ping(self: *Self) !void {
            const result = try self.request("ping", &.{});
            defer wipeFree(self.gpa, result);
            if (!std.mem.eql(u8, result, "pong")) return Error.UnexpectedResult;
        }

        /// Asks the signer to sign `template` and checks what comes back: an
        /// event by the user key, with the template's kind, content, tags and
        /// time, and a signature that verifies. Free it with `deinit`.
        pub fn signEvent(self: *Self, template: Template) !event.Parsed {
            const user = self.userPubkey() orelse return Error.NotConnected;
            const body = try templateJson(self.gpa, template);
            defer self.gpa.free(body);
            const result = try self.request("sign_event", &.{body});
            defer self.gpa.free(result);

            // Parsed into an arena that also holds the text: `event.fromJson`
            // leaves strings without escapes pointing into its input, and
            // `result` is freed on the way out.
            const arena = try self.gpa.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(self.gpa);
            var signed: event.Parsed = .{ .arena = arena, .value = undefined };
            errdefer signed.deinit();
            const a = arena.allocator();
            const text = try a.dupe(u8, result);
            const value = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return Error.UnexpectedResult,
            };
            signed.value = event.fromValueLeaky(a, value) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return Error.UnexpectedResult,
            };
            const ev = signed.value;
            if (!std.mem.eql(u8, &ev.pubkey, &user)) return Error.WrongSigner;
            if (ev.kind != template.kind or ev.created_at != template.created_at or
                !std.mem.eql(u8, ev.content, template.content) or !tagsEql(ev.tags, template.tags))
                return Error.WrongSigner;
            if (!try event.verify(self.gpa, self.signer, ev)) return Error.BadSignature;
            return signed;
        }

        /// NIP-44 encrypts `plaintext` from the user to `peer`. Owned result.
        pub fn nip44Encrypt(self: *Self, peer: [32]u8, plaintext: []const u8) ![]u8 {
            return self.peerRequest("nip44_encrypt", peer, plaintext);
        }

        /// NIP-44 decrypts `ciphertext` that `peer` sent the user. Owned
        /// result; zero it when done.
        pub fn nip44Decrypt(self: *Self, peer: [32]u8, ciphertext: []const u8) ![]u8 {
            return self.peerRequest("nip44_decrypt", peer, ciphertext);
        }

        /// NIP-04 encrypts `plaintext` from the user to `peer`. Owned result.
        pub fn nip04Encrypt(self: *Self, peer: [32]u8, plaintext: []const u8) ![]u8 {
            return self.peerRequest("nip04_encrypt", peer, plaintext);
        }

        /// NIP-04 decrypts `ciphertext` that `peer` sent the user. Owned
        /// result; zero it when done.
        pub fn nip04Decrypt(self: *Self, peer: [32]u8, ciphertext: []const u8) ![]u8 {
            return self.peerRequest("nip04_decrypt", peer, ciphertext);
        }

        fn peerRequest(self: *Self, method: []const u8, peer: [32]u8, text: []const u8) ![]u8 {
            var peer_hex = std.fmt.bytesToHex(peer, .lower);
            return self.request(method, &.{ &peer_hex, text });
        }
    };
}

fn mapRandom(err: std.Io.RandomSecureError) Error {
    return switch (err) {
        error.EntropyUnavailable => Error.EntropyUnavailable,
        error.Canceled => error.Canceled,
    };
}

fn wipeFree(gpa: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    gpa.free(bytes);
}

fn constantTimeEql(want: []const u8, got: []const u8) bool {
    if (want.len != got.len) return false;
    var diff: u8 = 0;
    for (want, got) |a, b| diff |= a ^ b;
    return diff == 0;
}

/// Whether `ev` carries a `p` tag naming `pubkey`.
fn tagsP(ev: event.Event, pubkey: [32]u8) bool {
    const want = std.fmt.bytesToHex(pubkey, .lower);
    for (ev.tags) |tag| {
        if (tag.len >= 2 and std.mem.eql(u8, tag[0], "p") and std.ascii.eqlIgnoreCase(tag[1], &want)) return true;
    }
    return false;
}

fn tagsEql(a: []const event.Tag, b: []const event.Tag) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x.len != y.len) return false;
        for (x, y) |s, t| if (!std.mem.eql(u8, s, t)) return false;
    }
    return true;
}

/// The `sign_event` param: `{kind, content, tags, created_at}` as JSON.
fn templateJson(gpa: std.mem.Allocator, t: Template) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.print(gpa, "{{\"kind\":{d},\"content\":", .{t.kind});
    try json.appendString(&out, gpa, t.content);
    try out.appendSlice(gpa, ",\"tags\":[");
    for (t.tags, 0..) |tag, i| {
        if (i != 0) try out.append(gpa, ',');
        try out.append(gpa, '[');
        for (tag, 0..) |field, j| {
            if (j != 0) try out.append(gpa, ',');
            try json.appendString(&out, gpa, field);
        }
        try out.append(gpa, ']');
    }
    try out.print(gpa, "],\"created_at\":{d}}}", .{t.created_at});
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const relay = @import("relay.zig");
const signer_mod = @import("signer.zig");
const websocket = @import("websocket.zig");
const nip44 = @import("nip44.zig");
const nip04 = @import("nip04.zig");

test "nip46_client: compiles against a live relay" {
    std.testing.refAllDecls(Client(*relay.Relay));
}

/// An in-memory relay. Each `Peer` is one connection's byte stream: what a
/// peer publishes reaches every other peer whose subscription `p`-tags the
/// event, as server frames, and a read waits for those frames, honours its
/// deadline, and ends at EOF once the hub closes. The waits are futex waits,
/// so they are cancelation points like a socket read.
const Hub = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    lock: std.Io.Mutex = .init,
    /// Bumped on every delivery and on close; readers wait on it.
    seq: std.atomic.Value(u32) = .init(0),
    peers: [8]*Peer = undefined,
    peer_count: usize = 0,
    closed: bool = false,

    const Peer = struct {
        hub: *Hub,
        inbox: std.ArrayList(u8) = .empty,
        /// The `#p` value of the peer's subscription, once it has one.
        p_filter: ?[64]u8 = null,

        pub fn read(self: *Peer, buffer: []u8, deadline: ?std.Io.Clock.Timestamp) !usize {
            const hub = self.hub;
            while (true) {
                const seen = hub.seq.load(.acquire);
                {
                    hub.lock.lockUncancelable(hub.io);
                    defer hub.lock.unlock(hub.io);
                    if (self.inbox.items.len > 0) {
                        const n = @min(buffer.len, self.inbox.items.len);
                        @memcpy(buffer[0..n], self.inbox.items[0..n]);
                        self.inbox.replaceRangeAssumeCapacity(0, n, &.{});
                        return n;
                    }
                    if (hub.closed) return 0;
                }
                const timeout: std.Io.Timeout = if (deadline) |d| .{ .deadline = d } else .none;
                try hub.io.futexWaitTimeout(u32, &hub.seq.raw, seen, timeout);
                if (deadline) |d| {
                    const now = std.Io.Clock.Timestamp.now(hub.io, d.clock);
                    if (now.raw.nanoseconds >= d.raw.nanoseconds) return error.Timeout;
                }
            }
        }

        pub fn writeAll(self: *Peer, bytes: []const u8) !void {
            const hub = self.hub;
            const copy = try hub.gpa.dupe(u8, bytes);
            defer hub.gpa.free(copy);
            var offset: usize = 0;
            while (try websocket.decodeFrame(copy[offset..])) |frame| {
                offset += frame.frame_len;
                const text = frame.payload;
                if (std.mem.startsWith(u8, text, "[\"REQ\"")) {
                    const marker = "\"#p\":[\"";
                    const at = std.mem.indexOf(u8, text, marker) orelse continue;
                    const start = at + marker.len;
                    hub.lock.lockUncancelable(hub.io);
                    defer hub.lock.unlock(hub.io);
                    self.p_filter = text[start..][0..64].*;
                } else if (std.mem.startsWith(u8, text, "[\"EVENT\",")) {
                    try hub.broadcast(self, text["[\"EVENT\",".len .. text.len - 1]);
                }
            }
        }
    };

    fn add(self: *Hub) !*Peer {
        const peer = try self.gpa.create(Peer);
        peer.* = .{ .hub = self };
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.peers[self.peer_count] = peer;
        self.peer_count += 1;
        return peer;
    }

    fn deinit(self: *Hub) void {
        for (self.peers[0..self.peer_count]) |peer| {
            peer.inbox.deinit(self.gpa);
            self.gpa.destroy(peer);
        }
    }

    fn broadcast(self: *Hub, from: *Peer, event_json: []const u8) !void {
        var frame: std.ArrayList(u8) = .empty;
        defer frame.deinit(self.gpa);
        const text = try std.fmt.allocPrint(self.gpa, "[\"EVENT\",\"sub\",{s}]", .{event_json});
        defer self.gpa.free(text);
        try appendServerText(&frame, self.gpa, text);

        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        for (self.peers[0..self.peer_count]) |peer| {
            if (peer == from) continue;
            const p = peer.p_filter orelse continue;
            var needle: [80]u8 = undefined;
            const tag = std.fmt.bufPrint(&needle, "[\"p\",\"{s}\"", .{&p}) catch unreachable;
            if (std.mem.indexOf(u8, event_json, tag) == null) continue;
            try peer.inbox.appendSlice(self.gpa, frame.items);
        }
        _ = self.seq.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.seq.raw, std.math.maxInt(u32));
    }

    /// Ends every peer's stream, so readers see EOF and return.
    fn close(self: *Hub) void {
        {
            self.lock.lockUncancelable(self.io);
            defer self.lock.unlock(self.io);
            self.closed = true;
        }
        _ = self.seq.fetchAdd(1, .release);
        self.io.futexWake(u32, &self.seq.raw, std.math.maxInt(u32));
    }

    /// Waits until `peer` has subscribed, so nothing published before then
    /// is lost.
    fn awaitSubscribed(self: *Hub, peer: *Peer) !void {
        for (0..2000) |_| {
            {
                self.lock.lockUncancelable(self.io);
                defer self.lock.unlock(self.io);
                if (peer.p_filter != null) return;
            }
            try self.io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.NeverSubscribed;
    }
};

fn appendServerText(list: *std.ArrayList(u8), gpa: std.mem.Allocator, text: []const u8) !void {
    try list.append(gpa, 0x81);
    if (text.len <= 125) {
        try list.append(gpa, @intCast(text.len));
    } else if (text.len <= 0xffff) {
        try list.append(gpa, 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext, @intCast(text.len), .big);
        try list.appendSlice(gpa, &ext);
    } else {
        try list.append(gpa, 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, &ext, text.len, .big);
        try list.appendSlice(gpa, &ext);
    }
    try list.appendSlice(gpa, text);
}

const TestConn = relay.Connection(*Hub.Peer);
const TestClient = Client(*TestConn);

fn serveTask(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: *TestConn,
    bunker: *nip46.Bunker,
    remote: keys.KeyPair,
    seen: *signer_mod.SeenRequests,
) !void {
    return signer_mod.serve(gpa, io, conn, bunker, remote, "wss://hub.test", seen);
}

fn testKeyPair(ctx: keys.Signer, last: u8) !keys.KeyPair {
    var sk = [_]u8{0} ** 32;
    sk[31] = last;
    return ctx.keyPairFromSecretKey(sk);
}

/// One hub, one bunker served by `signer.serve`, one client attached and
/// reading. The bunker's user key differs from its communication key, so a
/// test sees which one comes back.
const Fixture = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    ctx: keys.Signer,
    hub: Hub,
    signer_conn: TestConn = undefined,
    client_conn: TestConn = undefined,
    user: keys.KeyPair,
    remote: keys.KeyPair,
    clients: nip46.AuthorizedClients = .{},
    seen: signer_mod.SeenRequests = .{},
    bunker: nip46.Bunker = undefined,
    client: ?*TestClient = null,
    serving: ?std.Io.Future(@typeInfo(@TypeOf(serveTask)).@"fn".return_type.?) = null,
    reading: ?std.Io.Future(@typeInfo(@TypeOf(TestClient.run)).@"fn".return_type.?) = null,

    fn init(f: *Fixture, gpa: std.mem.Allocator, io: std.Io, bunker_secret: ?[]const u8, uri_secret: ?[]const u8, options: Options) !void {
        const ctx = keys.Signer.init();
        f.* = .{
            .gpa = gpa,
            .io = io,
            .ctx = ctx,
            .hub = .{ .gpa = gpa, .io = io },
            .user = try testKeyPair(ctx, 7),
            .remote = try testKeyPair(ctx, 9),
        };
        f.bunker = .{
            .signer = ctx,
            .user = f.user,
            .remote = f.remote,
            .secret = bunker_secret,
            .policy = nip46.approveAll(),
            .clients = &f.clients,
        };
        f.signer_conn = TestConn.init(gpa, io, try f.hub.add());
        f.client_conn = TestConn.init(gpa, io, try f.hub.add());
        errdefer f.deinit();
        f.serving = try io.concurrent(serveTask, .{ gpa, io, &f.signer_conn, &f.bunker, f.remote, &f.seen });
        try f.hub.awaitSubscribed(f.signer_conn.stream);

        const uri = try nip46.buildBunkerUri(gpa, f.remote.public_key, &.{"wss://hub.test"}, uri_secret);
        defer gpa.free(uri);
        const client = try TestClient.initBunker(gpa, io, ctx, uri, options);
        f.client = client;
        try client.attach(&f.client_conn);
        f.reading = try io.concurrent(TestClient.run, .{ client, &f.client_conn, "wss://hub.test" });
    }

    fn deinit(f: *Fixture) void {
        f.hub.close();
        if (f.serving) |*s| s.await(f.io) catch {};
        if (f.reading) |*r| r.await(f.io) catch {};
        if (f.client) |c| c.deinit();
        f.signer_conn.deinit();
        f.client_conn.deinit();
        f.hub.deinit();
        f.ctx.deinit();
    }
};

test "nip46_client: connect with the right secret, then get_public_key returns the user key" {
    var f: Fixture = undefined;
    try f.init(testing.allocator, testing.io, "s3cret", "s3cret", .{ .timeout_ms = 5000 });
    defer f.deinit();

    try f.client.?.connect();
    // The user key, not the key the signer talks with: they differ here.
    try testing.expectEqualSlices(u8, &f.user.public_key, &f.client.?.userPubkey().?);
    try testing.expect(!std.mem.eql(u8, &f.remote.public_key, &f.client.?.userPubkey().?));
    try testing.expect(f.clients.isAuthorized(f.client.?.clientPubkey()));
    try f.client.?.ping();
}

test "nip46_client: a wrong connect secret is refused and leaves the client unauthorized" {
    var f: Fixture = undefined;
    try f.init(testing.allocator, testing.io, "s3cret", "guess", .{ .timeout_ms = 5000 });
    defer f.deinit();

    try testing.expectError(Error.Rejected, f.client.?.connect());
    try testing.expect(f.client.?.userPubkey() == null);
    try testing.expect(!f.clients.isAuthorized(f.client.?.clientPubkey()));

    // The message is there for a caller that asks for it.
    var remote_hex = std.fmt.bytesToHex(f.remote.public_key, .lower);
    var reply = try f.client.?.call("connect", &.{ &remote_hex, "guess" });
    defer reply.deinit();
    try testing.expectEqualStrings("invalid secret", reply.err);
}

test "nip46_client: sign_event comes back signed by the user key" {
    var f: Fixture = undefined;
    try f.init(testing.allocator, testing.io, null, null, .{ .timeout_ms = 5000 });
    defer f.deinit();
    try f.client.?.connect();

    const tags = [_]event.Tag{&.{ "t", "zig" }};
    var signed = try f.client.?.signEvent(.{ .kind = 1, .content = "hello \"remote\"", .tags = &tags, .created_at = 1_700_000_000 });
    defer signed.deinit();
    try testing.expectEqualSlices(u8, &f.user.public_key, &signed.value.pubkey);
    try testing.expectEqualStrings("hello \"remote\"", signed.value.content);
    try testing.expect(try event.verify(testing.allocator, f.ctx, signed.value));
}

test "nip46_client: nip44 encrypt and decrypt round trip through the signer" {
    var f: Fixture = undefined;
    try f.init(testing.allocator, testing.io, null, null, .{ .timeout_ms = 5000 });
    defer f.deinit();
    try f.client.?.connect();

    const peer = try testKeyPair(f.ctx, 11);
    const ciphertext = try f.client.?.nip44Encrypt(peer.public_key, "for your eyes");
    defer testing.allocator.free(ciphertext);

    // The peer can read it with its own key, so it really is from the user.
    const opened = try nip44.decrypt(testing.allocator, f.ctx, peer.secret_key, f.user.public_key, ciphertext);
    defer testing.allocator.free(opened);
    try testing.expectEqualStrings("for your eyes", opened);

    const back = try f.client.?.nip44Decrypt(peer.public_key, ciphertext);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("for your eyes", back);
}

test "nip46_client: nip04 encrypt and decrypt round trip through the signer" {
    var f: Fixture = undefined;
    try f.init(testing.allocator, testing.io, null, null, .{ .timeout_ms = 5000 });
    defer f.deinit();
    try f.client.?.connect();

    const peer = try testKeyPair(f.ctx, 12);
    const ciphertext = try f.client.?.nip04Encrypt(peer.public_key, "an old style message");
    defer testing.allocator.free(ciphertext);

    const opened = try nip04.decrypt(testing.allocator, f.ctx, peer.secret_key, f.user.public_key, ciphertext);
    defer testing.allocator.free(opened);
    try testing.expectEqualStrings("an old style message", opened);

    const back = try f.client.?.nip04Decrypt(peer.public_key, ciphertext);
    defer testing.allocator.free(back);
    try testing.expectEqualStrings("an old style message", back);

    try testing.expectError(Error.Rejected, f.client.?.nip04Decrypt(peer.public_key, "not a payload"));
}

test "nip46_client: a request nobody answers times out instead of hanging" {
    const gpa = testing.allocator;
    const io = testing.io;
    var hub: Hub = .{ .gpa = gpa, .io = io };
    defer hub.deinit();
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    const remote = try testKeyPair(ctx, 9);

    var conn = TestConn.init(gpa, io, try hub.add());
    defer conn.deinit();
    const uri = try nip46.buildBunkerUri(gpa, remote.public_key, &.{"wss://hub.test"}, null);
    defer gpa.free(uri);
    const client = try TestClient.initBunker(gpa, io, ctx, uri, .{ .timeout_ms = 150 });
    defer client.deinit();
    try client.attach(&conn);
    var reading = try io.concurrent(TestClient.run, .{ client, &conn, "wss://hub.test" });
    defer {
        hub.close();
        _ = reading.await(io) catch {};
    }

    const started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    try testing.expectError(Error.Timeout, client.ping());
    const waited = std.Io.Timestamp.now(io, .awake).toMilliseconds() - started;
    try testing.expect(waited >= 100 and waited < 2000);

    // And a waiting request is a cancelation point: cancelled, it ends.
    client.timeout_ms = 60_000;
    var pinging = try io.concurrent(TestClient.ping, .{client});
    defer _ = pinging.cancel(io) catch {};
    try io.sleep(.fromMilliseconds(50), .awake);
    const cancel_started = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    try testing.expectError(error.Canceled, pinging.cancel(io));
    try testing.expect(std.Io.Timestamp.now(io, .awake).toMilliseconds() - cancel_started < 2000);

    // So is the reader, blocked on a relay that says nothing.
    try testing.expectError(error.Canceled, reading.cancel(io));
}

/// A signer played by hand, for what `Bunker` never does: a forged answer from
/// another key that somehow learned the request id, then an `auth_url`, then
/// the real answer. Answers every request once and runs until the hub closes.
fn scriptedSigner(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: *TestConn,
    ctx: keys.Signer,
    remote: keys.KeyPair,
    forger: keys.KeyPair,
) !void {
    var mine = std.fmt.bytesToHex(remote.public_key, .lower);
    const kinds = [_]u16{nip46.kind};
    const p_values = [_][]const u8{&mine};
    const tag_filters = [_]filter.TagFilter{.{ .letter = 'p', .values = &p_values }};
    try conn.subscribe("s", &.{.{ .kinds = &kinds, .tags = &tag_filters }});
    while (try conn.receive()) |msg_const| {
        var msg = msg_const;
        defer msg.deinit();
        const ev = switch (msg.value) {
            .event => |e| e.event,
            else => continue,
        };
        const plaintext = try nip46.open(gpa, ctx, remote.secret_key, ev);
        defer gpa.free(plaintext);
        var req = try nip46.parseRequest(gpa, plaintext);
        defer req.deinit();
        const id = req.value.id;
        const now = std.Io.Timestamp.now(io, .real).toSeconds();

        const answers = [_]struct { from: keys.KeyPair, reply: nip46.Response }{
            .{ .from = forger, .reply = .{ .id = id, .result = "forged" } },
            .{ .from = remote, .reply = .{ .id = id, .result = "auth_url", .err = "https://signer.test/approve" } },
            .{ .from = remote, .reply = .{ .id = id, .result = "auth_url", .err = "https://signer.test/approve" } },
            .{ .from = remote, .reply = .{ .id = id, .result = "pong" } },
        };
        for (answers) |a| {
            const body = try a.reply.toJson(gpa);
            defer gpa.free(body);
            var sealed = try nip46.seal(gpa, io, ctx, a.from, ev.pubkey, body, now);
            defer sealed.deinit();
            try conn.publish(sealed.event);
            try io.sleep(.fromMilliseconds(20), .awake);
        }
    }
}

const AuthLog = struct {
    count: std.atomic.Value(u32) = .init(0),
    url: [64]u8 = undefined,
    url_len: usize = 0,

    fn record(context: ?*anyopaque, request_id: []const u8, url: []const u8) void {
        _ = request_id;
        const self: *AuthLog = @ptrCast(@alignCast(context.?));
        @memcpy(self.url[0..url.len], url);
        self.url_len = url.len;
        _ = self.count.fetchAdd(1, .release);
    }
};

test "nip46_client: a forged answer is ignored and auth_url is surfaced while the request waits" {
    const gpa = testing.allocator;
    const io = testing.io;
    var hub: Hub = .{ .gpa = gpa, .io = io };
    defer hub.deinit();
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    const remote = try testKeyPair(ctx, 9);
    const forger = try testKeyPair(ctx, 13);

    var signer_conn = TestConn.init(gpa, io, try hub.add());
    defer signer_conn.deinit();
    var client_conn = TestConn.init(gpa, io, try hub.add());
    defer client_conn.deinit();

    var signing = try io.concurrent(scriptedSigner, .{ gpa, io, &signer_conn, ctx, remote, forger });
    defer {
        hub.close();
        _ = signing.await(io) catch {};
    }
    try hub.awaitSubscribed(signer_conn.stream);

    var log: AuthLog = .{};
    const uri = try nip46.buildBunkerUri(gpa, remote.public_key, &.{"wss://hub.test"}, null);
    defer gpa.free(uri);
    const client = try TestClient.initBunker(gpa, io, ctx, uri, .{
        .timeout_ms = 5000,
        .on_auth_url = .{ .context = &log, .onAuthUrl = &AuthLog.record },
    });
    defer client.deinit();
    try client.attach(&client_conn);
    var reading = try io.concurrent(TestClient.run, .{ client, &client_conn, "wss://hub.test" });
    defer {
        hub.close();
        _ = reading.await(io) catch {};
    }

    // The forged "forged" arrives first and would fail the ping if taken.
    try client.ping();
    try testing.expectEqual(@as(u32, 1), log.count.load(.acquire));
    try testing.expectEqualStrings("https://signer.test/approve", log.url[0..log.url_len]);

    hub.close();
    try signing.await(io);
    try reading.await(io);
}

test "nip46_client: nostrconnect adopts the signer that answers with the secret" {
    const gpa = testing.allocator;
    const io = testing.io;
    var hub: Hub = .{ .gpa = gpa, .io = io };
    defer hub.deinit();
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    const remote = try testKeyPair(ctx, 9);
    const impostor = try testKeyPair(ctx, 13);

    var signer_conn = TestConn.init(gpa, io, try hub.add());
    defer signer_conn.deinit();
    var client_conn = TestConn.init(gpa, io, try hub.add());
    defer client_conn.deinit();

    const client = try TestClient.initNostrConnect(gpa, io, ctx, &.{"wss://hub.test"}, .{ .timeout_ms = 5000, .perms = "sign_event:1" });
    defer client.deinit();
    try client.attach(&client_conn);
    var reading = try io.concurrent(TestClient.run, .{ client, &client_conn, "wss://hub.test" });
    defer {
        hub.close();
        _ = reading.await(io) catch {};
    }
    try testing.expectError(Error.NotConnected, client.ping());

    const uri = try client.nostrConnectUri(gpa, .{ .name = "Test App" });
    defer gpa.free(uri);
    var invite = try nip46.parseNostrConnectUri(gpa, uri);
    defer invite.deinit();
    try testing.expectEqualSlices(u8, &client.clientPubkey(), &invite.value.client_pubkey);
    try testing.expectEqualStrings("sign_event:1", invite.value.perms.?);
    try testing.expectEqualStrings("Test App", invite.value.name.?);
    try testing.expectEqual(@as(usize, 32), invite.value.secret.len);

    // An impostor answers first with a guess, and plain "ack": neither is the
    // secret, so neither is adopted.
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    for ([_][]const u8{ "guess", "ack" }) |guess| {
        var wrong = invite.value;
        wrong.secret = guess;
        var fake = try nip46.acceptNostrConnect(gpa, io, ctx, impostor, wrong, "x", now);
        defer fake.deinit();
        try signer_conn.publish(fake.event);
    }

    // The real signer accepts, authorizes the client, and serves.
    var clients: nip46.AuthorizedClients = .{};
    var bunker = nip46.Bunker.initSingleKey(ctx, remote, nip46.approveAll(), &clients);
    bunker.authorize(invite.value.client_pubkey);
    var seen: signer_mod.SeenRequests = .{};
    var serving = try io.concurrent(serveTask, .{ gpa, io, &signer_conn, &bunker, remote, &seen });
    defer {
        hub.close();
        _ = serving.await(io) catch {};
    }
    try hub.awaitSubscribed(signer_conn.stream);
    var accept = try nip46.acceptNostrConnect(gpa, io, ctx, remote, invite.value, "x", now);
    defer accept.deinit();
    try signer_conn.publish(accept.event);

    try client.awaitNostrConnect();
    try testing.expectEqualSlices(u8, &remote.public_key, &client.remotePubkey().?);
    try testing.expectEqualSlices(u8, &remote.public_key, &client.userPubkey().?);
    try client.ping();

    hub.close();
    try serving.await(io);
    try reading.await(io);
}

test "nip46_client: one request over two relays is answered once" {
    const gpa = testing.allocator;
    const io = testing.io;
    var ctx = keys.Signer.init();
    defer ctx.deinit();
    const remote = try testKeyPair(ctx, 9);

    var hub_a: Hub = .{ .gpa = gpa, .io = io };
    defer hub_a.deinit();
    var hub_b: Hub = .{ .gpa = gpa, .io = io };
    defer hub_b.deinit();

    // The signer listens on both, sharing one replay record, as a signer on
    // several relays does.
    var clients: nip46.AuthorizedClients = .{};
    var bunker = nip46.Bunker.initSingleKey(ctx, remote, nip46.approveAll(), &clients);
    var seen: signer_mod.SeenRequests = .{};
    var signer_a = TestConn.init(gpa, io, try hub_a.add());
    defer signer_a.deinit();
    var signer_b = TestConn.init(gpa, io, try hub_b.add());
    defer signer_b.deinit();
    var serving_a = try io.concurrent(serveTask, .{ gpa, io, &signer_a, &bunker, remote, &seen });
    var serving_b = try io.concurrent(serveTask, .{ gpa, io, &signer_b, &bunker, remote, &seen });
    defer {
        hub_a.close();
        hub_b.close();
        _ = serving_a.await(io) catch {};
        _ = serving_b.await(io) catch {};
    }
    try hub_a.awaitSubscribed(signer_a.stream);
    try hub_b.awaitSubscribed(signer_b.stream);

    const uri = try nip46.buildBunkerUri(gpa, remote.public_key, &.{ "wss://a.test", "wss://b.test" }, null);
    defer gpa.free(uri);
    const client = try TestClient.initBunker(gpa, io, ctx, uri, .{ .timeout_ms = 5000 });
    defer client.deinit();
    try testing.expectEqual(@as(usize, 2), client.relays.len);
    var conn_a = TestConn.init(gpa, io, try hub_a.add());
    defer conn_a.deinit();
    var conn_b = TestConn.init(gpa, io, try hub_b.add());
    defer conn_b.deinit();
    try client.attach(&conn_a);
    try client.attach(&conn_b);
    var reading_a = try io.concurrent(TestClient.run, .{ client, &conn_a, "wss://a.test" });
    var reading_b = try io.concurrent(TestClient.run, .{ client, &conn_b, "wss://b.test" });
    defer {
        hub_a.close();
        hub_b.close();
        _ = reading_a.await(io) catch {};
        _ = reading_b.await(io) catch {};
    }

    try client.connect();
    try client.ping();
    try testing.expectEqualSlices(u8, &remote.public_key, &client.userPubkey().?);

    hub_a.close();
    hub_b.close();
    try serving_a.await(io);
    try serving_b.await(io);
    try reading_a.await(io);
    try reading_b.await(io);
}
