//! The NIP-46 signer-side request-serving loop.
//!
//! EXPERIMENTAL (pre-1.0): the signer-support surface may still change shape.
//!
//! Given an established relay connection and a NIP-46 `nip46.Bunker`, `serve`
//! subscribes for the kind:24133 requests addressed to the signer, decrypts and
//! dispatches each one through the bunker, and publishes the sealed reply back
//! to the requesting client — the user's key never leaves the serving process.
//! This is the transport half of running a signer; the codec, the `Bunker`, and
//! the authorization `Policy` live in `nip46.zig`, and the key-at-rest half in
//! `keystore.zig`.
//!
//! `serve` is generic over the connection type. In production it drives a live
//! `relay.Relay`; in tests it drives an in-memory `relay.Connection` over a
//! scripted fake stream, so the whole request→response cycle is proven
//! hermetically. Relay dialing, fan-out across relays, and reconnection are the
//! caller's job; this is the pure protocol loop over one connection.

const std = @import("std");

const keys = @import("keys.zig");
const nip46 = @import("nip46.zig");
const nip42 = @import("nip42.zig");
const hex = @import("hex.zig");
const event = @import("event.zig");
const filter = @import("filter.zig");
const relay = @import("relay.zig");
const websocket = @import("websocket.zig");

const Event = event.Event;
const Filter = filter.Filter;
const TagFilter = filter.TagFilter;

/// The subscription id the signer opens on each relay.
pub const subscription_id = "nostr-signer";

/// Serves NIP-46 requests over `conn` until the connection closes (a clean
/// relay close or EOF), then returns. `conn` is any established connection
/// exposing `subscribe`, `receive`, and `publish` — the live `relay.Relay` in
/// production, an in-memory `relay.Connection` in tests. `bunker` answers the
/// decrypted requests; `remote` is the signer's communication keypair (the
/// pubkey clients address, and the sender of every reply).
///
/// I/O errors from the relay propagate to the caller (which reconnects);
/// per-request failures (an undecryptable event, a malformed request) are
/// logged and skipped so one bad event can't take the signer down.
pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: anytype,
    bunker: *nip46.Bunker,
    remote: keys.KeyPair,
    relay_url: []const u8,
) !void {
    const my_pubkey_hex = try hex.encode(gpa, &remote.public_key);
    defer gpa.free(my_pubkey_hex);

    // Only requests from now on: ignore any matching history the relay replays
    // before EOSE, so a restart doesn't re-answer stale requests.
    const since = std.Io.Timestamp.now(io, .real).toSeconds();
    const kinds = [_]u16{nip46.kind};
    const p_values = [_][]const u8{my_pubkey_hex};
    const tag_filters = [_]TagFilter{.{ .letter = 'p', .values = &p_values }};
    const filters = [_]Filter{.{ .kinds = &kinds, .tags = &tag_filters, .since = since }};
    try conn.subscribe(subscription_id, &filters);

    // NIP-42: relays that require authentication challenge us before delivering
    // ephemeral events (and reject our publishes). We answer each challenge by
    // signing a kind:22242 event; once the relay accepts it we (re)subscribe,
    // since the initial REQ may have been closed pending auth. `auth_event_id`
    // lets us recognize the OK for our own auth event.
    var auth_event_id: ?[32]u8 = null;

    // Replay defence, per connection. The `since` above is the relay's to
    // enforce and a hostile one simply would not, so freshness is checked here
    // as well.
    var seen: SeenRequests = .{};

    while (true) {
        var msg = (try conn.receive()) orelse break;
        defer msg.deinit();
        switch (msg.value) {
            .event => |e| {
                if (!worthAnswering(io, &seen, e.event)) continue;
                handleRequest(gpa, io, conn, bunker, remote, e.event) catch |err| {
                    std.debug.print("signer: dropped a request: {s}\n", .{@errorName(err)});
                };
            },
            .eose => {},
            .auth => |a| {
                if (authenticate(gpa, io, conn, bunker.signer, remote, relay_url, a.challenge)) |id| {
                    auth_event_id = id;
                    std.debug.print("signer: [{s}] answering NIP-42 auth challenge\n", .{relay_url});
                } else |err| {
                    std.debug.print("signer: [{s}] NIP-42 auth failed: {s}\n", .{ relay_url, @errorName(err) });
                }
            },
            .closed => |c| {
                // "auth-required" is not a real close: the relay is gating the
                // subscription behind NIP-42. We re-subscribe once the auth event
                // is accepted (below), so note it and keep the connection open.
                if (std.mem.startsWith(u8, c.message, "auth-required")) {
                    std.debug.print("signer: [{s}] auth required for the subscription\n", .{relay_url});
                } else {
                    std.debug.print("signer: relay closed the subscription: {s}\n", .{c.message});
                    return;
                }
            },
            .ok => |o| {
                // OK acks our publications. When the relay accepts our auth
                // event, (re)subscribe now that the connection is authenticated;
                // if it rejects it, surface why (a relay-URL or challenge
                // mismatch, an expired timestamp, ...).
                if (auth_event_id) |aid| {
                    if (std.mem.eql(u8, &o.event_id, &aid)) {
                        if (o.accepted) {
                            conn.subscribe(subscription_id, &filters) catch |err| {
                                std.debug.print("signer: [{s}] re-subscribe after auth failed: {s}\n", .{ relay_url, @errorName(err) });
                            };
                        } else {
                            std.debug.print("signer: [{s}] relay rejected NIP-42 auth: {s}\n", .{ relay_url, o.message });
                        }
                        auth_event_id = null; // one attempt per challenge
                    }
                }
            },
            .notice => |n| std.debug.print("signer: relay notice: {s}\n", .{n.message}),
        }
    }
}

/// Signs and sends a NIP-42 authentication event answering `challenge` for
/// `relay_url`, signed with the signer's communication key. Returns the event
/// id so the serve loop can recognize the relay's OK for it.
fn authenticate(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: anytype,
    signer: keys.Signer,
    remote: keys.KeyPair,
    relay_url: []const u8,
    challenge: []const u8,
) ![32]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const created_at = std.Io.Timestamp.now(io, .real).toSeconds();
    const ev = try nip42.authEvent(arena.allocator(), signer, remote, relay_url, challenge, created_at, null);
    try conn.authenticate(ev);
    return ev.id;
}

/// Decrypts one kind:24133 request event addressed to us, runs it through the
/// bunker, and publishes the sealed reply back to the event's author.
/// How far an incoming request's `created_at` may sit from now before the
/// signer refuses it, in seconds.
///
/// NIP-46 requests are interactive: a person is waiting on the other end. Two
/// minutes is generous for clock skew and still small enough that a captured
/// request stops working long before anybody could use it.
pub const max_request_age_s = 120;

/// Ids of requests already answered, so the same sealed event cannot be sent
/// twice.
///
/// kind:24133 is public on the relay, so anyone can subscribe to
/// `{"kinds":[24133],"#p":[<bunker pubkey>]}` and capture a client's sealed
/// request verbatim. They cannot read it, but they can re-publish it, and
/// without this the signer would decrypt and carry it out again. Ephemeral
/// events are not stored, so no relay deduplicates them on the signer's behalf.
///
/// A ring: the oldest is dropped when it is full. The freshness window is what
/// makes that safe, since an id old enough to be evicted is also old enough to
/// be refused outright.
const SeenRequests = struct {
    /// Two minutes of interactive signing does not come close to this.
    const capacity = 256;

    ids: [capacity][32]u8 = undefined,
    len: usize = 0,
    next: usize = 0,

    /// True if `id` was already handled. Records it otherwise.
    fn seenOrRecord(self: *SeenRequests, id: [32]u8) bool {
        for (self.ids[0..self.len]) |known| {
            if (std.mem.eql(u8, &known, &id)) return true;
        }
        self.ids[self.next] = id;
        self.next = (self.next + 1) % capacity;
        if (self.len < capacity) self.len += 1;
        return false;
    }
};

/// Whether this request should be carried out at all: recent, and not one we
/// have already answered.
///
/// Deliberately silent. A rejected replay is exactly what an attacker can send
/// as often as they like, so logging each one would hand them the daemon's
/// console.
fn worthAnswering(io: std.Io, seen: *SeenRequests, request_event: Event) bool {
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const age = if (now > request_event.created_at)
        now - request_event.created_at
    else
        request_event.created_at - now;
    if (age > max_request_age_s) return false;
    return !seen.seenOrRecord(request_event.id);
}

fn handleRequest(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: anytype,
    bunker: *nip46.Bunker,
    remote: keys.KeyPair,
    request_event: Event,
) !void {
    // The client is the event's author; decrypt with our communication key.
    const plaintext = try nip46.open(gpa, bunker.signer, remote.secret_key, request_event);
    defer gpa.free(plaintext);

    var parsed = try nip46.parseRequest(gpa, plaintext);
    defer parsed.deinit();

    const client_hex = try hex.encode(gpa, &request_event.pubkey);
    defer gpa.free(client_hex);

    var response = try bunker.handle(gpa, io, parsed.value, request_event.pubkey);
    defer response.deinit();

    // Audit line: the request, the client, and the authorization outcome.
    const outcome = if (response.value.err.len == 0) "ok" else response.value.err;
    // The method NAME, never the method string. What arrived is arbitrary bytes
    // from a stranger's JSON, and this goes to a terminal: escape sequences in
    // it can clear the screen, rewrite the title, or forge extra plausible
    // "signer: ok 'sign_event' from …" lines. This log is the only place a
    // mis-approval is visible afterwards, so it is not somewhere to print
    // whatever the attacker sent.
    const method_label = if (nip46.Method.fromString(parsed.value.method)) |m|
        m.name()
    else
        "<unsupported>";
    std.debug.print("signer: {s} '{s}' from {s}…\n", .{ outcome, method_label, client_hex[0..16] });

    const response_json = try response.value.toJson(gpa);
    defer gpa.free(response_json);

    const created_at = std.Io.Timestamp.now(io, .real).toSeconds();
    var sealed = try nip46.seal(gpa, io, bunker.signer, remote, request_event.pubkey, response_json, created_at);
    defer sealed.deinit();

    try conn.publish(sealed.event);
}

// ---------------------------------------------------------------------------
// Tests — an in-memory fake stream drives a real Connection end to end: a
// client seals a request, the serve loop answers it, and we decrypt the
// published reply and assert on it. No socket, no relay.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A byte stream that hands the serve loop one scripted server frame (then EOF)
/// and captures everything the loop writes back.
const FakeStream = struct {
    to_read: []const u8,
    read_pos: usize = 0,
    written: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    // `pub` because the generic `Connection` calls these across the module
    // boundary.
    pub fn read(self: *FakeStream, buffer: []u8) error{}!usize {
        const remaining = self.to_read[self.read_pos..];
        const n = @min(buffer.len, remaining.len);
        @memcpy(buffer[0..n], remaining[0..n]);
        self.read_pos += n;
        return n;
    }

    pub fn writeAll(self: *FakeStream, bytes: []const u8) !void {
        try self.written.appendSlice(self.allocator, bytes);
    }
};

/// Appends an unmasked server text frame (as a relay would send), for any length.
fn appendServerText(list: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try list.append(allocator, 0x81); // FIN + text
    if (text.len <= 125) {
        try list.append(allocator, @intCast(text.len));
    } else if (text.len <= 0xffff) {
        try list.append(allocator, 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext, @intCast(text.len), .big);
        try list.appendSlice(allocator, &ext);
    } else {
        try list.append(allocator, 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, &ext, text.len, .big);
        try list.appendSlice(allocator, &ext);
    }
    try list.appendSlice(allocator, text);
}

/// Wraps a NIP-46 request as a relay EVENT frame from `client` to `signer`,
/// runs the serve loop against it, and returns the decrypted reply the loop
/// published. Everything is arena-free; the caller owns `.deinit`.
const Harness = struct {
    signer_ctx: keys.Signer,
    signer_kp: keys.KeyPair,
    client_ctx: keys.Signer,
    client_kp: keys.KeyPair,

    fn init() !Harness {
        const signer_ctx = keys.Signer.init();
        const client_ctx = keys.Signer.init();
        // BIP-340 test-vector secret (known-good) for the signer; a small
        // in-range scalar for the client. Both derive valid x-only pubkeys.
        const signer_sec = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
        var client_sec = [_]u8{0} ** 32;
        client_sec[31] = 3;
        return .{
            .signer_ctx = signer_ctx,
            .signer_kp = try signer_ctx.keyPairFromSecretKey(signer_sec),
            .client_ctx = client_ctx,
            .client_kp = try client_ctx.keyPairFromSecretKey(client_sec),
        };
    }

    fn deinit(self: *Harness) void {
        self.signer_ctx.deinit();
        self.client_ctx.deinit();
    }

    /// Runs `serve` against a single sealed `request` and returns the reply
    /// plaintext JSON the signer published (decrypted with the client key).
    fn roundTrip(self: *Harness, gpa: std.mem.Allocator, io: std.Io, request: nip46.Request) ![]u8 {
        // Client seals the request to the signer's pubkey.
        const req_json = try request.toJson(gpa);
        defer gpa.free(req_json);
        var sealed_req = try nip46.seal(gpa, io, self.client_ctx, self.client_kp, self.signer_kp.public_key, req_json, std.Io.Timestamp.now(io, .real).toSeconds());
        defer sealed_req.deinit();
        const req_event_json = try event.toJson(gpa, sealed_req.event);
        defer gpa.free(req_event_json);

        // Frame it as the relay message the subscription would deliver.
        const relay_msg = try std.fmt.allocPrint(gpa, "[\"EVENT\",\"{s}\",{s}]", .{ subscription_id, req_event_json });
        defer gpa.free(relay_msg);
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(gpa);
        try appendServerText(&script, gpa, relay_msg);

        var written: std.ArrayList(u8) = .empty;
        defer written.deinit(gpa);
        var stream = FakeStream{ .to_read = script.items, .written = &written, .allocator = gpa };
        var conn = relay.Connection(*FakeStream).init(gpa, io, &stream);
        defer conn.deinit();

        var bunker = nip46.Bunker.initSingleKey(self.signer_ctx, self.signer_kp, nip46.approveAll());
        // This client has already connected. The connect handshake itself is
        // covered in nip46.zig; what this loop is being tested for is the
        // serve path, and a bunker now refuses a client it has never seen.
        bunker.authorize(self.client_kp.public_key);
        try serve(gpa, io, &conn, &bunker, self.signer_kp, "wss://relay.test");

        // The loop wrote a REQ then an EVENT; find the published EVENT frame and
        // decrypt its content with the client key.
        const reply_event_json = try findPublishedEvent(gpa, written.items);
        defer gpa.free(reply_event_json);
        var reply_event = try event.fromJson(gpa, reply_event_json);
        defer reply_event.deinit();
        return nip46.open(gpa, self.client_ctx, self.client_kp.secret_key, reply_event.value);
    }
};

/// Scans captured client frames for the `["EVENT",<event>]` publish and returns
/// the inner event JSON object. `written` is mutated in place (frame unmasking).
fn findPublishedEvent(gpa: std.mem.Allocator, written: []u8) ![]u8 {
    var offset: usize = 0;
    while (try websocket.decodeFrame(written[offset..])) |frame| {
        offset += frame.frame_len;
        const prefix = "[\"EVENT\",";
        if (std.mem.startsWith(u8, frame.payload, prefix)) {
            const inner = frame.payload[prefix.len .. frame.payload.len - 1];
            return gpa.dupe(u8, inner);
        }
    }
    return error.NoPublishedEvent;
}

test "serve answers get_public_key over the relay round-trip" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    const reply = try h.roundTrip(gpa, io, .{ .id = "req-1", .method = "get_public_key", .params = &.{} });
    defer gpa.free(reply);

    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();

    try testing.expectEqualStrings("req-1", parsed.value.id);
    try testing.expectEqualStrings("", parsed.value.err);
    const expected_pubkey = try hex.encode(gpa, &h.signer_kp.public_key);
    defer gpa.free(expected_pubkey);
    try testing.expectEqualStrings(expected_pubkey, parsed.value.result);
}

test "serve signs an event and the signature verifies" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    const template = "{\"kind\":1,\"content\":\"gm from a remote signer\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};
    const reply = try h.roundTrip(gpa, io, .{ .id = "sign-1", .method = "sign_event", .params = &params });
    defer gpa.free(reply);

    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();
    try testing.expectEqualStrings("sign-1", parsed.value.id);
    try testing.expectEqualStrings("", parsed.value.err);

    // The result is the signed event; it must carry the signer's key and a
    // signature that verifies against its own recomputed id.
    var signed = try event.fromJson(gpa, parsed.value.result);
    defer signed.deinit();
    try testing.expectEqual(@as(u16, 1), signed.value.kind);
    try testing.expectEqualStrings("gm from a remote signer", signed.value.content);
    try testing.expectEqualSlices(u8, &h.signer_kp.public_key, &signed.value.pubkey);
    try testing.expect(try event.verify(gpa, h.signer_ctx, signed.value));
}

test "serve rejects a request when the policy denies it" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    // A bunker that denies everything must still answer — with an error reply.
    const template = "{\"kind\":1,\"content\":\"nope\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};

    const req_json = try (nip46.Request{ .id = "deny-1", .method = "sign_event", .params = &params }).toJson(gpa);
    defer gpa.free(req_json);
    var sealed_req = try nip46.seal(gpa, io, h.client_ctx, h.client_kp, h.signer_kp.public_key, req_json, std.Io.Timestamp.now(io, .real).toSeconds());
    defer sealed_req.deinit();
    const req_event_json = try event.toJson(gpa, sealed_req.event);
    defer gpa.free(req_event_json);
    const relay_msg = try std.fmt.allocPrint(gpa, "[\"EVENT\",\"{s}\",{s}]", .{ subscription_id, req_event_json });
    defer gpa.free(relay_msg);
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try appendServerText(&script, gpa, relay_msg);

    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(gpa);
    var stream = FakeStream{ .to_read = script.items, .written = &written, .allocator = gpa };
    var conn = relay.Connection(*FakeStream).init(gpa, io, &stream);
    defer conn.deinit();

    var bunker = nip46.Bunker.initSingleKey(h.signer_ctx, h.signer_kp, denyAll());
    try serve(gpa, io, &conn, &bunker, h.signer_kp, "wss://relay.test");

    const reply_event_json = try findPublishedEvent(gpa, written.items);
    defer gpa.free(reply_event_json);
    var reply_event = try event.fromJson(gpa, reply_event_json);
    defer reply_event.deinit();
    const reply = try nip46.open(gpa, h.client_ctx, h.client_kp.secret_key, reply_event.value);
    defer gpa.free(reply);

    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();
    try testing.expectEqualStrings("deny-1", parsed.value.id);
    try testing.expect(parsed.value.err.len > 0);
}

fn denyAllFn(_: ?*anyopaque, _: *const nip46.Request, _: [32]u8) nip46.Decision {
    return .reject;
}

fn denyAll() nip46.Policy {
    return .{ .decideFn = &denyAllFn };
}

test "serve answers a NIP-42 challenge and keeps serving past auth-required" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    // A sealed sign_event request the relay delivers AFTER the auth dance.
    const template = "{\"kind\":1,\"content\":\"hi\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};
    const req_json = try (nip46.Request{ .id = "auth-1", .method = "sign_event", .params = &params }).toJson(gpa);
    defer gpa.free(req_json);
    var sealed_req = try nip46.seal(gpa, io, h.client_ctx, h.client_kp, h.signer_kp.public_key, req_json, std.Io.Timestamp.now(io, .real).toSeconds());
    defer sealed_req.deinit();
    const req_event_json = try event.toJson(gpa, sealed_req.event);
    defer gpa.free(req_event_json);
    const event_msg = try std.fmt.allocPrint(gpa, "[\"EVENT\",\"{s}\",{s}]", .{ subscription_id, req_event_json });
    defer gpa.free(event_msg);

    // Script: the relay challenges (NIP-42), closes the sub as auth-required,
    // then delivers the request (as it would once we're authenticated).
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try appendServerText(&script, gpa, "[\"AUTH\",\"chal-1\"]");
    try appendServerText(&script, gpa, "[\"CLOSED\",\"" ++ subscription_id ++ "\",\"auth-required: authenticate first\"]");
    try appendServerText(&script, gpa, event_msg);

    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(gpa);
    var stream = FakeStream{ .to_read = script.items, .written = &written, .allocator = gpa };
    var conn = relay.Connection(*FakeStream).init(gpa, io, &stream);
    defer conn.deinit();

    var bunker = nip46.Bunker.initSingleKey(h.signer_ctx, h.signer_kp, nip46.approveAll());
    bunker.authorize(h.client_kp.public_key);
    try serve(gpa, io, &conn, &bunker, h.signer_kp, "wss://relay.test");

    // Walk the client frames once: it must have written a kind:22242 AUTH reply
    // to the challenge, AND (not aborting on auth-required) a sealed response to
    // the request that followed.
    var authed = false;
    var reply_json: ?[]u8 = null;
    defer if (reply_json) |r| gpa.free(r);
    var offset: usize = 0;
    while (try websocket.decodeFrame(written.items[offset..])) |frame| {
        offset += frame.frame_len;
        if (std.mem.startsWith(u8, frame.payload, "[\"AUTH\",")) {
            try testing.expect(std.mem.indexOf(u8, frame.payload, "\"kind\":22242") != null);
            try testing.expect(std.mem.indexOf(u8, frame.payload, "wss://relay.test") != null);
            try testing.expect(std.mem.indexOf(u8, frame.payload, "chal-1") != null);
            authed = true;
        } else if (std.mem.startsWith(u8, frame.payload, "[\"EVENT\",") and reply_json == null) {
            reply_json = try gpa.dupe(u8, frame.payload["[\"EVENT\",".len .. frame.payload.len - 1]);
        }
    }
    try testing.expect(authed);

    var reply_event = try event.fromJson(gpa, reply_json orelse return error.NoReply);
    defer reply_event.deinit();
    const reply = try nip46.open(gpa, h.client_ctx, h.client_kp.secret_key, reply_event.value);
    defer gpa.free(reply);
    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();
    try testing.expectEqualStrings("auth-1", parsed.value.id);
    try testing.expectEqualStrings("", parsed.value.err);
}

test "a replayed request is not answered twice, and a stale one is not answered at all" {
    // kind:24133 is public, so anyone can capture a client's sealed request off
    // the relay. They cannot read it, but re-publishing it used to make the
    // signer carry it out again: ephemeral events are not stored, so no relay
    // deduplicates them, and the signer kept no record.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var seen: SeenRequests = .{};
    const now = std.Io.Timestamp.now(io, .real).toSeconds();

    const fresh = Event{ .id = [_]u8{0xab} ** 32, .pubkey = [_]u8{1} ** 32, .created_at = now, .kind = nip46.kind, .tags = &.{}, .content = "", .sig = [_]u8{0} ** 64 };
    try testing.expect(worthAnswering(io, &seen, fresh));
    // The same sealed event, sent again.
    try testing.expect(!worthAnswering(io, &seen, fresh));

    // Captured earlier in the session and held: refused on age alone, so it
    // does not matter whether the id is still in the ring.
    var stale = fresh;
    stale.id = [_]u8{0xcd} ** 32;
    stale.created_at = now - (max_request_age_s + 1);
    try testing.expect(!worthAnswering(io, &seen, stale));

    // A clock running ahead is refused the same way, in the other direction.
    var future = fresh;
    future.id = [_]u8{0xef} ** 32;
    future.created_at = now + (max_request_age_s + 1);
    try testing.expect(!worthAnswering(io, &seen, future));

    // Eviction cannot resurrect a request: the ring holds far more than the
    // freshness window admits, and anything evicted is already too old.
    for (0..SeenRequests.capacity) |i| {
        var filler = fresh;
        filler.id = [_]u8{0} ** 32;
        filler.id[0] = @intCast(i % 256);
        filler.id[1] = @intCast(i / 256);
        _ = worthAnswering(io, &seen, filler);
    }
    try testing.expectEqual(SeenRequests.capacity, seen.len);
}
