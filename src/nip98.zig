//! NIP-98 HTTP authentication.
//!
//! A client proves it controls a key to an HTTP server by signing an
//! ephemeral `kind:27235` event naming the absolute URL and method of the
//! request (and, for requests with a body, the sha256 of that body), then
//! sending it in the `Authorization` header as `Nostr <base64(event json)>`.
//!
//! This module builds that event and header, decodes a header, and checks one
//! on the server side. There is no HTTP transport here: the caller owns the
//! request and the clock.

const std = @import("std");
const event = @import("event.zig");
const hex = @import("hex.zig");
const keys = @import("keys.zig");

/// The NIP-98 HTTP auth event kind.
pub const kind: u16 = 27235;

/// The scheme prefix of the `Authorization` header value.
pub const scheme = "Nostr ";

/// How far `created_at` may sit from the verifier's clock, in seconds, when
/// the caller does not choose a window. NIP-98 suggests a short one.
pub const default_window_secs: i64 = 60;

/// sha256 of a request body, the value of the `payload` tag (as hex).
pub fn payloadHash(body: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &out, .{});
    return out;
}

/// Builds and signs the `kind:27235` event for one request. `payload` is the
/// sha256 of the body, or null for a request without one. The event borrows
/// `url` and `method` and owns its tag slices, allocated from `allocator`;
/// build it in an arena.
pub fn authEvent(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    url: []const u8,
    method: []const u8,
    payload: ?[32]u8,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error)!event.Event {
    const count: usize = if (payload != null) 3 else 2;
    const tags = try allocator.alloc(event.Tag, count);
    tags[0] = try tag2(allocator, "u", url);
    tags[1] = try tag2(allocator, "method", method);
    if (payload) |p| tags[2] = try tag2(allocator, "payload", try hex.encode(allocator, &p));
    return event.create(allocator, signer, keypair, created_at, kind, tags, "", aux_rand);
}

fn tag2(allocator: std.mem.Allocator, name: []const u8, value: []const u8) std.mem.Allocator.Error!event.Tag {
    const t = try allocator.alloc([]const u8, 2);
    t[0] = name;
    t[1] = value;
    return t;
}

/// Encodes a signed event as an `Authorization` header value:
/// `Nostr <base64 of the event JSON>`. Caller frees. Shared with Blossom.
pub fn encodeHeader(allocator: std.mem.Allocator, ev: event.Event) std.mem.Allocator.Error![]u8 {
    const json_text = try event.toJson(allocator, ev);
    defer allocator.free(json_text);
    const enc = std.base64.standard.Encoder;
    const out = try allocator.alloc(u8, scheme.len + enc.calcSize(json_text.len));
    @memcpy(out[0..scheme.len], scheme);
    _ = enc.encode(out[scheme.len..], json_text);
    return out;
}

/// Builds the whole header for a request. When `body` is non-null its sha256
/// goes in the `payload` tag. Caller frees.
pub fn authHeader(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    url: []const u8,
    method: []const u8,
    body: ?[]const u8,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error)![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const payload: ?[32]u8 = if (body) |b| payloadHash(b) else null;
    const ev = try authEvent(arena_state.allocator(), signer, keypair, created_at, url, method, payload, aux_rand);
    return encodeHeader(allocator, ev);
}

pub const DecodeError = error{
    /// The value does not start with `Nostr ` or its base64 is invalid.
    MalformedHeader,
} || event.Error;

/// Decodes an `Authorization` header value into the event it carries. The
/// result owns an arena; call `deinit`. The signature is not checked here.
pub fn decodeHeader(gpa: std.mem.Allocator, header: []const u8) DecodeError!event.Parsed {
    if (header.len <= scheme.len or !std.ascii.eqlIgnoreCase(header[0..scheme.len], scheme))
        return error.MalformedHeader;
    const b64 = std.mem.trim(u8, header[scheme.len..], " ");
    const dec = std.base64.standard.Decoder;
    const size = dec.calcSizeForSlice(b64) catch return error.MalformedHeader;

    // The parsed event borrows from the decoded JSON text, so the text lives
    // in the same arena as the event.
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const raw = try a.alloc(u8, size);
    dec.decode(raw, b64) catch return error.MalformedHeader;
    const value = std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    if (value != .object) return error.InvalidJson;
    const ev = event.fromValueLeaky(a, value) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidHex => return error.InvalidHex,
        else => return error.InvalidJson,
    };
    return .{ .arena = arena, .value = ev };
}

pub const VerifyError = error{
    WrongKind,
    BadSignature,
    /// `created_at` is outside the allowed window around `now`.
    Expired,
    MissingTag,
    UrlMismatch,
    MethodMismatch,
    /// The body was given but the event has no `payload` tag.
    MissingPayload,
    PayloadMismatch,
} || std.mem.Allocator.Error;

pub const VerifyOptions = struct {
    /// The absolute URL the server received the request on.
    url: []const u8,
    /// The HTTP method, upper case.
    method: []const u8,
    /// The request body. When non-null the event must carry a matching
    /// `payload` tag; when null the tag is not checked.
    body: ?[]const u8 = null,
    /// The verifier's clock, unix seconds.
    now: i64,
    window_secs: i64 = default_window_secs,
};

/// Checks an event against one request: signature, kind, freshness, `u`,
/// `method` and (when a body is given) `payload`.
pub fn verify(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    ev: event.Event,
    opts: VerifyOptions,
) VerifyError!void {
    if (ev.kind != kind) return error.WrongKind;
    if (!try event.verify(allocator, signer, ev)) return error.BadSignature;
    const delta = ev.created_at - opts.now;
    if (delta > opts.window_secs or -delta > opts.window_secs) return error.Expired;

    const u = tagValue(ev, "u") orelse return error.MissingTag;
    if (!std.mem.eql(u8, u, opts.url)) return error.UrlMismatch;
    const m = tagValue(ev, "method") orelse return error.MissingTag;
    if (!std.mem.eql(u8, m, opts.method)) return error.MethodMismatch;

    if (opts.body) |body| {
        const p = tagValue(ev, "payload") orelse return error.MissingPayload;
        const want = payloadHash(body);
        const got = hex.decodeFixed(32, p) catch return error.PayloadMismatch;
        if (!std.mem.eql(u8, &want, &got)) return error.PayloadMismatch;
    }
}

/// Decodes a header and verifies it; returns the signer's public key.
pub fn verifyHeader(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    header: []const u8,
    opts: VerifyOptions,
) (VerifyError || DecodeError)!keys.PublicKey {
    var parsed = try decodeHeader(allocator, header);
    defer parsed.deinit();
    try verify(allocator, signer, parsed.value, opts);
    return parsed.value.pubkey;
}

fn tagValue(ev: event.Event, name: []const u8) ?[]const u8 {
    for (ev.tags) |t| {
        if (t.len >= 2 and std.mem.eql(u8, t[0], name)) return t[1];
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testKey(signer: keys.Signer) !keys.KeyPair {
    const secret = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    return signer.keyPairFromSecretKey(secret);
}

const test_url = "https://api.example.com/upload?x=1";
const now: i64 = 1_700_000_000;

test "nip98: header round trips and verifies" {
    const gpa = testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);

    const header = try authHeader(gpa, signer, kp, now, test_url, "POST", "hello body", null);
    defer gpa.free(header);
    try testing.expect(std.mem.startsWith(u8, header, "Nostr "));

    var parsed = try decodeHeader(gpa, header);
    defer parsed.deinit();
    const ev = parsed.value;
    try testing.expectEqual(@as(u16, 27235), ev.kind);
    try testing.expectEqualStrings("", ev.content);
    try testing.expectEqualStrings("u", ev.tags[0][0]);
    try testing.expectEqualStrings(test_url, ev.tags[0][1]);
    try testing.expectEqualStrings("POST", ev.tags[1][1]);
    try testing.expectEqual(@as(usize, 3), ev.tags.len);

    const pk = try verifyHeader(gpa, signer, header, .{ .url = test_url, .method = "POST", .body = "hello body", .now = now + 10 });
    try testing.expectEqualSlices(u8, &kp.public_key, &pk);
}

test "nip98: no payload tag without a body" {
    const gpa = testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);
    const header = try authHeader(gpa, signer, kp, now, test_url, "GET", null, null);
    defer gpa.free(header);
    var parsed = try decodeHeader(gpa, header);
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.value.tags.len);
    _ = try verifyHeader(gpa, signer, header, .{ .url = test_url, .method = "GET", .now = now });
    try testing.expectError(error.MissingPayload, verifyHeader(gpa, signer, header, .{ .url = test_url, .method = "GET", .body = "x", .now = now }));
}

test "nip98: verifier rejects mismatches" {
    const gpa = testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);
    const header = try authHeader(gpa, signer, kp, now, test_url, "POST", "body", null);
    defer gpa.free(header);

    const base: VerifyOptions = .{ .url = test_url, .method = "POST", .body = "body", .now = now };
    try testing.expectError(error.MethodMismatch, verifyHeader(gpa, signer, header, .{ .url = test_url, .method = "GET", .body = "body", .now = now }));
    try testing.expectError(error.UrlMismatch, verifyHeader(gpa, signer, header, .{ .url = "https://api.example.com/other", .method = "POST", .body = "body", .now = now }));
    try testing.expectError(error.PayloadMismatch, verifyHeader(gpa, signer, header, .{ .url = test_url, .method = "POST", .body = "other", .now = now }));
    var late = base;
    late.now = now + 61;
    try testing.expectError(error.Expired, verifyHeader(gpa, signer, header, late));
    var early = base;
    early.now = now - 61;
    try testing.expectError(error.Expired, verifyHeader(gpa, signer, header, early));
    var wide = base;
    wide.now = now + 61;
    wide.window_secs = 120;
    _ = try verifyHeader(gpa, signer, header, wide);
}

test "nip98: verifier rejects wrong kind and bad signature" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);

    var ev = try authEvent(arena, signer, kp, now, test_url, "GET", null, null);
    const opts: VerifyOptions = .{ .url = test_url, .method = "GET", .now = now };
    try verify(arena, signer, ev, opts);

    var tampered = ev;
    tampered.sig[0] ^= 1;
    try testing.expectError(error.BadSignature, verify(arena, signer, tampered, opts));

    ev.kind = 1;
    try testing.expectError(error.WrongKind, verify(arena, signer, ev, opts));
}

test "nip98: malformed headers are refused" {
    const gpa = testing.allocator;
    try testing.expectError(error.MalformedHeader, decodeHeader(gpa, "Bearer abc"));
    try testing.expectError(error.MalformedHeader, decodeHeader(gpa, "Nostr !!!"));
    try testing.expectError(error.InvalidJson, decodeHeader(gpa, "Nostr aGVsbG8="));
}
