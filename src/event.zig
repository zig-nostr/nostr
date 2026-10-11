//! NIP-01 event model: the `Event` struct, canonical serialization for id
//! hashing, and wire-format JSON encode/decode.

const std = @import("std");
const hex = @import("hex.zig");
const keys = @import("keys.zig");
const scan = @import("scan.zig");

pub const Error = error{
    InvalidJson,
    InvalidHex,
    InvalidLength,
} || std.mem.Allocator.Error;

/// A single tag: an array of one or more strings (name + arbitrary fields).
pub const Tag = []const []const u8;

pub const Event = struct {
    id: [32]u8,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
    sig: [64]u8,
};

// -- Serialization ------------------------------------------------------------
//
// Every serializer below writes through a `std.Io.Writer`, so the same code
// fills a caller's buffer (`Writer.fixed`), an exactly sized allocation, or a
// SHA-256 state with a small stack buffer in front of it, which is how
// `computeId` hashes an event without allocating. The `...Len` functions
// return the exact byte count the matching writer produces, so a caller can
// size a buffer before writing into it.

const Writer = std.Io.Writer;

const nextSpecial = scan.nextSpecial;

/// The escape for a byte `nextSpecial` stopped at. A six-byte buffer holds
/// the longest, `\u00XX`.
fn escapeFor(c: u8, buf: *[6]u8) []const u8 {
    const short: u8 = switch (c) {
        '\n' => 'n',
        '"' => '"',
        '\\' => '\\',
        '\r' => 'r',
        '\t' => 't',
        0x08 => 'b',
        0x0C => 'f',
        else => 0,
    };
    buf[0] = '\\';
    if (short != 0) {
        buf[1] = short;
        return buf[0..2];
    }
    buf[1..4].* = "u00".*;
    buf[4] = hex_digits[c >> 4];
    buf[5] = hex_digits[c & 0xf];
    return buf[0..6];
}

fn escapedLen(s: []const u8) usize {
    var n: usize = s.len + 2;
    var i = nextSpecial(s, 0);
    while (i < s.len) : (i = nextSpecial(s, i + 1)) {
        n += switch (s[i]) {
            '\n', '"', '\\', '\r', '\t', 0x08, 0x0C => 1,
            else => 5,
        };
    }
    return n;
}

/// Writes `s` as a quoted JSON string, escaped the way the id serialization
/// needs.
///
/// NIP-01 names seven escapes (`\n \" \\ \r \t \b \f`) and says all other
/// characters must be included verbatim. Read literally that leaves a byte
/// below 0x20 sitting raw inside a JSON string, and RFC 8259 forbids exactly
/// that, so the wire form would not be JSON and no relay could parse it.
///
/// The sentence also does not describe what the network does. nostr-tools
/// builds the preimage with `JSON.stringify` and go-nostr writes the same
/// behaviour by hand in `escapeString`, so both escape every remaining
/// control byte as `\u00XX`. Following the sentence instead of the
/// implementations produces an id nothing else reproduces, which turns a
/// correctly signed event from any JS or Go client into a bad signature here
/// and makes our own ids unverifiable everywhere else.
///
/// So the remaining control bytes are escaped as `\u00XX`. Everything from
/// 0x20 up, raw UTF-8 included, is still copied verbatim, which is where the
/// warning against a general-purpose encoder still holds: escaping non-ASCII
/// would change the id. The wire JSON wants the same bytes.
fn writeJsonString(w: *Writer, s: []const u8) Writer.Error!void {
    try w.writeByte('"');
    var start: usize = 0;
    var i = nextSpecial(s, 0);
    var esc: [6]u8 = undefined;
    while (i < s.len) : (i = nextSpecial(s, start)) {
        try w.writeAll(s[start..i]);
        try w.writeAll(escapeFor(s[i], &esc));
        start = i + 1;
    }
    try w.writeAll(s[start..]);
    try w.writeByte('"');
}

const hex_digits = "0123456789abcdef";

fn writeHex(w: *Writer, comptime n: usize, bytes: *const [n]u8) Writer.Error!void {
    var out: [n * 2]u8 = undefined;
    for (bytes, 0..) |b, i| {
        out[2 * i] = hex_digits[b >> 4];
        out[2 * i + 1] = hex_digits[b & 0xf];
    }
    try w.writeAll(&out);
}

/// Decimal digits of `v`, written from the back of `buf`.
fn intDigits(v: i64, buf: *[20]u8) []const u8 {
    var mag: u64 = @abs(v);
    var i: usize = buf.len;
    while (true) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(mag % 10));
        mag /= 10;
        if (mag == 0) break;
    }
    if (v < 0) {
        i -= 1;
        buf[i] = '-';
    }
    return buf[i..];
}

fn intLen(v: i64) usize {
    var buf: [20]u8 = undefined;
    return intDigits(v, &buf).len;
}

fn writeInt(w: *Writer, v: i64) Writer.Error!void {
    var buf: [20]u8 = undefined;
    try w.writeAll(intDigits(v, &buf));
}

fn tagsLen(tags: []const Tag) usize {
    var n: usize = 2;
    for (tags, 0..) |tag, ti| {
        n += @as(usize, @intFromBool(ti != 0)) + 2;
        for (tag, 0..) |field, fi| n += @as(usize, @intFromBool(fi != 0)) + escapedLen(field);
    }
    return n;
}

fn writeTags(w: *Writer, tags: []const Tag) Writer.Error!void {
    try w.writeByte('[');
    for (tags, 0..) |tag, ti| {
        if (ti != 0) try w.writeByte(',');
        try w.writeByte('[');
        for (tag, 0..) |field, fi| {
            if (fi != 0) try w.writeByte(',');
            try writeJsonString(w, field);
        }
        try w.writeByte(']');
    }
    try w.writeByte(']');
}

/// The exact length of the canonical serialization `writeCanonical` writes.
pub fn canonicalLen(created_at: i64, kind: u16, tags: []const Tag, content: []const u8) usize {
    // `[0,"` + 64 hex + `",` + created_at + `,` + kind + `,` + tags + `,` + content + `]`
    return 4 + 64 + 2 + intLen(created_at) + 1 + intLen(kind) + 1 + tagsLen(tags) + 1 + escapedLen(content) + 1;
}

/// Writes the canonical `[0,pubkey,created_at,kind,tags,content]`
/// serialization (used only for id hashing, per NIP-01) to `w`. With
/// `Writer.fixed` over a buffer of `canonicalLen` bytes it allocates nothing.
pub fn writeCanonical(
    w: *Writer,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) Writer.Error!void {
    try w.writeAll("[0,\"");
    try writeHex(w, 32, &pubkey);
    try w.writeAll("\",");
    try writeInt(w, created_at);
    try w.writeByte(',');
    try writeInt(w, kind);
    try w.writeByte(',');
    try writeTags(w, tags);
    try w.writeByte(',');
    try writeJsonString(w, content);
    try w.writeByte(']');
}

/// Appends the canonical `[0,pubkey,created_at,kind,tags,content]`
/// serialization (used only for id hashing, per NIP-01) to `list`.
pub fn appendCanonical(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error!void {
    const len = canonicalLen(created_at, kind, tags, content);
    try list.ensureUnusedCapacity(allocator, len);
    var w: Writer = .fixed(list.unusedCapacitySlice()[0..len]);
    writeCanonical(&w, pubkey, created_at, kind, tags, content) catch unreachable;
    list.items.len += len;
}

/// Returns the owned canonical serialization bytes (for inspection/testing).
pub fn serializeCanonical(
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, canonicalLen(created_at, kind, tags, content));
    var w: Writer = .fixed(out);
    writeCanonical(&w, pubkey, created_at, kind, tags, content) catch unreachable;
    return out;
}

/// Computes the NIP-01 event id: sha256 of the canonical serialization.
///
/// The serialization streams through a stack buffer into the hash, so this
/// allocates nothing; `allocator` is kept for the signature callers already
/// use, and the error set with it.
pub fn computeId(
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error![32]u8 {
    _ = allocator;
    return idOf(pubkey, created_at, kind, tags, content);
}

fn idOf(pubkey: [32]u8, created_at: i64, kind: u16, tags: []const Tag, content: []const u8) [32]u8 {
    var buf: [1024]u8 = undefined;
    var hashing: Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buf);
    // The hashing writer's drain cannot fail.
    writeCanonical(&hashing.writer, pubkey, created_at, kind, tags, content) catch unreachable;
    hashing.writer.flush() catch unreachable;
    var id: [32]u8 = undefined;
    hashing.hasher.final(&id);
    return id;
}

/// Builds and signs an event: computes the canonical id from `keypair`'s
/// public key and the given fields, then signs that id with `keypair`'s
/// secret key. `aux_rand`, when provided, is 32 bytes of fresh randomness
/// (recommended — see `keys.Signer.sign`).
pub fn create(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error)!Event {
    const id = try computeId(allocator, keypair.public_key, created_at, kind, tags, content);
    const sig = try signer.signId(id, keypair, aux_rand);
    return Event{
        .id = id,
        .pubkey = keypair.public_key,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
        .sig = sig,
    };
}

/// Verifies an event: recomputes the canonical id from its fields (rejecting
/// any event whose `id` doesn't match its own content — a forged or
/// corrupted id), then verifies `sig` against that id and `pubkey`.
pub fn verify(allocator: std.mem.Allocator, signer: keys.Signer, ev: Event) std.mem.Allocator.Error!bool {
    const computed_id = try computeId(allocator, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    if (!std.mem.eql(u8, &computed_id, &ev.id)) return false;
    return signer.verifyId(ev.sig, ev.id, ev.pubkey);
}

const json_id = "{\"id\":\"";
const json_pubkey = "\",\"pubkey\":\"";
const json_created_at = "\",\"created_at\":";
const json_kind = ",\"kind\":";
const json_tags = ",\"tags\":";
const json_content = ",\"content\":";
const json_sig = ",\"sig\":\"";
const json_end = "\"}";

/// The exact length of the wire JSON `writeJson` writes.
pub fn jsonLen(event: Event) usize {
    return json_id.len + 64 + json_pubkey.len + 64 + json_created_at.len + intLen(event.created_at) +
        json_kind.len + intLen(event.kind) + json_tags.len + tagsLen(event.tags) +
        json_content.len + escapedLen(event.content) + json_sig.len + 128 + json_end.len;
}

/// Writes a full `Event` as wire-format JSON (`{"id":...,...}`) to `w`. With
/// `Writer.fixed` over a buffer of `jsonLen` bytes it allocates nothing.
pub fn writeJson(w: *Writer, event: Event) Writer.Error!void {
    try w.writeAll(json_id);
    try writeHex(w, 32, &event.id);
    try w.writeAll(json_pubkey);
    try writeHex(w, 32, &event.pubkey);
    try w.writeAll(json_created_at);
    try writeInt(w, event.created_at);
    try w.writeAll(json_kind);
    try writeInt(w, event.kind);
    try w.writeAll(json_tags);
    try writeTags(w, event.tags);
    try w.writeAll(json_content);
    try writeJsonString(w, event.content);
    try w.writeAll(json_sig);
    try writeHex(w, 64, &event.sig);
    try w.writeAll(json_end);
}

/// Serializes a full `Event` to wire-format JSON (`{"id":...,...}`), in one
/// allocation of exactly the right size.
pub fn toJson(allocator: std.mem.Allocator, event: Event) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, jsonLen(event));
    var w: Writer = .fixed(out);
    writeJson(&w, event) catch unreachable;
    return out;
}

/// The seven fields NIP-01 names. An event object may carry other keys beside
/// them (some relays and clients add their own), and they are skipped rather
/// than refused: the id and the signature cover these seven and nothing else,
/// so an extra key cannot change what was signed. A key named twice is still
/// refused, because then it is ambiguous which value the signature covers.
const WireEvent = struct {
    id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    kind: u16,
    tags: []const []const []const u8,
    content: []const u8,
    sig: []const u8,
};

const wire_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };

pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    value: Event,

    pub fn deinit(self: *Parsed) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses wire-format event JSON. The returned `Parsed` owns every byte the
/// Parses wire-format event JSON. The returned `Parsed` owns every byte the
/// event points at, in one arena, so `json_text` may be freed or reused as soon
/// as this returns. Call `deinit` to free it.
///
/// The text is copied into the arena once and read by `scan.event`, which
/// decodes each string in place in that copy and builds the event without a
/// JSON tree. Anything it does not take on the first pass (a missing or
/// repeated field, a number written as `1e3`, bad hex, malformed JSON) is
/// parsed again by `std.json`, so what is accepted and every error returned
/// are exactly what the `std.json` path alone gives.
pub fn fromJson(gpa: std.mem.Allocator, json_text: []const u8) !Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    const owned_text = try allocator.dupe(u8, json_text);
    if (scan.event(allocator, owned_text)) |ev| {
        return .{ .arena = arena, .value = ev };
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unsupported => {},
    }

    // The scan decoded strings in place, so the copy is no longer the text.
    _ = arena.reset(.retain_capacity);
    const fresh = try allocator.dupe(u8, json_text);
    const wire = try std.json.parseFromSliceLeaky(WireEvent, allocator, fresh, wire_options);
    return .{ .arena = arena, .value = try fromWire(wire) };
}

/// Builds an `Event` from an already-parsed `std.json.Value` (which must be a
/// JSON object) into `allocator`. The returned event borrows string/tag
/// storage from `allocator`, so it must be arena-like and outlive the event.
///
/// This is the entry point the relay-message parser uses: a relay `EVENT`
/// message is a JSON array whose third element is the event object, and the
/// whole message shares one arena, so re-serializing just to call `fromJson`
/// would be wasteful.
pub fn fromValueLeaky(allocator: std.mem.Allocator, value: std.json.Value) !Event {
    // `std.json` bounds a float against `maxInt(i64)` converted to a float,
    // which rounds up to 2^63, so a `created_at` of exactly 2^63 written as a
    // float (`9223372036854775808.0`, `9.223372036854775807e18`) passes the
    // check and then fails the conversion: a panic in a safe build. It is out
    // of range, so say so first.
    if (value == .object) if (value.object.get("created_at")) |v| {
        if (v == .float and v.float >= 0x1p63) return error.Overflow;
    };
    const wire = try std.json.parseFromValueLeaky(WireEvent, allocator, value, wire_options);
    return fromWire(wire);
}

/// Converts the parsed wire representation into an `Event`, decoding the hex
/// id/pubkey/sig fields. Shared by `fromJson` and `fromValueLeaky`.
fn fromWire(wire: WireEvent) hex.Error!Event {
    return Event{
        .id = try hex.decodeFixed(32, wire.id),
        .pubkey = try hex.decodeFixed(32, wire.pubkey),
        .created_at = wire.created_at,
        .kind = wire.kind,
        .tags = wire.tags,
        .content = wire.content,
        .sig = try hex.decodeFixed(64, wire.sig),
    };
}

fn hexToBytes32(h: []const u8) ![32]u8 {
    return hex.decodeFixed(32, h);
}

test "canonical serialization matches a hand-computed vector" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca");
    const tags = [_]Tag{&[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" }};
    const content = "Hello, \"world\"!\n";

    const serialized = try serializeCanonical(allocator, pubkey, 1700000000, 1, &tags, content);
    defer allocator.free(serialized);

    const expected = "[0,\"f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca\",1700000000,1,[[\"e\",\"5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36\",\"wss://nostr.example.com\"]],\"Hello, \\\"world\\\"!\\n\"]";
    try std.testing.expectEqualStrings(expected, serialized);

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const expected_id = try hexToBytes32("d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40");
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}

test "canonical serialization: empty tags, mixed escapes" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const tags = [_]Tag{};
    const content = "line1\\nline2\ttab\r\n";

    const id = try computeId(allocator, pubkey, 0, 0, &tags, content);
    const expected_id = try hexToBytes32("06e17cd2f072210550eba01397803e32f3b035cb01b5400665fa282f09060106");
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}

test "control bytes escape the way the rest of the network escapes them" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const tags = [_]Tag{&[_][]const u8{ "e", "a\x02b" }};
    const content = "a\x01b\x1bc";

    // These bytes are what `JSON.stringify` produces, which is how nostr-tools
    // builds the preimage and what go-nostr's `escapeString` writes by hand.
    // Derived from an independent implementation rather than from this code, so
    // it fails if this file ever drifts back to the spec's literal wording.
    const serialized = try serializeCanonical(allocator, pubkey, 1700000000, 1, &tags, content);
    defer allocator.free(serialized);
    const expected = "[0,\"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\",1700000000,1,[[\"e\",\"a\\u0002b\"]],\"a\\u0001b\\u001bc\"]";
    try std.testing.expectEqualStrings(expected, serialized);

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const expected_id = try hexToBytes32("d70263901ff294ef8559ce5626d7c3b216877255385fb23ba00c4b60d583fd00");
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}

test "an event carrying control bytes survives its own wire format" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const tags = [_]Tag{&[_][]const u8{ "e", "a\x02b" }};
    const content = "a\x01b\x1bc";

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const event = Event{
        .id = id,
        .pubkey = pubkey,
        .created_at = 1700000000,
        .kind = 1,
        .tags = &tags,
        .content = content,
        .sig = [_]u8{0xab} ** 64,
    };

    const json_text = try toJson(allocator, event);
    defer allocator.free(json_text);

    // The point of the test: the wire form used to carry the control bytes raw,
    // which is not JSON, so this parse failed on our own output.
    try std.testing.expect(std.mem.indexOfScalar(u8, json_text, 0x01) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, json_text, 0x1b) == null);

    var parsed = try fromJson(allocator, json_text);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(content, parsed.value.content);
    try std.testing.expectEqualStrings("a\x02b", parsed.value.tags[0][1]);
    try std.testing.expectEqualSlices(u8, &event.id, &parsed.value.id);
}

test "toJson / fromJson round trip" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca");
    const tags = [_]Tag{&[_][]const u8{ "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" }};
    const content = "hello";

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const event = Event{
        .id = id,
        .pubkey = pubkey,
        .created_at = 1700000000,
        .kind = 1,
        .tags = &tags,
        .content = content,
        .sig = [_]u8{0xab} ** 64,
    };

    const json_text = try toJson(allocator, event);
    defer allocator.free(json_text);

    var parsed = try fromJson(allocator, json_text);
    defer parsed.deinit();

    try std.testing.expectEqualSlices(u8, &event.id, &parsed.value.id);
    try std.testing.expectEqualSlices(u8, &event.pubkey, &parsed.value.pubkey);
    try std.testing.expectEqual(event.created_at, parsed.value.created_at);
    try std.testing.expectEqual(event.kind, parsed.value.kind);
    try std.testing.expectEqualStrings(event.content, parsed.value.content);
    try std.testing.expectEqualSlices(u8, &event.sig, &parsed.value.sig);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.tags.len);
    try std.testing.expectEqualStrings("p", parsed.value.tags[0][0]);
}

test "fromJson rejects malformed hex id" {
    const allocator = std.testing.allocator;
    const bad = "{\"id\":\"zz\",\"pubkey\":\"" ++ "00" ** 32 ++ "\",\"created_at\":0,\"kind\":0,\"tags\":[],\"content\":\"\",\"sig\":\"" ++ "00" ** 64 ++ "\"}";
    try std.testing.expectError(hex.Error.InvalidHex, fromJson(allocator, bad));
}

test "an event carrying a field NIP-01 does not name still parses and verifies" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    const tags = [_]Tag{&[_][]const u8{ "t", "zig" }};
    const ev = try create(allocator, signer, kp, 1700000000, 1, &tags, "hello", null);
    const wire = try toJson(allocator, ev);
    defer allocator.free(wire);

    // The id and signature cover the seven named fields and nothing else, so
    // a key beside them, of any shape, changes nothing about the event.
    const extra = try std.mem.concat(allocator, u8, &.{
        "{\"relays\":[\"wss://relay.example\"],\"meta\":{\"n\":[1,{\"x\":null}]},",
        wire[1..],
    });
    defer allocator.free(extra);

    var parsed = try fromJson(allocator, extra);
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, &ev.id, &parsed.value.id);
    try std.testing.expectEqualStrings("hello", parsed.value.content);
    try std.testing.expect(try verify(allocator, signer, parsed.value));

    // Written back out, it is the event that was signed, without the extra key.
    const again = try toJson(allocator, parsed.value);
    defer allocator.free(again);
    try std.testing.expectEqualStrings(wire, again);
}

test "a parsed event outlives the text it was parsed from" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    // Unescaped strings are the ones a parser can hand back as slices of its
    // input, and the escaped content is the one it cannot, so both kinds are
    // here.
    const tags = [_]Tag{
        &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example" },
        &[_][]const u8{ "t", "zig" },
    };
    const ev = try create(allocator, signer, kp, 1700000000, 1, &tags, "plain words", null);
    const wire = try toJson(allocator, ev);
    defer allocator.free(wire);

    const text = try allocator.dupe(u8, wire);
    var parsed = parsed: {
        // Overwrite the text before freeing it as well, so the test does not
        // depend on what the allocator does with freed memory.
        defer {
            @memset(text, 'x');
            allocator.free(text);
        }
        break :parsed try fromJson(allocator, text);
    };
    defer parsed.deinit();

    try std.testing.expectEqualStrings("plain words", parsed.value.content);
    try std.testing.expectEqualStrings("zig", parsed.value.tags[1][1]);
    try std.testing.expect(try verify(allocator, signer, parsed.value));
    const again = try toJson(allocator, parsed.value);
    defer allocator.free(again);
    try std.testing.expectEqualStrings(wire, again);
}

test "an event naming the same field twice is still refused" {
    const allocator = std.testing.allocator;
    // Two contents make it ambiguous which one the signature covers.
    const twice = "{\"id\":\"" ++ "00" ** 32 ++ "\",\"pubkey\":\"" ++ "00" ** 32 ++ "\",\"created_at\":0,\"kind\":1,\"tags\":[],\"content\":\"a\",\"content\":\"b\",\"sig\":\"" ++ "00" ** 64 ++ "\"}";
    try std.testing.expectError(error.DuplicateField, fromJson(allocator, twice));
}

test "create produces a valid, self-consistent, verifiable event" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    const tags = [_]Tag{&[_][]const u8{ "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" }};
    const ev = try create(allocator, signer, kp, 1700000000, 1, &tags, "hello nostr", null);

    // The id really is the canonical hash of the event's own fields.
    const expected_id = try computeId(allocator, kp.public_key, 1700000000, 1, &tags, "hello nostr");
    try std.testing.expectEqualSlices(u8, &expected_id, &ev.id);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &ev.pubkey);

    try std.testing.expect(try verify(allocator, signer, ev));
}

test "verify rejects a tampered content field" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var ev = try create(allocator, signer, kp, 1700000000, 1, &[_]Tag{}, "original", null);
    ev.content = "tampered"; // id no longer matches its own content
    try std.testing.expect(!(try verify(allocator, signer, ev)));
}

test "verify rejects a signature from the wrong key" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp_a = try signer.generateKeyPair(std.testing.io);
    const kp_b = try signer.generateKeyPair(std.testing.io);

    var ev = try create(allocator, signer, kp_a, 1700000000, 1, &[_]Tag{}, "hello", null);
    ev.sig = try signer.signId(ev.id, kp_b, null); // sign the same id, wrong key
    try std.testing.expect(!(try verify(allocator, signer, ev)));
}

// -- The scanner and the serializers against the code they replaced ----------

const reference = @import("event_reference.zig");

test "fromJson and the serializers agree with std.json on generated events" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x6576_656e_7473);
    const g: reference.Generator = .{ .rand = prng.random(), .arena = arena_state.allocator() };

    for (0..4000) |_| {
        const ev = try g.event();
        try reference.expectSameSerialization(ev);
        const wire = try toJson(g.arena, ev);
        try reference.expectSameAsReference(wire);
        const spelled = try g.text(ev);
        try reference.expectSameAsReference(spelled);
        try reference.expectSameAsReference(try g.mutate(spelled));
        try reference.expectSameAsReference(try g.mutate(try g.arena.dupe(u8, wire)));
        _ = arena_state.reset(.retain_capacity);
    }
}

test "fromJson agrees with std.json at the edges" {
    const z32 = "\"" ++ "00" ** 32 ++ "\"";
    const z64 = "\"" ++ "00" ** 64 ++ "\"";
    const head = "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[]";
    const cases = [_][]const u8{
        head ++ ",\"created_at\":0,\"kind\":0,\"content\":\"\"}",
        head ++ ",\"created_at\":-0,\"kind\":-0,\"content\":\"\"}",
        head ++ ",\"created_at\":9223372036854775807,\"kind\":65535,\"content\":\"\"}",
        head ++ ",\"created_at\":-9223372036854775808,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":9223372036854775808,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":-9223372036854775809,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1,\"kind\":65536,\"content\":\"\"}",
        head ++ ",\"created_at\":1,\"kind\":-1,\"content\":\"\"}",
        head ++ ",\"created_at\":01,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1.5,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1e3,\"kind\":1E0,\"content\":\"\"}",
        head ++ ",\"created_at\":\"12\",\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":[104,105]}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":null}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ud83d\\ude00\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ud83d\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ude00\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ud83d\\u0041\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\x\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\u12\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xed\xa0\x80\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xc0\xaf\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xf4\x90\x80\x80\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xc3\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xc3\\u00a9\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"a\tb\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\x7f\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\"} x",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\"}\x00",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",}",
        head ++ ",\"created_at\":1,\"kind\":1}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"kind\":2}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":1,\"x\":2}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":[1,]}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":tru}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":1.}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":.5}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":1e}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":+1}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":" ++ "[" ** 100 ++ "]" ** 100 ++ "}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"\\u0069d\":1}",
        "{\"\\u0069d\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"" ++ "0" ** 63 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"" ++ "AB" ** 32 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"" ++ "0g" ** 32 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"\\u0030" ++ "0" ** 63 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[[]],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[[1]],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[\"e\"],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":null,\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{}",
        "[]",
        "",
        " ",
        "{",
        "\"x\"",
    };
    for (cases) |c| try reference.expectSameAsReference(c);
}
