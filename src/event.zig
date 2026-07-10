//! NIP-01 event model: the `Event` struct, canonical serialization for id
//! hashing, and wire-format JSON encode/decode.

const std = @import("std");
const hex = @import("hex.zig");
const keys = @import("keys.zig");

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

/// Escapes a string per the NIP-01 id-serialization rule: only `\n \" \\ \r
/// \t \b \f` are escaped; every other byte (including other control
/// characters and raw UTF-8) is copied verbatim. This is deliberately
/// stricter than general-purpose JSON escaping, which the spec forbids —
/// using a generic JSON encoder here would produce a different byte
/// sequence, and therefore a different id, than other implementations.
fn appendJsonString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) std.mem.Allocator.Error!void {
    try list.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '\n' => try list.appendSlice(allocator, "\\n"),
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            0x08 => try list.appendSlice(allocator, "\\b"),
            0x0C => try list.appendSlice(allocator, "\\f"),
            else => try list.append(allocator, c),
        }
    }
    try list.append(allocator, '"');
}

fn appendInt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: anytype) std.mem.Allocator.Error!void {
    var buf: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch unreachable;
    try list.appendSlice(allocator, s);
}

fn appendTags(list: *std.ArrayList(u8), allocator: std.mem.Allocator, tags: []const Tag) std.mem.Allocator.Error!void {
    try list.append(allocator, '[');
    for (tags, 0..) |tag, ti| {
        if (ti != 0) try list.append(allocator, ',');
        try list.append(allocator, '[');
        for (tag, 0..) |field, fi| {
            if (fi != 0) try list.append(allocator, ',');
            try appendJsonString(list, allocator, field);
        }
        try list.append(allocator, ']');
    }
    try list.append(allocator, ']');
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
    try list.appendSlice(allocator, "[0,\"");
    try hex.appendHex(list, allocator, &pubkey);
    try list.appendSlice(allocator, "\",");
    try appendInt(list, allocator, created_at);
    try list.append(allocator, ',');
    try appendInt(list, allocator, kind);
    try list.append(allocator, ',');
    try appendTags(list, allocator, tags);
    try list.append(allocator, ',');
    try appendJsonString(list, allocator, content);
    try list.append(allocator, ']');
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
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try appendCanonical(&list, allocator, pubkey, created_at, kind, tags, content);
    return list.toOwnedSlice(allocator);
}

/// Computes the NIP-01 event id: sha256 of the canonical serialization.
pub fn computeId(
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error![32]u8 {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try appendCanonical(&list, allocator, pubkey, created_at, kind, tags, content);
    var id: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(list.items, &id, .{});
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

/// Serializes a full `Event` to wire-format JSON (`{"id":...,...}`).
pub fn toJson(allocator: std.mem.Allocator, event: Event) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    try list.appendSlice(allocator, "{\"id\":\"");
    try hex.appendHex(&list, allocator, &event.id);
    try list.appendSlice(allocator, "\",\"pubkey\":\"");
    try hex.appendHex(&list, allocator, &event.pubkey);
    try list.appendSlice(allocator, "\",\"created_at\":");
    try appendInt(&list, allocator, event.created_at);
    try list.appendSlice(allocator, ",\"kind\":");
    try appendInt(&list, allocator, event.kind);
    try list.appendSlice(allocator, ",\"tags\":");
    try appendTags(&list, allocator, event.tags);
    try list.appendSlice(allocator, ",\"content\":");
    try appendJsonString(&list, allocator, event.content);
    try list.appendSlice(allocator, ",\"sig\":\"");
    try hex.appendHex(&list, allocator, &event.sig);
    try list.appendSlice(allocator, "\"}");

    return list.toOwnedSlice(allocator);
}

const WireEvent = struct {
    id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    kind: u16,
    tags: []const []const []const u8,
    content: []const u8,
    sig: []const u8,
};

pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    value: Event,

    pub fn deinit(self: *Parsed) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses wire-format event JSON. The returned `Parsed` owns an arena
/// backing `value.tags`/`value.content` — call `deinit` to free it.
pub fn fromJson(gpa: std.mem.Allocator, json_text: []const u8) !Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    const wire = try std.json.parseFromSliceLeaky(WireEvent, allocator, json_text, .{});

    return Parsed{
        .arena = arena,
        .value = try fromWire(wire),
    };
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
    const wire = try std.json.parseFromValueLeaky(WireEvent, allocator, value, .{});
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
