//! NIP-19: bech32-encoded entities (npub/nsec/note, and TLV-based
//! nprofile/nevent/naddr/nrelay), plus NIP-21 `nostr:` URIs.
//!
//! These encodings are for display, copy-paste, and input only — never for
//! wire-format events or filters.

const std = @import("std");
const bech32 = @import("bech32.zig");

pub const Error = bech32.Error || error{
    InvalidPrefix,
    InvalidTlv,
    WrongLength,
};

fn appendTlv(list: *std.ArrayList(u8), allocator: std.mem.Allocator, t: u8, value: []const u8) Error!void {
    if (value.len > 255) return Error.InvalidTlv;
    try list.append(allocator, t);
    try list.append(allocator, @intCast(value.len));
    try list.appendSlice(allocator, value);
}

fn encodeBare(allocator: std.mem.Allocator, hrp: []const u8, bytes32: [32]u8) Error![]u8 {
    const data5 = try bech32.convertBits(allocator, &bytes32, 8, 5, true);
    defer allocator.free(data5);
    return bech32.encode(allocator, hrp, data5);
}

fn decodeBare(allocator: std.mem.Allocator, expected_hrp: []const u8, s: []const u8) Error![32]u8 {
    var decoded = try bech32.decode(allocator, s);
    defer decoded.deinit(allocator);
    if (!std.mem.eql(u8, decoded.hrp, expected_hrp)) return Error.InvalidPrefix;

    const bytes = try bech32.convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(bytes);
    if (bytes.len != 32) return Error.WrongLength;

    var out: [32]u8 = undefined;
    @memcpy(&out, bytes);
    return out;
}

pub fn encodeNpub(allocator: std.mem.Allocator, pubkey: [32]u8) Error![]u8 {
    return encodeBare(allocator, "npub", pubkey);
}
pub fn decodeNpub(allocator: std.mem.Allocator, s: []const u8) Error![32]u8 {
    return decodeBare(allocator, "npub", s);
}

pub fn encodeNsec(allocator: std.mem.Allocator, seckey: [32]u8) Error![]u8 {
    return encodeBare(allocator, "nsec", seckey);
}
pub fn decodeNsec(allocator: std.mem.Allocator, s: []const u8) Error![32]u8 {
    return decodeBare(allocator, "nsec", s);
}

pub fn encodeNote(allocator: std.mem.Allocator, id: [32]u8) Error![]u8 {
    return encodeBare(allocator, "note", id);
}
pub fn decodeNote(allocator: std.mem.Allocator, s: []const u8) Error![32]u8 {
    return decodeBare(allocator, "note", s);
}

pub const ProfilePointer = struct {
    pubkey: [32]u8,
    relays: [][]u8 = &.{},

    pub fn deinit(self: *ProfilePointer, allocator: std.mem.Allocator) void {
        for (self.relays) |r| allocator.free(r);
        allocator.free(self.relays);
    }
};

pub fn encodeNprofile(allocator: std.mem.Allocator, pubkey: [32]u8, relays: []const []const u8) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendTlv(&buf, allocator, 0, &pubkey);
    for (relays) |r| try appendTlv(&buf, allocator, 1, r);

    const data5 = try bech32.convertBits(allocator, buf.items, 8, 5, true);
    defer allocator.free(data5);
    return bech32.encode(allocator, "nprofile", data5);
}

pub fn decodeNprofile(allocator: std.mem.Allocator, s: []const u8) Error!ProfilePointer {
    var decoded = try bech32.decode(allocator, s);
    defer decoded.deinit(allocator);
    if (!std.mem.eql(u8, decoded.hrp, "nprofile")) return Error.InvalidPrefix;

    const raw = try bech32.convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(raw);

    var pubkey: ?[32]u8 = null;
    var relays: std.ArrayList([]u8) = .empty;
    errdefer {
        for (relays.items) |r| allocator.free(r);
        relays.deinit(allocator);
    }

    var i: usize = 0;
    while (i + 2 <= raw.len) {
        const t = raw[i];
        const l = raw[i + 1];
        if (i + 2 + l > raw.len) return Error.InvalidTlv;
        const v = raw[i + 2 .. i + 2 + l];
        switch (t) {
            0 => {
                if (l != 32) return Error.WrongLength;
                var pk: [32]u8 = undefined;
                @memcpy(&pk, v);
                pubkey = pk;
            },
            1 => try relays.append(allocator, try allocator.dupe(u8, v)),
            else => {}, // unrecognized TLV types are ignored per spec
        }
        i += 2 + l;
    }

    const pk = pubkey orelse return Error.InvalidTlv;
    return ProfilePointer{ .pubkey = pk, .relays = try relays.toOwnedSlice(allocator) };
}

pub const EventPointer = struct {
    id: [32]u8,
    relays: [][]u8 = &.{},
    author: ?[32]u8 = null,
    kind: ?u32 = null,

    pub fn deinit(self: *EventPointer, allocator: std.mem.Allocator) void {
        for (self.relays) |r| allocator.free(r);
        allocator.free(self.relays);
    }
};

pub fn encodeNevent(
    allocator: std.mem.Allocator,
    id: [32]u8,
    relays: []const []const u8,
    author: ?[32]u8,
    kind: ?u32,
) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendTlv(&buf, allocator, 0, &id);
    for (relays) |r| try appendTlv(&buf, allocator, 1, r);
    if (author) |a| try appendTlv(&buf, allocator, 2, &a);
    if (kind) |k| {
        var kb: [4]u8 = undefined;
        std.mem.writeInt(u32, &kb, k, .big);
        try appendTlv(&buf, allocator, 3, &kb);
    }

    const data5 = try bech32.convertBits(allocator, buf.items, 8, 5, true);
    defer allocator.free(data5);
    return bech32.encode(allocator, "nevent", data5);
}

pub fn decodeNevent(allocator: std.mem.Allocator, s: []const u8) Error!EventPointer {
    var decoded = try bech32.decode(allocator, s);
    defer decoded.deinit(allocator);
    if (!std.mem.eql(u8, decoded.hrp, "nevent")) return Error.InvalidPrefix;

    const raw = try bech32.convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(raw);

    var id: ?[32]u8 = null;
    var author: ?[32]u8 = null;
    var kind: ?u32 = null;
    var relays: std.ArrayList([]u8) = .empty;
    errdefer {
        for (relays.items) |r| allocator.free(r);
        relays.deinit(allocator);
    }

    var i: usize = 0;
    while (i + 2 <= raw.len) {
        const t = raw[i];
        const l = raw[i + 1];
        if (i + 2 + l > raw.len) return Error.InvalidTlv;
        const v = raw[i + 2 .. i + 2 + l];
        switch (t) {
            0 => {
                if (l != 32) return Error.WrongLength;
                var buf: [32]u8 = undefined;
                @memcpy(&buf, v);
                id = buf;
            },
            1 => try relays.append(allocator, try allocator.dupe(u8, v)),
            2 => {
                if (l != 32) return Error.WrongLength;
                var buf: [32]u8 = undefined;
                @memcpy(&buf, v);
                author = buf;
            },
            3 => {
                if (l != 4) return Error.WrongLength;
                kind = std.mem.readInt(u32, v[0..4], .big);
            },
            else => {},
        }
        i += 2 + l;
    }

    const eid = id orelse return Error.InvalidTlv;
    return EventPointer{
        .id = eid,
        .relays = try relays.toOwnedSlice(allocator),
        .author = author,
        .kind = kind,
    };
}

pub const AddrPointer = struct {
    identifier: []u8,
    pubkey: [32]u8,
    kind: u32,
    relays: [][]u8 = &.{},

    pub fn deinit(self: *AddrPointer, allocator: std.mem.Allocator) void {
        allocator.free(self.identifier);
        for (self.relays) |r| allocator.free(r);
        allocator.free(self.relays);
    }
};

pub fn encodeNaddr(
    allocator: std.mem.Allocator,
    identifier: []const u8,
    pubkey: [32]u8,
    kind: u32,
    relays: []const []const u8,
) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendTlv(&buf, allocator, 0, identifier);
    for (relays) |r| try appendTlv(&buf, allocator, 1, r);
    try appendTlv(&buf, allocator, 2, &pubkey);
    var kb: [4]u8 = undefined;
    std.mem.writeInt(u32, &kb, kind, .big);
    try appendTlv(&buf, allocator, 3, &kb);

    const data5 = try bech32.convertBits(allocator, buf.items, 8, 5, true);
    defer allocator.free(data5);
    return bech32.encode(allocator, "naddr", data5);
}

pub fn decodeNaddr(allocator: std.mem.Allocator, s: []const u8) Error!AddrPointer {
    var decoded = try bech32.decode(allocator, s);
    defer decoded.deinit(allocator);
    if (!std.mem.eql(u8, decoded.hrp, "naddr")) return Error.InvalidPrefix;

    const raw = try bech32.convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(raw);

    var identifier: ?[]u8 = null;
    errdefer if (identifier) |ident| allocator.free(ident);
    var pubkey: ?[32]u8 = null;
    var kind: ?u32 = null;
    var relays: std.ArrayList([]u8) = .empty;
    errdefer {
        for (relays.items) |r| allocator.free(r);
        relays.deinit(allocator);
    }

    var i: usize = 0;
    while (i + 2 <= raw.len) {
        const t = raw[i];
        const l = raw[i + 1];
        if (i + 2 + l > raw.len) return Error.InvalidTlv;
        const v = raw[i + 2 .. i + 2 + l];
        switch (t) {
            0 => identifier = try allocator.dupe(u8, v),
            1 => try relays.append(allocator, try allocator.dupe(u8, v)),
            2 => {
                if (l != 32) return Error.WrongLength;
                var buf: [32]u8 = undefined;
                @memcpy(&buf, v);
                pubkey = buf;
            },
            3 => {
                if (l != 4) return Error.WrongLength;
                kind = std.mem.readInt(u32, v[0..4], .big);
            },
            else => {},
        }
        i += 2 + l;
    }

    const ident = identifier orelse return Error.InvalidTlv;
    const pk = pubkey orelse return Error.InvalidTlv;
    const k = kind orelse return Error.InvalidTlv;
    return AddrPointer{
        .identifier = ident,
        .pubkey = pk,
        .kind = k,
        .relays = try relays.toOwnedSlice(allocator),
    };
}

/// `nrelay` (deprecated): a bare relay URL wrapped as a TLV `special` entry.
pub fn encodeNrelay(allocator: std.mem.Allocator, url: []const u8) Error![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try appendTlv(&buf, allocator, 0, url);

    const data5 = try bech32.convertBits(allocator, buf.items, 8, 5, true);
    defer allocator.free(data5);
    return bech32.encode(allocator, "nrelay", data5);
}

pub fn decodeNrelay(allocator: std.mem.Allocator, s: []const u8) Error![]u8 {
    var decoded = try bech32.decode(allocator, s);
    defer decoded.deinit(allocator);
    if (!std.mem.eql(u8, decoded.hrp, "nrelay")) return Error.InvalidPrefix;

    const raw = try bech32.convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(raw);

    var i: usize = 0;
    while (i + 2 <= raw.len) {
        const t = raw[i];
        const l = raw[i + 1];
        if (i + 2 + l > raw.len) return Error.InvalidTlv;
        if (t == 0) return allocator.dupe(u8, raw[i + 2 .. i + 2 + l]);
        i += 2 + l;
    }
    return Error.InvalidTlv;
}

/// NIP-21: `nostr:` URI wrapping any bech32 entity.
pub fn toNostrUri(allocator: std.mem.Allocator, bech: []const u8) Error![]u8 {
    return std.fmt.allocPrint(allocator, "nostr:{s}", .{bech});
}

/// Strips the `nostr:` prefix if present; returns a slice into `s` (no allocation).
pub fn fromNostrUri(s: []const u8) []const u8 {
    const prefix = "nostr:";
    if (std.mem.startsWith(u8, s, prefix)) return s[prefix.len..];
    return s;
}

fn hexToBytes32(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidLength;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

test "npub encode/decode matches official NIP-19 vector" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e");
    const expected = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";

    const encoded = try encodeNpub(allocator, pubkey);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(expected, encoded);

    const decoded = try decodeNpub(allocator, expected);
    try std.testing.expectEqualSlices(u8, &pubkey, &decoded);
}

test "nsec encode/decode matches official NIP-19 vector" {
    const allocator = std.testing.allocator;
    const seckey = try hexToBytes32("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");
    const expected = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";

    const encoded = try encodeNsec(allocator, seckey);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(expected, encoded);

    const decoded = try decodeNsec(allocator, expected);
    try std.testing.expectEqualSlices(u8, &seckey, &decoded);
}

test "note encode/decode round trip" {
    const allocator = std.testing.allocator;
    const id = try hexToBytes32("5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36");

    const encoded = try encodeNote(allocator, id);
    defer allocator.free(encoded);
    const decoded = try decodeNote(allocator, encoded);
    try std.testing.expectEqualSlices(u8, &id, &decoded);
}

test "nprofile decode matches official NIP-19 vector" {
    const allocator = std.testing.allocator;
    const s = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    const expected_pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");

    var decoded = try decodeNprofile(allocator, s);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &expected_pubkey, &decoded.pubkey);
    try std.testing.expectEqual(@as(usize, 2), decoded.relays.len);
    try std.testing.expectEqualStrings("wss://r.x.com", decoded.relays[0]);
    try std.testing.expectEqualStrings("wss://djbas.sadkb.com", decoded.relays[1]);
}

test "nprofile encode reproduces official NIP-19 vector" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const relays = [_][]const u8{ "wss://r.x.com", "wss://djbas.sadkb.com" };

    const encoded = try encodeNprofile(allocator, pubkey, &relays);
    defer allocator.free(encoded);

    const expected = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
    try std.testing.expectEqualStrings(expected, encoded);
}

test "nevent round trip with optional author and kind" {
    const allocator = std.testing.allocator;
    const id = try hexToBytes32("5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36");
    const author = try hexToBytes32("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca");
    const relays = [_][]const u8{"wss://nostr.example.com"};

    const encoded = try encodeNevent(allocator, id, &relays, author, 1);
    defer allocator.free(encoded);

    var decoded = try decodeNevent(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &id, &decoded.id);
    try std.testing.expectEqualSlices(u8, &author, &decoded.author.?);
    try std.testing.expectEqual(@as(u32, 1), decoded.kind.?);
    try std.testing.expectEqual(@as(usize, 1), decoded.relays.len);
    try std.testing.expectEqualStrings("wss://nostr.example.com", decoded.relays[0]);
}

test "naddr round trip" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca");
    const relays = [_][]const u8{"wss://nostr.example.com"};

    const encoded = try encodeNaddr(allocator, "abcd", pubkey, 30023, &relays);
    defer allocator.free(encoded);

    var decoded = try decodeNaddr(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings("abcd", decoded.identifier);
    try std.testing.expectEqualSlices(u8, &pubkey, &decoded.pubkey);
    try std.testing.expectEqual(@as(u32, 30023), decoded.kind);
}

test "nrelay round trip (deprecated)" {
    const allocator = std.testing.allocator;
    const encoded = try encodeNrelay(allocator, "wss://relay.example.com");
    defer allocator.free(encoded);

    const decoded = try decodeNrelay(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("wss://relay.example.com", decoded);
}

test "NIP-21 nostr: URI wrap/unwrap" {
    const allocator = std.testing.allocator;
    const uri = try toNostrUri(allocator, "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg");
    defer allocator.free(uri);
    try std.testing.expectEqualStrings("nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg", uri);
    try std.testing.expectEqualStrings("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg", fromNostrUri(uri));
}
