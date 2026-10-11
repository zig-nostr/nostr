//! NIP-05 DNS-based identifiers.
//!
//! A codec only: no HTTP happens here. The caller fetches the URL from
//! `wellKnownUrl` and hands the response body to `parseResponse`.
//!
//! An identifier is `name@domain`. The name uses `a-z0-9-_.` and the domain
//! is a hostname with an optional port. Input is accepted in any case and
//! normalized to lowercase. `_@domain` is the root identifier, and a bare
//! `domain` is read as `_@domain`.

const std = @import("std");
const hex = @import("hex.zig");

pub const max_name_len = 64;
pub const max_domain_len = 260;

pub const ParseError = error{
    EmptyName,
    NameTooLong,
    InvalidNameChar,
    EmptyDomain,
    DomainTooLong,
    InvalidDomain,
};

pub const ResponseError = error{
    InvalidJson,
    NameNotFound,
    InvalidPubkey,
} || std.mem.Allocator.Error;

/// A normalized (lowercase) identifier. Holds its own storage, so it can be
/// copied and outlives the input.
pub const Identifier = struct {
    name_buf: [max_name_len]u8 = undefined,
    name_len: u8 = 0,
    domain_buf: [max_domain_len]u8 = undefined,
    domain_len: u16 = 0,

    pub fn name(self: *const Identifier) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn domain(self: *const Identifier) []const u8 {
        return self.domain_buf[0..self.domain_len];
    }

    pub fn isRoot(self: *const Identifier) bool {
        return std.mem.eql(u8, self.name(), "_");
    }
};

fn nameCharOk(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-' or c == '_' or c == '.';
}

fn validateDomain(d: []const u8) ParseError!void {
    if (d.len == 0) return error.EmptyDomain;
    if (d.len > max_domain_len) return error.DomainTooLong;
    var host = d;
    if (std.mem.lastIndexOfScalar(u8, d, ':')) |i| {
        const port = d[i + 1 ..];
        if (port.len == 0 or port.len > 5) return error.InvalidDomain;
        for (port) |c| if (c < '0' or c > '9') return error.InvalidDomain;
        host = d[0..i];
    }
    if (host.len == 0 or host.len > 253) return error.InvalidDomain;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.InvalidDomain;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidDomain;
        for (label) |c| {
            if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-')) return error.InvalidDomain;
        }
    }
}

/// Parses `name@domain`, or a bare `domain` (meaning `_@domain`).
pub fn parseIdentifier(text: []const u8) ParseError!Identifier {
    var id: Identifier = .{};
    var name_part: []const u8 = "_";
    var domain_part = text;
    if (std.mem.indexOfScalar(u8, text, '@')) |at| {
        name_part = text[0..at];
        domain_part = text[at + 1 ..];
    }
    if (name_part.len == 0) return error.EmptyName;
    if (name_part.len > max_name_len) return error.NameTooLong;
    if (domain_part.len > max_domain_len) return error.DomainTooLong;
    for (name_part, 0..) |c, i| {
        const l = std.ascii.toLower(c);
        if (!nameCharOk(l)) return error.InvalidNameChar;
        id.name_buf[i] = l;
    }
    id.name_len = @intCast(name_part.len);
    for (domain_part, 0..) |c, i| id.domain_buf[i] = std.ascii.toLower(c);
    id.domain_len = @intCast(domain_part.len);
    try validateDomain(id.domain());
    return id;
}

/// `https://<domain>/.well-known/nostr.json?name=<name>`. Caller frees.
pub fn wellKnownUrl(allocator: std.mem.Allocator, id: *const Identifier) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "https://{s}/.well-known/nostr.json?name={s}", .{ id.domain(), id.name() });
}

pub const Resolved = struct {
    arena: std.heap.ArenaAllocator,
    pubkey: [32]u8,
    /// Relays listed for this pubkey under `relays`. Empty when absent.
    relays: []const []const u8,
    /// Relays listed for this pubkey under `nip46`. Empty when absent.
    nip46: []const []const u8,

    pub fn deinit(self: *Resolved) void {
        self.arena.deinit();
    }
};

fn isLowerHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    return true;
}

fn pubkeyFrom(v: std.json.Value) ResponseError![32]u8 {
    if (v != .string or !isLowerHex64(v.string)) return error.InvalidPubkey;
    return hex.decodeFixed(32, v.string) catch error.InvalidPubkey;
}

fn relaysFor(
    a: std.mem.Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
    pubkey_hex: []const u8,
) ResponseError![]const []const u8 {
    const section = obj.get(key) orelse return &.{};
    if (section != .object) return &.{};
    var it = section.object.iterator();
    while (it.next()) |e| {
        if (!std.ascii.eqlIgnoreCase(e.key_ptr.*, pubkey_hex)) continue;
        if (e.value_ptr.* != .array) return &.{};
        var out: std.ArrayList([]const u8) = .empty;
        for (e.value_ptr.array.items) |item| {
            if (item == .string and item.string.len > 0) try out.append(a, item.string);
        }
        return out.toOwnedSlice(a);
    }
    return &.{};
}

/// Parses a `/.well-known/nostr.json` body and returns the entry for `name`
/// (matched case-insensitively). A name that is missing, or whose pubkey is
/// not 64 lowercase hex characters, is an error. A malformed `relays` or
/// `nip46` section is treated as absent.
pub fn parseResponse(gpa: std.mem.Allocator, body: []const u8, name: []const u8) ResponseError!Resolved {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    if (root != .object) return error.InvalidJson;
    const names = root.object.get("names") orelse return error.NameNotFound;
    if (names != .object) return error.InvalidJson;

    var found: ?std.json.Value = null;
    var it = names.object.iterator();
    while (it.next()) |e| {
        if (std.ascii.eqlIgnoreCase(e.key_ptr.*, name)) {
            found = e.value_ptr.*;
            break;
        }
    }
    const v = found orelse return error.NameNotFound;
    const pubkey = try pubkeyFrom(v);
    const relays = try relaysFor(a, root.object, "relays", v.string);
    const nip46 = try relaysFor(a, root.object, "nip46", v.string);
    return .{ .arena = arena, .pubkey = pubkey, .relays = relays, .nip46 = nip46 };
}

const testing = std.testing;
const pk_hex = "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9";

test "nip05: parse name@domain and lowercase" {
    const id = try parseIdentifier("Bob.Smith-1_x@Example.COM");
    try testing.expectEqualStrings("bob.smith-1_x", id.name());
    try testing.expectEqualStrings("example.com", id.domain());
    try testing.expect(!id.isRoot());
}

test "nip05: root identifier and bare domain" {
    const a = try parseIdentifier("_@example.com");
    try testing.expect(a.isRoot());
    const b = try parseIdentifier("Example.com");
    try testing.expect(b.isRoot());
    try testing.expectEqualStrings("example.com", b.domain());
    const c = try parseIdentifier("a@localhost:8080");
    try testing.expectEqualStrings("localhost:8080", c.domain());
}

test "nip05: invalid identifiers" {
    try testing.expectError(error.EmptyName, parseIdentifier("@example.com"));
    try testing.expectError(error.InvalidNameChar, parseIdentifier("a+b@example.com"));
    try testing.expectError(error.InvalidNameChar, parseIdentifier("a b@example.com"));
    try testing.expectError(error.EmptyDomain, parseIdentifier("bob@"));
    try testing.expectError(error.EmptyDomain, parseIdentifier(""));
    try testing.expectError(error.InvalidDomain, parseIdentifier("a@b@example.com"));
    try testing.expectError(error.InvalidDomain, parseIdentifier("bob@exa mple.com"));
    try testing.expectError(error.InvalidDomain, parseIdentifier("bob@-example.com"));
    try testing.expectError(error.InvalidDomain, parseIdentifier("bob@example..com"));
    try testing.expectError(error.InvalidDomain, parseIdentifier("bob@example.com:"));
    try testing.expectError(error.InvalidDomain, parseIdentifier("bob@example.com:80a"));
    try testing.expectError(error.InvalidDomain, parseIdentifier("bob@exam/ple.com"));
    const long = "a" ** 65 ++ "@example.com";
    try testing.expectError(error.NameTooLong, parseIdentifier(long));
}

test "nip05: well-known url" {
    const id = try parseIdentifier("Bob@Example.com");
    const url = try wellKnownUrl(testing.allocator, &id);
    defer testing.allocator.free(url);
    try testing.expectEqualStrings("https://example.com/.well-known/nostr.json?name=bob", url);
}

test "nip05: response with relays and nip46" {
    const body =
        \\{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"},
        \\ "relays":{"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9":["wss://r1.example.com",5,"wss://r2.example.com"]},
        \\ "nip46":{"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9":["wss://sign.example.com"]},
        \\ "extra":1}
    ;
    var r = try parseResponse(testing.allocator, body, "bob");
    defer r.deinit();
    const want = try hex.decodeFixed(32, pk_hex);
    try testing.expectEqualSlices(u8, &want, &r.pubkey);
    try testing.expectEqual(@as(usize, 2), r.relays.len);
    try testing.expectEqualStrings("wss://r2.example.com", r.relays[1]);
    try testing.expectEqual(@as(usize, 1), r.nip46.len);
}

test "nip05: response missing optional sections and case handling" {
    const body = "{\"names\":{\"Bob\":\"" ++ pk_hex ++ "\",\"alice\":\"" ++ pk_hex ++ "\"}}";
    var r = try parseResponse(testing.allocator, body, "bOb");
    defer r.deinit();
    try testing.expectEqual(@as(usize, 0), r.relays.len);
    try testing.expectEqual(@as(usize, 0), r.nip46.len);
}

test "nip05: relays keyed by uppercase pubkey still match, wrong types ignored" {
    const upper = "B0635D6A9851D3AED0CD6C495B282167ACF761729078D975FC341B22650B07B9";
    const body = "{\"names\":{\"_\":\"" ++ pk_hex ++ "\"},\"relays\":{\"" ++ upper ++ "\":[\"wss://a\"]},\"nip46\":[1]}";
    var r = try parseResponse(testing.allocator, body, "_");
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.relays.len);
    try testing.expectEqual(@as(usize, 0), r.nip46.len);
}

test "nip05: response errors" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidJson, parseResponse(a, "nope", "bob"));
    try testing.expectError(error.InvalidJson, parseResponse(a, "[]", "bob"));
    try testing.expectError(error.NameNotFound, parseResponse(a, "{}", "bob"));
    try testing.expectError(error.InvalidJson, parseResponse(a, "{\"names\":[]}", "bob"));
    try testing.expectError(error.NameNotFound, parseResponse(a, "{\"names\":{\"alice\":\"" ++ pk_hex ++ "\"}}", "bob"));
    try testing.expectError(error.InvalidPubkey, parseResponse(a, "{\"names\":{\"bob\":\"abc\"}}", "bob"));
    try testing.expectError(error.InvalidPubkey, parseResponse(a, "{\"names\":{\"bob\":12}}", "bob"));
    const upper = "B0635D6A9851D3AED0CD6C495B282167ACF761729078D975FC341B22650B07B9";
    try testing.expectError(error.InvalidPubkey, parseResponse(a, "{\"names\":{\"bob\":\"" ++ upper ++ "\"}}", "bob"));
    const bad = "g0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9";
    try testing.expectError(error.InvalidPubkey, parseResponse(a, "{\"names\":{\"bob\":\"" ++ bad ++ "\"}}", "bob"));
}
