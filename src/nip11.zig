//! NIP-11 relay information documents.
//!
//! A codec only: no HTTP happens here. Send a GET to `httpUrl(relay_url)`
//! with `accept_header_name: accept_header_value`, then hand the body to
//! `parse`. Unknown fields are ignored and fields of the wrong type are
//! skipped, so one odd value never loses the rest of the document.

const std = @import("std");

pub const accept_header_name = "Accept";
pub const accept_header_value = "application/nostr+json";

pub const UrlError = error{ UnsupportedScheme, EmptyHost } || std.mem.Allocator.Error;
pub const ParseError = error{InvalidJson} || std.mem.Allocator.Error;

/// Converts a relay URL (`wss://` or `ws://`) to the HTTP URL to query.
/// `https://` and `http://` pass through. Caller frees.
pub fn httpUrl(allocator: std.mem.Allocator, relay_url: []const u8) UrlError![]u8 {
    const map = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "wss://", .to = "https://" },
        .{ .from = "ws://", .to = "http://" },
        .{ .from = "https://", .to = "https://" },
        .{ .from = "http://", .to = "http://" },
    };
    for (map) |m| {
        if (relay_url.len >= m.from.len and std.ascii.eqlIgnoreCase(relay_url[0..m.from.len], m.from)) {
            const rest = relay_url[m.from.len..];
            if (rest.len == 0 or rest[0] == '/') return error.EmptyHost;
            return std.fmt.allocPrint(allocator, "{s}{s}", .{ m.to, rest });
        }
    }
    return error.UnsupportedScheme;
}

pub const Limitation = struct {
    max_message_length: ?u64 = null,
    max_subscriptions: ?u64 = null,
    max_limit: ?u64 = null,
    max_subid_length: ?u64 = null,
    max_event_tags: ?u64 = null,
    max_content_length: ?u64 = null,
    min_pow_difficulty: ?u64 = null,
    auth_required: ?bool = null,
    payment_required: ?bool = null,
    restricted_writes: ?bool = null,
    created_at_lower_limit: ?u64 = null,
    created_at_upper_limit: ?u64 = null,
    default_limit: ?u64 = null,
};

pub const Info = struct {
    arena: std.heap.ArenaAllocator,
    /// The document exactly as received.
    raw: []const u8,
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    banner: ?[]const u8 = null,
    icon: ?[]const u8 = null,
    /// Hex pubkey of the operator, as published (not validated).
    pubkey: ?[]const u8 = null,
    self: ?[]const u8 = null,
    contact: ?[]const u8 = null,
    supported_nips: []const u32 = &.{},
    software: ?[]const u8 = null,
    version: ?[]const u8 = null,
    limitation: Limitation = .{},
    relay_countries: []const []const u8 = &.{},
    language_tags: []const []const u8 = &.{},
    tags: []const []const u8 = &.{},
    posting_policy: ?[]const u8 = null,
    payments_url: ?[]const u8 = null,
    /// Free-form sections, kept as parsed JSON (null when absent).
    retention: ?std.json.Value = null,
    fees: ?std.json.Value = null,

    pub fn deinit(self: *Info) void {
        self.arena.deinit();
    }

    pub fn supportsNip(self: *const Info, nip: u32) bool {
        return std.mem.indexOfScalar(u32, self.supported_nips, nip) != null;
    }
};

fn str(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn uint(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const v = obj.get(key) orelse return null;
    if (v == .integer and v.integer >= 0) return @intCast(v.integer);
    return null;
}

fn boolean(obj: std.json.ObjectMap, key: []const u8) ?bool {
    const v = obj.get(key) orelse return null;
    return if (v == .bool) v.bool else null;
}

fn strList(a: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) std.mem.Allocator.Error![]const []const u8 {
    const v = obj.get(key) orelse return &.{};
    if (v != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |item| if (item == .string) try out.append(a, item.string);
    return out.toOwnedSlice(a);
}

fn nipList(a: std.mem.Allocator, obj: std.json.ObjectMap, key: []const u8) std.mem.Allocator.Error![]const u32 {
    const v = obj.get(key) orelse return &.{};
    if (v != .array) return &.{};
    var out: std.ArrayList(u32) = .empty;
    for (v.array.items) |item| {
        if (item == .integer and item.integer >= 0 and item.integer <= std.math.maxInt(u32)) {
            try out.append(a, @intCast(item.integer));
        }
    }
    return out.toOwnedSlice(a);
}

/// Parses a relay information document. Only a body that is not a JSON
/// object is an error.
pub fn parse(gpa: std.mem.Allocator, body: []const u8) ParseError!Info {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    const raw = try a.dupe(u8, body);
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, raw, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    if (root != .object) return error.InvalidJson;
    const o = root.object;

    var info: Info = .{ .arena = undefined, .raw = raw };
    info.name = str(o, "name");
    info.description = str(o, "description");
    info.banner = str(o, "banner");
    info.icon = str(o, "icon");
    info.pubkey = str(o, "pubkey");
    info.self = str(o, "self");
    info.contact = str(o, "contact");
    info.software = str(o, "software");
    info.version = str(o, "version");
    info.posting_policy = str(o, "posting_policy");
    info.payments_url = str(o, "payments_url");
    info.supported_nips = try nipList(a, o, "supported_nips");
    info.relay_countries = try strList(a, o, "relay_countries");
    info.language_tags = try strList(a, o, "language_tags");
    info.tags = try strList(a, o, "tags");
    if (o.get("retention")) |v| info.retention = v;
    if (o.get("fees")) |v| info.fees = v;

    if (o.get("limitation")) |lv| if (lv == .object) {
        const l = lv.object;
        info.limitation = .{
            .max_message_length = uint(l, "max_message_length"),
            .max_subscriptions = uint(l, "max_subscriptions"),
            .max_limit = uint(l, "max_limit"),
            .max_subid_length = uint(l, "max_subid_length"),
            .max_event_tags = uint(l, "max_event_tags"),
            .max_content_length = uint(l, "max_content_length"),
            .min_pow_difficulty = uint(l, "min_pow_difficulty"),
            .auth_required = boolean(l, "auth_required"),
            .payment_required = boolean(l, "payment_required"),
            .restricted_writes = boolean(l, "restricted_writes"),
            .created_at_lower_limit = uint(l, "created_at_lower_limit"),
            .created_at_upper_limit = uint(l, "created_at_upper_limit"),
            .default_limit = uint(l, "default_limit"),
        };
    };

    info.arena = arena;
    return info;
}

const testing = std.testing;

test "nip11: http url conversion" {
    const a = testing.allocator;
    const cases = [_][2][]const u8{
        .{ "wss://relay.example.com", "https://relay.example.com" },
        .{ "WSS://relay.example.com/path?x=1", "https://relay.example.com/path?x=1" },
        .{ "ws://localhost:7777", "http://localhost:7777" },
        .{ "https://relay.example.com", "https://relay.example.com" },
    };
    for (cases) |c| {
        const u = try httpUrl(a, c[0]);
        defer a.free(u);
        try testing.expectEqualStrings(c[1], u);
    }
    try testing.expectError(error.UnsupportedScheme, httpUrl(a, "ftp://x"));
    try testing.expectError(error.UnsupportedScheme, httpUrl(a, "relay.example.com"));
    try testing.expectError(error.EmptyHost, httpUrl(a, "wss://"));
    try testing.expectEqualStrings("application/nostr+json", accept_header_value);
}

const real_world =
    \\{
    \\  "name": "nostr.example relay",
    \\  "description": "A public relay.",
    \\  "banner": "https://example.com/banner.png",
    \\  "icon": "https://example.com/icon.png",
    \\  "pubkey": "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9",
    \\  "self": "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9",
    \\  "contact": "mailto:admin@example.com",
    \\  "supported_nips": [1, 2, 4, 9, 11, 22, 28, 40, 42, 70, 77],
    \\  "software": "git+https://github.com/example/relay.git",
    \\  "version": "1.2.3",
    \\  "limitation": {
    \\    "max_message_length": 524288,
    \\    "max_subscriptions": 20,
    \\    "max_limit": 5000,
    \\    "max_subid_length": 100,
    \\    "max_event_tags": 2000,
    \\    "max_content_length": 70000,
    \\    "min_pow_difficulty": 0,
    \\    "auth_required": false,
    \\    "payment_required": true,
    \\    "restricted_writes": true,
    \\    "created_at_lower_limit": 94608000,
    \\    "created_at_upper_limit": 300,
    \\    "default_limit": 500
    \\  },
    \\  "retention": [{"kinds": [0, 1], "time": 3600}, {"time": null}],
    \\  "relay_countries": ["US", "DE"],
    \\  "language_tags": ["en", "en-419"],
    \\  "tags": ["sfw-only", "bitcoin-only"],
    \\  "posting_policy": "https://example.com/policy.html",
    \\  "payments_url": "https://example.com/payments",
    \\  "fees": {"admission": [{"amount": 1000000, "unit": "msats"}]},
    \\  "somethingNew": {"x": [1, 2]}
    \\}
;

test "nip11: real-world document" {
    var info = try parse(testing.allocator, real_world);
    defer info.deinit();
    try testing.expectEqualStrings("nostr.example relay", info.name.?);
    try testing.expectEqualStrings("1.2.3", info.version.?);
    try testing.expectEqualStrings("mailto:admin@example.com", info.contact.?);
    try testing.expectEqual(@as(usize, 11), info.supported_nips.len);
    try testing.expect(info.supportsNip(77));
    try testing.expect(!info.supportsNip(50));
    try testing.expectEqual(@as(u64, 524288), info.limitation.max_message_length.?);
    try testing.expectEqual(@as(u64, 94608000), info.limitation.created_at_lower_limit.?);
    try testing.expectEqual(@as(u64, 500), info.limitation.default_limit.?);
    try testing.expectEqual(false, info.limitation.auth_required.?);
    try testing.expectEqual(true, info.limitation.payment_required.?);
    try testing.expectEqual(@as(usize, 2), info.relay_countries.len);
    try testing.expectEqualStrings("en-419", info.language_tags[1]);
    try testing.expectEqual(@as(usize, 2), info.tags.len);
    try testing.expect(info.retention.? == .array);
    try testing.expect(info.fees.? == .object);
    try testing.expectEqualStrings(real_world, info.raw);
}

test "nip11: wrong types are skipped, not fatal" {
    const body =
        \\{"name": 5, "description": "ok", "supported_nips": [1, "2", 3.5, -1, 11],
        \\ "limitation": {"max_limit": "big", "auth_required": 1, "max_subscriptions": 10, "default_limit": -3},
        \\ "tags": "x", "language_tags": ["en", 7], "banner": null}
    ;
    var info = try parse(testing.allocator, body);
    defer info.deinit();
    try testing.expect(info.name == null);
    try testing.expectEqualStrings("ok", info.description.?);
    try testing.expectEqual(@as(usize, 2), info.supported_nips.len);
    try testing.expect(info.limitation.max_limit == null);
    try testing.expect(info.limitation.auth_required == null);
    try testing.expect(info.limitation.default_limit == null);
    try testing.expectEqual(@as(u64, 10), info.limitation.max_subscriptions.?);
    try testing.expectEqual(@as(usize, 0), info.tags.len);
    try testing.expectEqual(@as(usize, 1), info.language_tags.len);
    try testing.expect(info.banner == null);
}

test "nip11: empty object and limitation of the wrong type" {
    var info = try parse(testing.allocator, "{\"limitation\": []}");
    defer info.deinit();
    try testing.expect(info.name == null);
    try testing.expect(info.limitation.max_limit == null);
}

test "nip11: malformed documents" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidJson, parse(a, ""));
    try testing.expectError(error.InvalidJson, parse(a, "<html>not json</html>"));
    try testing.expectError(error.InvalidJson, parse(a, "{\"name\": "));
    try testing.expectError(error.InvalidJson, parse(a, "[1,2]"));
    try testing.expectError(error.InvalidJson, parse(a, "\"str\""));
}
