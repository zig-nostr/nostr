//! NIP-01 relay wire messages.
//!
//! Every message on a Nostr relay connection is a JSON array whose first
//! element is a type string. This module encodes the messages a client sends
//! (`REQ`, `EVENT`, `CLOSE`) and parses the messages a relay sends back
//! (`EVENT`, `OK`, `EOSE`, `CLOSED`, `NOTICE`).

const std = @import("std");
const hex = @import("hex.zig");
const json = @import("json.zig");
const event_mod = @import("event.zig");
const filter_mod = @import("filter.zig");
const Event = event_mod.Event;
const Filter = filter_mod.Filter;

pub const Error = error{
    /// The bytes were not a well-formed relay message (not a JSON array, an
    /// unknown/absent type tag, or the wrong shape for its type).
    InvalidMessage,
} || std.mem.Allocator.Error;

// ---------------------------------------------------------------------------
// Client -> relay (encoding)
// ---------------------------------------------------------------------------

/// Encodes `["EVENT", <event>]` — publishing an event to a relay.
pub fn encodeEvent(allocator: std.mem.Allocator, ev: Event) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"EVENT\",");
    try appendEvent(&list, allocator, ev);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["REQ", <subscription_id>, <filter>...]` — opening a subscription.
/// With no filters this is `["REQ","<id>"]`, which most relays treat as an
/// empty (match-nothing) request; pass at least one filter to receive events.
pub fn encodeReq(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    filters: []const Filter,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"REQ\",");
    try json.appendString(&list, allocator, subscription_id);
    for (filters) |f| {
        try list.append(allocator, ',');
        try f.appendJson(&list, allocator);
    }
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["CLOSE", <subscription_id>]` — cancelling a subscription.
pub fn encodeClose(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"CLOSE\",");
    try json.appendString(&list, allocator, subscription_id);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["AUTH", <event>]` — the client's NIP-42 authentication response
/// (a signed `kind:22242` event; see `nip42.authEvent`).
pub fn encodeAuth(allocator: std.mem.Allocator, ev: Event) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"AUTH\",");
    try appendEvent(&list, allocator, ev);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Serializes a full event object into `list` (shared by `encodeEvent` and
/// the tests). Mirrors `event.toJson` but writes in place.
fn appendEvent(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    ev: Event,
) std.mem.Allocator.Error!void {
    const j = try event_mod.toJson(allocator, ev);
    defer allocator.free(j);
    try list.appendSlice(allocator, j);
}

// ---------------------------------------------------------------------------
// Relay -> client (parsing)
// ---------------------------------------------------------------------------

/// A message received from a relay. Borrowed slices (`subscription_id`,
/// `message`) and the nested `Event` are owned by the arena in the enclosing
/// `ParsedRelayMessage`.
pub const RelayMessage = union(enum) {
    /// `["EVENT", <subscription_id>, <event>]` — an event for a subscription.
    event: struct { subscription_id: []const u8, event: Event },
    /// `["OK", <event_id>, <accepted>, <message>]` — a publish result.
    ok: struct { event_id: [32]u8, accepted: bool, message: []const u8 },
    /// `["EOSE", <subscription_id>]` — end of stored events for a subscription.
    eose: struct { subscription_id: []const u8 },
    /// `["CLOSED", <subscription_id>, <message>]` — the relay closed a sub.
    closed: struct { subscription_id: []const u8, message: []const u8 },
    /// `["NOTICE", <message>]` — a human-readable relay notice.
    notice: struct { message: []const u8 },
    /// `["AUTH", <challenge>]` — a NIP-42 authentication challenge; sign a
    /// `kind:22242` event (see `nip42.authEvent`) and reply with `encodeAuth`.
    auth: struct { challenge: []const u8 },
};

pub const ParsedRelayMessage = struct {
    arena: *std.heap.ArenaAllocator,
    value: RelayMessage,

    pub fn deinit(self: *ParsedRelayMessage) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses one relay message. The returned value owns an arena backing its
/// borrowed fields — call `deinit` to free it.
pub fn parseRelayMessage(gpa: std.mem.Allocator, json_text: []const u8) Error!ParsedRelayMessage {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, json_text, .{}) catch
        return Error.InvalidMessage;
    const items = switch (root) {
        .array => |a| a.items,
        else => return Error.InvalidMessage,
    };
    if (items.len < 1) return Error.InvalidMessage;
    const tag = asString(items[0]) orelse return Error.InvalidMessage;

    const value: RelayMessage = if (std.mem.eql(u8, tag, "EVENT")) blk: {
        if (items.len < 3) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        const ev = event_mod.fromValueLeaky(allocator, items[2]) catch return Error.InvalidMessage;
        break :blk .{ .event = .{ .subscription_id = sub, .event = ev } };
    } else if (std.mem.eql(u8, tag, "OK")) blk: {
        if (items.len < 4) return Error.InvalidMessage;
        const id_hex = asString(items[1]) orelse return Error.InvalidMessage;
        const accepted = asBool(items[2]) orelse return Error.InvalidMessage;
        const msg = asString(items[3]) orelse return Error.InvalidMessage;
        const id = hex.decodeFixed(32, id_hex) catch return Error.InvalidMessage;
        break :blk .{ .ok = .{ .event_id = id, .accepted = accepted, .message = msg } };
    } else if (std.mem.eql(u8, tag, "EOSE")) blk: {
        if (items.len < 2) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .eose = .{ .subscription_id = sub } };
    } else if (std.mem.eql(u8, tag, "CLOSED")) blk: {
        if (items.len < 3) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        const msg = asString(items[2]) orelse return Error.InvalidMessage;
        break :blk .{ .closed = .{ .subscription_id = sub, .message = msg } };
    } else if (std.mem.eql(u8, tag, "NOTICE")) blk: {
        if (items.len < 2) return Error.InvalidMessage;
        const msg = asString(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .notice = .{ .message = msg } };
    } else if (std.mem.eql(u8, tag, "AUTH")) blk: {
        // NIP-42: relay → client is `["AUTH", <challenge-string>]`. (The client's
        // reply carries an event object instead; that direction is `encodeAuth`.)
        if (items.len < 2) return Error.InvalidMessage;
        const challenge = asString(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .auth = .{ .challenge = challenge } };
    } else {
        return Error.InvalidMessage;
    };

    return ParsedRelayMessage{ .arena = arena, .value = value };
}

fn asString(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn asBool(v: std.json.Value) ?bool {
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn hb(comptime h: []const u8) [32]u8 {
    return hex.decodeFixed(32, h) catch unreachable;
}

const test_pubkey = "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca";

fn sampleEvent() Event {
    return .{
        .id = hb("d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40"),
        .pubkey = hb(test_pubkey),
        .created_at = 1700000000,
        .kind = 1,
        .tags = &[_]event_mod.Tag{},
        .content = "hello",
        .sig = [_]u8{0xab} ** 64,
    };
}

test "encodeReq with a filter" {
    const allocator = std.testing.allocator;
    const authors = [_][32]u8{hb(test_pubkey)};
    const kinds = [_]u16{1};
    const filters = [_]Filter{.{ .authors = &authors, .kinds = &kinds, .limit = 10 }};

    const s = try encodeReq(allocator, "sub1", &filters);
    defer allocator.free(s);

    const expected = "[\"REQ\",\"sub1\",{\"authors\":[\"" ++ test_pubkey ++ "\"],\"kinds\":[1],\"limit\":10}]";
    try std.testing.expectEqualStrings(expected, s);
}

test "encodeReq with no filters" {
    const allocator = std.testing.allocator;
    const s = try encodeReq(allocator, "sub1", &[_]Filter{});
    defer allocator.free(s);
    try std.testing.expectEqualStrings("[\"REQ\",\"sub1\"]", s);
}

test "encodeClose" {
    const allocator = std.testing.allocator;
    const s = try encodeClose(allocator, "sub1");
    defer allocator.free(s);
    try std.testing.expectEqualStrings("[\"CLOSE\",\"sub1\"]", s);
}

test "encodeEvent round-trips through the event parser" {
    const allocator = std.testing.allocator;
    const s = try encodeEvent(allocator, sampleEvent());
    defer allocator.free(s);
    try std.testing.expect(std.mem.startsWith(u8, s, "[\"EVENT\",{"));
    try std.testing.expect(std.mem.endsWith(u8, s, "}]"));

    // The inner object must be a parseable event equal to the original.
    const inner = s["[\"EVENT\",".len .. s.len - 1];
    var parsed = try event_mod.fromJson(allocator, inner);
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, &sampleEvent().id, &parsed.value.id);
    try std.testing.expectEqualStrings("hello", parsed.value.content);
}

test "parse EVENT message" {
    const allocator = std.testing.allocator;
    const j = try encodeEvent(allocator, sampleEvent());
    defer allocator.free(j);
    // Wrap the published event into a relay EVENT frame.
    const framed = try std.fmt.allocPrint(allocator, "[\"EVENT\",\"sub1\",{s}]", .{j["[\"EVENT\",".len .. j.len - 1]});
    defer allocator.free(framed);

    var parsed = try parseRelayMessage(allocator, framed);
    defer parsed.deinit();
    switch (parsed.value) {
        .event => |e| {
            try std.testing.expectEqualStrings("sub1", e.subscription_id);
            try std.testing.expectEqualSlices(u8, &sampleEvent().id, &e.event.id);
            try std.testing.expectEqualStrings("hello", e.event.content);
        },
        else => return error.WrongVariant,
    }
}

test "parse OK message (accepted and rejected)" {
    const allocator = std.testing.allocator;
    const id_hex = "d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40";

    {
        const text = "[\"OK\",\"" ++ id_hex ++ "\",true,\"\"]";
        var parsed = try parseRelayMessage(allocator, text);
        defer parsed.deinit();
        switch (parsed.value) {
            .ok => |o| {
                try std.testing.expect(o.accepted);
                try std.testing.expectEqualSlices(u8, &hb(id_hex), &o.event_id);
                try std.testing.expectEqualStrings("", o.message);
            },
            else => return error.WrongVariant,
        }
    }
    {
        const text = "[\"OK\",\"" ++ id_hex ++ "\",false,\"blocked: spam\"]";
        var parsed = try parseRelayMessage(allocator, text);
        defer parsed.deinit();
        switch (parsed.value) {
            .ok => |o| {
                try std.testing.expect(!o.accepted);
                try std.testing.expectEqualStrings("blocked: spam", o.message);
            },
            else => return error.WrongVariant,
        }
    }
}

test "parse EOSE, CLOSED, NOTICE" {
    const allocator = std.testing.allocator;

    {
        var p = try parseRelayMessage(allocator, "[\"EOSE\",\"sub1\"]");
        defer p.deinit();
        try std.testing.expectEqualStrings("sub1", p.value.eose.subscription_id);
    }
    {
        var p = try parseRelayMessage(allocator, "[\"CLOSED\",\"sub1\",\"auth-required: login\"]");
        defer p.deinit();
        try std.testing.expectEqualStrings("sub1", p.value.closed.subscription_id);
        try std.testing.expectEqualStrings("auth-required: login", p.value.closed.message);
    }
    {
        var p = try parseRelayMessage(allocator, "[\"NOTICE\",\"rate limited\"]");
        defer p.deinit();
        try std.testing.expectEqualStrings("rate limited", p.value.notice.message);
    }
}

test "parse AUTH challenge" {
    const allocator = std.testing.allocator;
    var p = try parseRelayMessage(allocator, "[\"AUTH\",\"challenge-abc123\"]");
    defer p.deinit();
    try std.testing.expectEqualStrings("challenge-abc123", p.value.auth.challenge);
}

test "encodeAuth wraps a signed event as [\"AUTH\", <event>]" {
    const allocator = std.testing.allocator;
    const s = try encodeAuth(allocator, sampleEvent());
    defer allocator.free(s);
    try std.testing.expect(std.mem.startsWith(u8, s, "[\"AUTH\",{"));
    try std.testing.expect(std.mem.endsWith(u8, s, "}]"));
    // The wrapped object parses back as the original event.
    const inner = s["[\"AUTH\",".len .. s.len - 1];
    var parsed = try event_mod.fromJson(allocator, inner);
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, &sampleEvent().id, &parsed.value.id);
    try std.testing.expectEqualStrings("hello", parsed.value.content);
}

test "parse rejects malformed messages" {
    const allocator = std.testing.allocator;
    const bad = [_][]const u8{
        "not json",
        "{}", // object, not an array
        "[]", // no type tag
        "[123]", // non-string type tag
        "[\"WAT\",\"x\"]", // unknown type
        "[\"EOSE\"]", // missing subscription id
        "[\"OK\",\"zz\",true,\"\"]", // bad hex id
        "[\"OK\",\"" ++ "d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40" ++ "\",\"yes\",\"\"]", // accepted not a bool
    };
    for (bad) |t| {
        try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, t));
    }
}
