//! NIP-01 relay wire messages.
//!
//! Every message on a Nostr relay connection is a JSON array whose first
//! element is a type string. This module encodes the messages a client sends
//! (`REQ`, `EVENT`, `CLOSE`, `COUNT`, NIP-77 `NEG-*`) and parses the messages
//! a relay sends back (`EVENT`, `OK`, `EOSE`, `CLOSED`, `NOTICE`, `AUTH`,
//! `COUNT`, `NEG-MSG`, `NEG-ERR`). The other direction exists too, for code
//! that plays the relay: `parseClientMessage` and the `encode*` functions for
//! relay replies.

const std = @import("std");
const hex = @import("hex.zig");
const json = @import("json.zig");
const event_mod = @import("event.zig");
const filter_mod = @import("filter.zig");
const scan = @import("scan.zig");
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

/// Encodes `["COUNT", <subscription_id>, <filter>...]` (NIP-45): asks the
/// relay how many events match, without sending them.
pub fn encodeCount(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    filters: []const Filter,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"COUNT\",");
    try json.appendString(&list, allocator, subscription_id);
    for (filters) |f| {
        try list.append(allocator, ',');
        try f.appendJson(&list, allocator);
    }
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["NEG-OPEN", <subscription_id>, <filter>, <initial_hex>]` (NIP-77).
/// `initial_hex` is the hex of the first negentropy message; it is written
/// as given, so it must already be hex.
pub fn encodeNegOpen(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    filter: Filter,
    initial_hex: []const u8,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"NEG-OPEN\",");
    try json.appendString(&list, allocator, subscription_id);
    try list.append(allocator, ',');
    try filter.appendJson(&list, allocator);
    try list.append(allocator, ',');
    try json.appendString(&list, allocator, initial_hex);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["NEG-MSG", <subscription_id>, <hex>]` (NIP-77). The same frame
/// goes both ways: a client sends it to continue a session, a relay answers
/// with it.
pub fn encodeNegMsg(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    msg_hex: []const u8,
) std.mem.Allocator.Error![]u8 {
    return encodeIdAndString(allocator, "NEG-MSG", subscription_id, msg_hex);
}

/// Encodes `["NEG-CLOSE", <subscription_id>]` (NIP-77).
pub fn encodeNegClose(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
) std.mem.Allocator.Error![]u8 {
    return encodeTagAndString(allocator, "NEG-CLOSE", subscription_id);
}

// ---------------------------------------------------------------------------
// Relay -> client (encoding), for code that plays the relay
// ---------------------------------------------------------------------------

/// Encodes `["EVENT", <subscription_id>, <event>]`.
pub fn encodeEventMsg(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    ev: Event,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"EVENT\",");
    try json.appendString(&list, allocator, subscription_id);
    try list.append(allocator, ',');
    try appendEvent(&list, allocator, ev);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["OK", <event_id>, <accepted>, <message>]`.
pub fn encodeOk(
    allocator: std.mem.Allocator,
    event_id: [32]u8,
    accepted: bool,
    msg: []const u8,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"OK\",\"");
    try hex.appendHex(&list, allocator, &event_id);
    try list.appendSlice(allocator, if (accepted) "\",true," else "\",false,");
    try json.appendString(&list, allocator, msg);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// Encodes `["EOSE", <subscription_id>]`.
pub fn encodeEose(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
) std.mem.Allocator.Error![]u8 {
    return encodeTagAndString(allocator, "EOSE", subscription_id);
}

/// Encodes `["CLOSED", <subscription_id>, <message>]`.
pub fn encodeClosed(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    msg: []const u8,
) std.mem.Allocator.Error![]u8 {
    return encodeIdAndString(allocator, "CLOSED", subscription_id, msg);
}

/// Encodes `["NOTICE", <message>]`.
pub fn encodeNotice(allocator: std.mem.Allocator, msg: []const u8) std.mem.Allocator.Error![]u8 {
    return encodeTagAndString(allocator, "NOTICE", msg);
}

/// Encodes `["AUTH", <challenge>]`, the NIP-42 challenge a relay sends.
pub fn encodeAuthChallenge(allocator: std.mem.Allocator, challenge: []const u8) std.mem.Allocator.Error![]u8 {
    return encodeTagAndString(allocator, "AUTH", challenge);
}

/// Encodes `["COUNT", <subscription_id>, {"count": N[, "approximate": bool]}]`
/// (NIP-45).
pub fn encodeCountReply(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    count: u64,
    approximate: ?bool,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"COUNT\",");
    try json.appendString(&list, allocator, subscription_id);
    var buf: [48]u8 = undefined;
    try list.appendSlice(allocator, std.fmt.bufPrint(&buf, ",{{\"count\":{d}", .{count}) catch unreachable);
    if (approximate) |a| {
        try list.appendSlice(allocator, if (a) ",\"approximate\":true" else ",\"approximate\":false");
    }
    try list.appendSlice(allocator, "}]");
    return list.toOwnedSlice(allocator);
}

/// Encodes `["NEG-ERR", <subscription_id>, <reason>]` (NIP-77).
pub fn encodeNegErr(
    allocator: std.mem.Allocator,
    subscription_id: []const u8,
    reason: []const u8,
) std.mem.Allocator.Error![]u8 {
    return encodeIdAndString(allocator, "NEG-ERR", subscription_id, reason);
}

/// `["<tag>", "<a>"]`.
fn encodeTagAndString(
    allocator: std.mem.Allocator,
    comptime tag: []const u8,
    a: []const u8,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"" ++ tag ++ "\",");
    try json.appendString(&list, allocator, a);
    try list.append(allocator, ']');
    return list.toOwnedSlice(allocator);
}

/// `["<tag>", "<a>", "<b>"]`.
fn encodeIdAndString(
    allocator: std.mem.Allocator,
    comptime tag: []const u8,
    a: []const u8,
    b: []const u8,
) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "[\"" ++ tag ++ "\",");
    try json.appendString(&list, allocator, a);
    try list.append(allocator, ',');
    try json.appendString(&list, allocator, b);
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
    /// `["COUNT", <subscription_id>, {"count": N, "approximate"?: bool}]`
    /// (NIP-45). The optional `hll` field is ignored.
    count: struct { subscription_id: []const u8, count: u64, approximate: ?bool },
    /// `["NEG-MSG", <subscription_id>, <hex>]` (NIP-77): the relay's next
    /// negentropy message, hex-validated but not decoded.
    neg_msg: struct { sub_id: []const u8, hex: []const u8 },
    /// `["NEG-ERR", <subscription_id>, <reason>]` (NIP-77).
    neg_err: struct { sub_id: []const u8, reason: []const u8 },
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
/// borrowed fields, so `json_text` may be freed as soon as this returns; call
/// `deinit` to free it.
///
/// The text is copied into the arena and read in one pass by `scanRelayMessage`,
/// which hands an `EVENT`'s object to the event scanner without building a
/// JSON tree. Anything it does not take (an extra element, a key an event does
/// not name, a number spelled `1e3`, malformed JSON) is parsed again through a
/// `std.json.Value` tree, so what is accepted and every error returned are
/// exactly what that path alone gives.
pub fn parseRelayMessage(gpa: std.mem.Allocator, json_text: []const u8) Error!ParsedRelayMessage {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    const owned_text = try allocator.dupe(u8, json_text);
    if (scanRelayMessage(allocator, owned_text)) |value| {
        return .{ .arena = arena, .value = value };
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unsupported => {},
    }
    // The scan decoded strings in place, so the copy is no longer the text.
    _ = arena.reset(.retain_capacity);
    return .{ .arena = arena, .value = try relayMessageFromTree(allocator, json_text) };
}

/// Reads a relay message in one pass, decoding its strings in place in `buf`.
/// Takes only the shapes a relay sends in practice, each with exactly the
/// elements its type names; anything else is `Unsupported`, never an error of
/// its own, so `relayMessageFromTree` decides it.
fn scanRelayMessage(allocator: std.mem.Allocator, buf: []u8) scan.ScanError!RelayMessage {
    var s: scan.Scanner = .{ .buf = buf };
    const tag = try openEnvelope(&s);
    const eql = std.mem.eql;
    const value: RelayMessage = if (eql(u8, tag, "EVENT")) blk: {
        const sub = try nextString(&s);
        try nextElement(&s);
        const ev = try scan.eventObject(allocator, &s, .refuse);
        break :blk .{ .event = .{ .subscription_id = sub, .event = ev } };
    } else if (eql(u8, tag, "EOSE"))
        .{ .eose = .{ .subscription_id = try nextString(&s) } }
    else if (eql(u8, tag, "OK")) blk: {
        try nextElement(&s);
        const id = try s.hexString(32);
        try nextElement(&s);
        const accepted = try scanBool(&s);
        break :blk .{ .ok = .{ .event_id = id, .accepted = accepted, .message = try nextString(&s) } };
    } else if (eql(u8, tag, "CLOSED")) blk: {
        const sub = try nextString(&s);
        break :blk .{ .closed = .{ .subscription_id = sub, .message = try nextString(&s) } };
    } else if (eql(u8, tag, "NOTICE"))
        .{ .notice = .{ .message = try nextString(&s) } }
    else if (eql(u8, tag, "AUTH"))
        .{ .auth = .{ .challenge = try nextString(&s) } }
    else if (eql(u8, tag, "COUNT")) blk: {
        const sub = try nextString(&s);
        try nextElement(&s);
        const c = try scanCountObject(&s);
        break :blk .{ .count = .{ .subscription_id = sub, .count = c.count, .approximate = c.approximate } };
    } else if (eql(u8, tag, "NEG-MSG")) blk: {
        const sub = try nextString(&s);
        const h = try nextString(&s);
        if (!isNegHex(h)) return error.Unsupported;
        break :blk .{ .neg_msg = .{ .sub_id = sub, .hex = h } };
    } else if (eql(u8, tag, "NEG-ERR")) blk: {
        const sub = try nextString(&s);
        break :blk .{ .neg_err = .{ .sub_id = sub, .reason = try nextString(&s) } };
    } else return error.Unsupported;
    try closeEnvelope(&s);
    return value;
}

/// `[` and the type string, decoded.
fn openEnvelope(s: *scan.Scanner) error{Unsupported}![]const u8 {
    s.skipWs();
    try s.expect('[');
    s.skipWs();
    if (s.peek() != '"') return error.Unsupported;
    return s.string();
}

/// `]` and nothing after it but whitespace.
fn closeEnvelope(s: *scan.Scanner) error{Unsupported}!void {
    s.skipWs();
    try s.expect(']');
    s.skipWs();
    if (s.i != s.buf.len) return error.Unsupported;
}

/// The `,` before the next element, and the whitespace around it.
fn nextElement(s: *scan.Scanner) error{Unsupported}!void {
    s.skipWs();
    try s.expect(',');
    s.skipWs();
}

/// The next element, which has to be a string.
fn nextString(s: *scan.Scanner) error{Unsupported}![]const u8 {
    try nextElement(s);
    if (s.peek() != '"') return error.Unsupported;
    return s.string();
}

fn scanBool(s: *scan.Scanner) error{Unsupported}!bool {
    switch (s.peek()) {
        't' => {
            try s.literal("true");
            return true;
        },
        'f' => {
            try s.literal("false");
            return false;
        },
        else => return error.Unsupported,
    }
}

/// `{"count": N, "approximate"?: bool, "hll"?: string}`, each key at most once
/// and no other, which is everything NIP-45 puts there.
fn scanCountObject(s: *scan.Scanner) error{Unsupported}!struct { count: u64, approximate: ?bool } {
    try s.expect('{');
    s.skipWs();
    var count: ?u64 = null;
    var approximate: ?bool = null;
    var hll = false;
    while (true) {
        if (s.peek() != '"') return error.Unsupported;
        const key = try s.string();
        s.skipWs();
        try s.expect(':');
        s.skipWs();
        if (std.mem.eql(u8, key, "count")) {
            if (count != null) return error.Unsupported;
            count = try s.int(u64);
        } else if (std.mem.eql(u8, key, "approximate")) {
            if (approximate != null) return error.Unsupported;
            approximate = try scanBool(s);
        } else if (std.mem.eql(u8, key, "hll")) {
            if (hll or s.peek() != '"') return error.Unsupported;
            hll = true;
            _ = try s.string();
        } else return error.Unsupported;
        s.skipWs();
        switch (s.peek()) {
            ',' => {
                s.i += 1;
                s.skipWs();
            },
            '}' => {
                s.i += 1;
                break;
            },
            else => return error.Unsupported,
        }
    }
    return .{ .count = count orelse return error.Unsupported, .approximate = approximate };
}

/// The relay message, read through a `std.json.Value` tree into `allocator`.
/// What `parseRelayMessage` falls back to, and the reference it is tested
/// against.
fn relayMessageFromTree(allocator: std.mem.Allocator, json_text: []const u8) Error!RelayMessage {
    // Out of memory is not a malformed message, and a caller that skips
    // malformed messages would otherwise drop a good one without a word.
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, json_text, .{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => Error.InvalidMessage,
    };
    const items = switch (root) {
        .array => |a| a.items,
        else => return Error.InvalidMessage,
    };
    if (items.len < 1) return Error.InvalidMessage;
    const tag = asString(items[0]) orelse return Error.InvalidMessage;

    const value: RelayMessage = if (std.mem.eql(u8, tag, "EVENT")) blk: {
        if (items.len < 3) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        const ev = event_mod.fromValueLeaky(allocator, items[2]) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => Error.InvalidMessage,
        };
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
    } else if (std.mem.eql(u8, tag, "COUNT")) blk: {
        if (items.len < 3) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        const obj = switch (items[2]) {
            .object => |o| o,
            else => return Error.InvalidMessage,
        };
        const n = asUint(obj.get("count") orelse return Error.InvalidMessage) orelse return Error.InvalidMessage;
        const approximate: ?bool = if (obj.get("approximate")) |a|
            (asBool(a) orelse return Error.InvalidMessage)
        else
            null;
        break :blk .{ .count = .{ .subscription_id = sub, .count = n, .approximate = approximate } };
    } else if (std.mem.eql(u8, tag, "NEG-MSG")) blk: {
        if (items.len < 3) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        const h = asNegHex(items[2]) orelse return Error.InvalidMessage;
        break :blk .{ .neg_msg = .{ .sub_id = sub, .hex = h } };
    } else if (std.mem.eql(u8, tag, "NEG-ERR")) blk: {
        if (items.len < 3) return Error.InvalidMessage;
        const sub = asString(items[1]) orelse return Error.InvalidMessage;
        const reason = asString(items[2]) orelse return Error.InvalidMessage;
        break :blk .{ .neg_err = .{ .sub_id = sub, .reason = reason } };
    } else {
        return Error.InvalidMessage;
    };

    return value;
}

// ---------------------------------------------------------------------------
// Client -> relay (parsing), for code that plays the relay
// ---------------------------------------------------------------------------

/// The most filters one `REQ` or `COUNT` may carry.
pub const max_filters = 64;

/// The longest subscription id NIP-01 allows.
pub const max_subscription_id_len = 64;

/// The longest negentropy hex payload accepted, in hex characters.
/// `nip77.default_frame_size_limit` is held below half of this at compile
/// time, so a peer on default options never sends more.
pub const max_neg_hex_len = 1 << 20;

/// A message received from a client.
pub const ClientMessage = union(enum) {
    /// `["EVENT", <event>]`: a publish.
    event: Event,
    /// `["REQ", <subscription_id>, <filter>...]`.
    req: struct { subscription_id: []const u8, filters: []const Filter },
    /// `["CLOSE", <subscription_id>]`.
    close: struct { subscription_id: []const u8 },
    /// `["AUTH", <event>]`: the NIP-42 response.
    auth: Event,
    /// `["COUNT", <subscription_id>, <filter>...]` (NIP-45).
    count: struct { subscription_id: []const u8, filters: []const Filter },
    /// `["NEG-OPEN", <subscription_id>, <filter>, <initial_hex>]` (NIP-77).
    neg_open: struct { sub_id: []const u8, filter: Filter, initial_hex: []const u8 },
    /// `["NEG-MSG", <subscription_id>, <hex>]` (NIP-77).
    neg_msg: struct { sub_id: []const u8, hex: []const u8 },
    /// `["NEG-CLOSE", <subscription_id>]` (NIP-77).
    neg_close: struct { sub_id: []const u8 },
};

pub const ParsedClientMessage = struct {
    arena: *std.heap.ArenaAllocator,
    value: ClientMessage,

    pub fn deinit(self: *ParsedClientMessage) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses one client message. The returned value owns an arena backing its
/// borrowed fields; call `deinit` to free it. Subscription ids must be 1 to 64
/// bytes, filters must carry full-length hex ids and pubkeys, and a `REQ`
/// or `COUNT` carries 1 to `max_filters` filters. A `limit` above `u32` is
/// read as the largest `u32`. Unknown filter keys
/// are skipped, as NIP-01 asks of a relay.
///
/// An `EVENT` or `AUTH` is read in one pass, the way `parseRelayMessage`
/// reads a relay's `EVENT`; every other message, and anything that pass does
/// not take, goes through a `std.json.Value` tree, so what is accepted and
/// every error returned are what that path alone gives.
pub fn parseClientMessage(gpa: std.mem.Allocator, json_text: []const u8) Error!ParsedClientMessage {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    const owned_text = try allocator.dupe(u8, json_text);
    if (scanClientEvent(allocator, owned_text)) |value| {
        return .{ .arena = arena, .value = value };
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unsupported => {},
    }
    _ = arena.reset(.retain_capacity);
    return .{ .arena = arena, .value = try clientMessageFromTree(allocator, json_text) };
}

/// `["EVENT", <event>]` or `["AUTH", <event>]` in one pass; everything else is
/// `Unsupported`.
fn scanClientEvent(allocator: std.mem.Allocator, buf: []u8) scan.ScanError!ClientMessage {
    var s: scan.Scanner = .{ .buf = buf };
    const tag = try openEnvelope(&s);
    const is_event = std.mem.eql(u8, tag, "EVENT");
    if (!is_event and !std.mem.eql(u8, tag, "AUTH")) return error.Unsupported;
    try nextElement(&s);
    const ev = try scan.eventObject(allocator, &s, .refuse);
    try closeEnvelope(&s);
    return if (is_event) .{ .event = ev } else .{ .auth = ev };
}

/// The client message, read through a `std.json.Value` tree into
/// `allocator`: the fallback of `parseClientMessage` and its test reference.
fn clientMessageFromTree(allocator: std.mem.Allocator, json_text: []const u8) Error!ClientMessage {
    const root = std.json.parseFromSliceLeaky(std.json.Value, allocator, json_text, .{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => Error.InvalidMessage,
    };
    const items = switch (root) {
        .array => |a| a.items,
        else => return Error.InvalidMessage,
    };
    if (items.len < 1) return Error.InvalidMessage;
    const tag = asString(items[0]) orelse return Error.InvalidMessage;

    const value: ClientMessage = if (std.mem.eql(u8, tag, "EVENT")) blk: {
        if (items.len != 2) return Error.InvalidMessage;
        break :blk .{ .event = try eventFromValue(allocator, items[1]) };
    } else if (std.mem.eql(u8, tag, "AUTH")) blk: {
        if (items.len != 2) return Error.InvalidMessage;
        break :blk .{ .auth = try eventFromValue(allocator, items[1]) };
    } else if (std.mem.eql(u8, tag, "REQ")) blk: {
        if (items.len < 2) return Error.InvalidMessage;
        const sub = asSubId(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .req = .{ .subscription_id = sub, .filters = try filtersFromValues(allocator, items[2..]) } };
    } else if (std.mem.eql(u8, tag, "COUNT")) blk: {
        if (items.len < 2) return Error.InvalidMessage;
        const sub = asSubId(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .count = .{ .subscription_id = sub, .filters = try filtersFromValues(allocator, items[2..]) } };
    } else if (std.mem.eql(u8, tag, "CLOSE")) blk: {
        if (items.len != 2) return Error.InvalidMessage;
        const sub = asSubId(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .close = .{ .subscription_id = sub } };
    } else if (std.mem.eql(u8, tag, "NEG-OPEN")) blk: {
        if (items.len != 4) return Error.InvalidMessage;
        const sub = asSubId(items[1]) orelse return Error.InvalidMessage;
        const f = try filterFromValue(allocator, items[2]);
        const h = asNegHex(items[3]) orelse return Error.InvalidMessage;
        break :blk .{ .neg_open = .{ .sub_id = sub, .filter = f, .initial_hex = h } };
    } else if (std.mem.eql(u8, tag, "NEG-MSG")) blk: {
        if (items.len != 3) return Error.InvalidMessage;
        const sub = asSubId(items[1]) orelse return Error.InvalidMessage;
        const h = asNegHex(items[2]) orelse return Error.InvalidMessage;
        break :blk .{ .neg_msg = .{ .sub_id = sub, .hex = h } };
    } else if (std.mem.eql(u8, tag, "NEG-CLOSE")) blk: {
        if (items.len != 2) return Error.InvalidMessage;
        const sub = asSubId(items[1]) orelse return Error.InvalidMessage;
        break :blk .{ .neg_close = .{ .sub_id = sub } };
    } else {
        return Error.InvalidMessage;
    };

    return value;
}

fn eventFromValue(allocator: std.mem.Allocator, v: std.json.Value) Error!Event {
    return event_mod.fromValueLeaky(allocator, v) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => Error.InvalidMessage,
    };
}

fn filtersFromValues(allocator: std.mem.Allocator, vals: []const std.json.Value) Error![]const Filter {
    if (vals.len == 0 or vals.len > max_filters) return Error.InvalidMessage;
    const out = try allocator.alloc(Filter, vals.len);
    for (vals, out) |v, *f| f.* = try filterFromValue(allocator, v);
    return out;
}

/// Reads one filter object. Only the fields `Filter` carries are read; ids and
/// authors must be full 64-character hex, kinds must fit a `u16`, and `#x`
/// keys must name a single ASCII letter and hold an array of strings.
fn filterFromValue(allocator: std.mem.Allocator, v: std.json.Value) Error!Filter {
    const obj = switch (v) {
        .object => |o| o,
        else => return Error.InvalidMessage,
    };
    var f: Filter = .{};
    var tag_list: std.ArrayList(filter_mod.TagFilter) = .empty;
    var it = obj.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const val = entry.value_ptr.*;
        if (std.mem.eql(u8, key, "ids")) {
            f.ids = try hashArray(allocator, val);
        } else if (std.mem.eql(u8, key, "authors")) {
            f.authors = try hashArray(allocator, val);
        } else if (std.mem.eql(u8, key, "kinds")) {
            const arr = asArray(val) orelse return Error.InvalidMessage;
            const kinds = try allocator.alloc(u16, arr.len);
            for (arr, kinds) |k, *out| {
                const n = asUint(k) orelse return Error.InvalidMessage;
                out.* = std.math.cast(u16, n) orelse return Error.InvalidMessage;
            }
            f.kinds = kinds;
        } else if (std.mem.eql(u8, key, "since")) {
            f.since = asInt(val) orelse return Error.InvalidMessage;
        } else if (std.mem.eql(u8, key, "until")) {
            f.until = asInt(val) orelse return Error.InvalidMessage;
        } else if (std.mem.eql(u8, key, "limit")) {
            const n = asUint(val) orelse return Error.InvalidMessage;
            // Past u32 is still just "as many as you have".
            f.limit = std.math.cast(u32, n) orelse std.math.maxInt(u32);
        } else if (std.mem.eql(u8, key, "search")) {
            f.search = asString(val) orelse return Error.InvalidMessage;
        } else if (key.len == 2 and key[0] == '#') {
            if (!std.ascii.isAlphabetic(key[1])) continue;
            const arr = asArray(val) orelse return Error.InvalidMessage;
            const values = try allocator.alloc([]const u8, arr.len);
            for (arr, values) |s, *out| out.* = asString(s) orelse return Error.InvalidMessage;
            try tag_list.append(allocator, .{ .letter = key[1], .values = values });
        }
    }
    if (tag_list.items.len > 0) f.tags = try tag_list.toOwnedSlice(allocator);
    return f;
}

fn hashArray(allocator: std.mem.Allocator, v: std.json.Value) Error![]const [32]u8 {
    const arr = asArray(v) orelse return Error.InvalidMessage;
    const out = try allocator.alloc([32]u8, arr.len);
    for (arr, out) |e, *h| {
        const s = asString(e) orelse return Error.InvalidMessage;
        h.* = hex.decodeFixed(32, s) catch return Error.InvalidMessage;
    }
    return out;
}

fn asArray(v: std.json.Value) ?[]const std.json.Value {
    return switch (v) {
        .array => |a| a.items,
        else => null,
    };
}

fn asInt(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |i| i,
        else => null,
    };
}

fn asUint(v: std.json.Value) ?u64 {
    return switch (v) {
        .integer => |i| std.math.cast(u64, i),
        // Counts past the i64 range arrive as a digit string.
        .number_string => |s| std.fmt.parseInt(u64, s, 10) catch null,
        else => null,
    };
}

/// A subscription id: a string of 1 to 64 bytes.
fn asSubId(v: std.json.Value) ?[]const u8 {
    const s = asString(v) orelse return null;
    if (s.len == 0 or s.len > max_subscription_id_len) return null;
    return s;
}

/// A negentropy payload: an even-length hex string, bounded.
fn asNegHex(v: std.json.Value) ?[]const u8 {
    const s = asString(v) orelse return null;
    return if (isNegHex(s)) s else null;
}

fn isNegHex(s: []const u8) bool {
    if (s.len > max_neg_hex_len or s.len % 2 != 0) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
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

test "parse EVENT message whose event carries a field NIP-01 does not name" {
    const allocator = std.testing.allocator;
    const j = try encodeEvent(allocator, sampleEvent());
    defer allocator.free(j);
    const inner = j["[\"EVENT\",{".len .. j.len - 1];
    const framed = try std.fmt.allocPrint(allocator, "[\"EVENT\",\"sub1\",{{\"seen\":[1,2],{s}]", .{inner});
    defer allocator.free(framed);

    var parsed = try parseRelayMessage(allocator, framed);
    defer parsed.deinit();
    switch (parsed.value) {
        .event => |e| {
            try std.testing.expectEqualStrings("sub1", e.subscription_id);
            try std.testing.expectEqualSlices(u8, &sampleEvent().id, &e.event.id);
        },
        else => return error.WrongVariant,
    }
}

test "parse EVENT refuses an event naming the same field twice" {
    const allocator = std.testing.allocator;
    const twice = "[\"EVENT\",\"s\",{\"id\":\"" ++ "00" ** 32 ++ "\",\"pubkey\":\"" ++ "00" ** 32 ++ "\",\"created_at\":0,\"kind\":1,\"tags\":[],\"content\":\"a\",\"content\":\"b\",\"sig\":\"" ++ "00" ** 64 ++ "\"}]";
    try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, twice));
}

fn parseAndFree(allocator: std.mem.Allocator, text: []const u8) !void {
    var parsed = try parseRelayMessage(allocator, text);
    parsed.deinit();
}

test "running out of memory is reported as that, not as a malformed message" {
    const allocator = std.testing.allocator;
    // Enough tags that the event's own conversion has to grow the parse arena,
    // so its allocations reach the failing allocator too and not only the
    // outer parse's.
    var ev = sampleEvent();
    const one: event_mod.Tag = &[_][]const u8{ "p", test_pubkey };
    const tags = [_]event_mod.Tag{one} ** 256;
    ev.tags = &tags;
    const j = try encodeEvent(allocator, ev);
    defer allocator.free(j);
    const framed = try std.fmt.allocPrint(allocator, "[\"EVENT\",\"sub1\",{s}]", .{j["[\"EVENT\",".len .. j.len - 1]});
    defer allocator.free(framed);

    // Fails every allocation in turn, and requires each failure to come back
    // as OutOfMemory, with nothing leaked.
    try std.testing.checkAllAllocationFailures(allocator, parseAndFree, .{framed});
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

fn expectSameEvent(a: Event, b: Event) !void {
    try std.testing.expectEqualSlices(u8, &a.id, &b.id);
    try std.testing.expectEqualSlices(u8, &a.pubkey, &b.pubkey);
    try std.testing.expectEqualSlices(u8, &a.sig, &b.sig);
    try std.testing.expectEqual(a.created_at, b.created_at);
    try std.testing.expectEqual(a.kind, b.kind);
    try std.testing.expectEqualStrings(a.content, b.content);
}

fn fullFilter() Filter {
    const S = struct {
        const ids = [_][32]u8{hb("d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40")};
        const authors = [_][32]u8{hb(test_pubkey)};
        const kinds = [_]u16{ 1, 7, 30023 };
        const vals = [_][]const u8{ "a", "b\"c" };
        const tags = [_]filter_mod.TagFilter{.{ .letter = 't', .values = &vals }};
    };
    return .{
        .ids = &S.ids,
        .authors = &S.authors,
        .kinds = &S.kinds,
        .tags = &S.tags,
        .since = 10,
        .until = 20,
        .limit = 5,
        .search = "hi \"there\"",
    };
}

fn expectSameFilter(a: Filter, b: Filter) !void {
    const allocator = std.testing.allocator;
    var la: std.ArrayList(u8) = .empty;
    defer la.deinit(allocator);
    var lb: std.ArrayList(u8) = .empty;
    defer lb.deinit(allocator);
    try a.appendJson(&la, allocator);
    try b.appendJson(&lb, allocator);
    try std.testing.expectEqualStrings(la.items, lb.items);
}

test "COUNT round trips on both sides" {
    const allocator = std.testing.allocator;
    const filters = [_]Filter{ fullFilter(), .{ .kinds = &[_]u16{1} } };
    const s = try encodeCount(allocator, "c\"1", &filters);
    defer allocator.free(s);
    var p = try parseClientMessage(allocator, s);
    defer p.deinit();
    try std.testing.expectEqualStrings("c\"1", p.value.count.subscription_id);
    try std.testing.expectEqual(@as(usize, 2), p.value.count.filters.len);
    try expectSameFilter(filters[0], p.value.count.filters[0]);
    try expectSameFilter(filters[1], p.value.count.filters[1]);

    inline for (.{ @as(?bool, null), true, false }) |ap| {
        const r = try encodeCountReply(allocator, "c1", 18446744073709551615, ap);
        defer allocator.free(r);
        var rp = try parseRelayMessage(allocator, r);
        defer rp.deinit();
        try std.testing.expectEqualStrings("c1", rp.value.count.subscription_id);
        try std.testing.expectEqual(@as(u64, 18446744073709551615), rp.value.count.count);
        try std.testing.expectEqual(ap, rp.value.count.approximate);
    }
}

test "parse COUNT reply ignores hll and rejects bad shapes" {
    const allocator = std.testing.allocator;
    var p = try parseRelayMessage(allocator, "[\"COUNT\",\"s\",{\"count\":5,\"hll\":\"00ff\",\"extra\":1}]");
    defer p.deinit();
    try std.testing.expectEqual(@as(u64, 5), p.value.count.count);
    try std.testing.expectEqual(@as(?bool, null), p.value.count.approximate);

    const bad = [_][]const u8{
        "[\"COUNT\",\"s\"]",
        "[\"COUNT\",\"s\",5]",
        "[\"COUNT\",\"s\",{}]",
        "[\"COUNT\",\"s\",{\"count\":-1}]",
        "[\"COUNT\",\"s\",{\"count\":1.5}]",
        "[\"COUNT\",\"s\",{\"count\":\"5\"}]",
        "[\"COUNT\",\"s\",{\"count\":5,\"approximate\":1}]",
        "[\"COUNT\",7,{\"count\":5}]",
    };
    for (bad) |t| try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, t));
}

test "relay replies round trip" {
    const allocator = std.testing.allocator;
    const id = hb("d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40");

    {
        const s = try encodeEventMsg(allocator, "sub\n1", sampleEvent());
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("sub\n1", p.value.event.subscription_id);
        try expectSameEvent(sampleEvent(), p.value.event.event);
    }
    inline for (.{ true, false }) |acc| {
        const s = try encodeOk(allocator, id, acc, "blocked: \"x\"\\");
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualSlices(u8, &id, &p.value.ok.event_id);
        try std.testing.expectEqual(acc, p.value.ok.accepted);
        try std.testing.expectEqualStrings("blocked: \"x\"\\", p.value.ok.message);
    }
    {
        const s = try encodeEose(allocator, "s");
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("s", p.value.eose.subscription_id);
    }
    {
        const s = try encodeClosed(allocator, "s", "auth-required: \u{e9}");
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("s", p.value.closed.subscription_id);
        try std.testing.expectEqualStrings("auth-required: \u{e9}", p.value.closed.message);
    }
    {
        const s = try encodeNotice(allocator, "line\nbreak\x01");
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("line\nbreak\x01", p.value.notice.message);
    }
    {
        const s = try encodeAuthChallenge(allocator, "chal");
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("chal", p.value.auth.challenge);
    }
}

test "NIP-77 envelopes round trip" {
    const allocator = std.testing.allocator;
    const f = fullFilter();
    {
        const s = try encodeNegOpen(allocator, "n1", f, "6100000a");
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("n1", p.value.neg_open.sub_id);
        try expectSameFilter(f, p.value.neg_open.filter);
        try std.testing.expectEqualStrings("6100000a", p.value.neg_open.initial_hex);
    }
    {
        const s = try encodeNegMsg(allocator, "n1", "");
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("", p.value.neg_msg.hex);
        var r = try parseRelayMessage(allocator, s);
        defer r.deinit();
        try std.testing.expectEqualStrings("n1", r.value.neg_msg.sub_id);
        try std.testing.expectEqualStrings("", r.value.neg_msg.hex);
    }
    {
        const s = try encodeNegClose(allocator, "n1");
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("n1", p.value.neg_close.sub_id);
    }
    {
        const s = try encodeNegErr(allocator, "n1", "blocked: too many rows");
        defer allocator.free(s);
        var p = try parseRelayMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("n1", p.value.neg_err.sub_id);
        try std.testing.expectEqualStrings("blocked: too many rows", p.value.neg_err.reason);
    }
}

test "parseClientMessage round trips EVENT, REQ, CLOSE and AUTH" {
    const allocator = std.testing.allocator;
    {
        const s = try encodeEvent(allocator, sampleEvent());
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try expectSameEvent(sampleEvent(), p.value.event);
    }
    {
        const s = try encodeAuth(allocator, sampleEvent());
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try expectSameEvent(sampleEvent(), p.value.auth);
    }
    {
        const filters = [_]Filter{ fullFilter(), .{} };
        const s = try encodeReq(allocator, "r", &filters);
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("r", p.value.req.subscription_id);
        try std.testing.expectEqual(@as(usize, 2), p.value.req.filters.len);
        try expectSameFilter(filters[0], p.value.req.filters[0]);
        try expectSameFilter(filters[1], p.value.req.filters[1]);
    }
    {
        const s = try encodeClose(allocator, "r");
        defer allocator.free(s);
        var p = try parseClientMessage(allocator, s);
        defer p.deinit();
        try std.testing.expectEqualStrings("r", p.value.close.subscription_id);
    }
}

test "parseClientMessage skips unknown filter keys and non-letter tag keys" {
    const allocator = std.testing.allocator;
    var p = try parseClientMessage(allocator, "[\"REQ\",\"s\",{\"kinds\":[1],\"weird\":{\"a\":1},\"#1\":[3],\"#e\":[\"x\"]}]");
    defer p.deinit();
    const f = p.value.req.filters[0];
    try std.testing.expectEqual(@as(u16, 1), f.kinds.?[0]);
    try std.testing.expectEqual(@as(usize, 1), f.tags.?.len);
    try std.testing.expectEqual(@as(u8, 'e'), f.tags.?[0].letter);
}

test "parseClientMessage rejects malformed input" {
    const allocator = std.testing.allocator;
    const id = "d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40";
    const bad = [_][]const u8{
        "not json",
        "{}",
        "[]",
        "[1]",
        "[\"WAT\"]",
        // arity
        "[\"EVENT\"]",
        "[\"EVENT\"," ++ "{}" ++ ",{}]",
        "[\"AUTH\"]",
        "[\"REQ\"]",
        "[\"CLOSE\"]",
        "[\"CLOSE\",\"a\",\"b\"]",
        "[\"COUNT\"]",
        "[\"NEG-OPEN\",\"a\",{}]",
        "[\"NEG-OPEN\",\"a\",{},\"00\",\"extra\"]",
        "[\"NEG-MSG\",\"a\"]",
        "[\"NEG-CLOSE\"]",
        // types
        "[\"EVENT\",\"x\"]",
        "[\"REQ\",5]",
        "[\"REQ\",\"a\",5]",
        "[\"REQ\",\"a\",[]]",
        "[\"CLOSE\",null]",
        "[\"NEG-MSG\",\"a\",5]",
        "[\"NEG-OPEN\",\"a\",\"f\",\"00\"]",
        // sub id bounds
        "[\"CLOSE\",\"\"]",
        "[\"CLOSE\",\"" ++ "a" ** 65 ++ "\"]",
        // filter fields
        "[\"REQ\",\"a\",{\"ids\":\"x\"}]",
        "[\"REQ\",\"a\",{\"ids\":[\"abcd\"]}]",
        "[\"REQ\",\"a\",{\"ids\":[\"" ++ "g" ** 64 ++ "\"]}]",
        "[\"REQ\",\"a\",{\"ids\":[5]}]",
        "[\"REQ\",\"a\",{\"authors\":[\"" ++ id ++ "00\"]}]",
        "[\"REQ\",\"a\",{\"kinds\":[65536]}]",
        "[\"REQ\",\"a\",{\"kinds\":[-1]}]",
        "[\"REQ\",\"a\",{\"kinds\":[1.5]}]",
        "[\"REQ\",\"a\",{\"kinds\":1}]",
        "[\"REQ\",\"a\",{\"limit\":-1}]",
        "[\"REQ\",\"a\",{\"since\":\"1\"}]",
        "[\"REQ\",\"a\",{\"until\":1.5}]",
        "[\"REQ\",\"a\",{\"search\":5}]",
        "[\"REQ\",\"a\",{\"#e\":\"x\"}]",
        "[\"REQ\",\"a\",{\"#e\":[1]}]",
        // negentropy hex
        "[\"NEG-MSG\",\"a\",\"abc\"]",
        "[\"NEG-MSG\",\"a\",\"zz\"]",
        "[\"NEG-OPEN\",\"a\",{},\"0\"]",
    };
    for (bad) |t| try std.testing.expectError(Error.InvalidMessage, parseClientMessage(allocator, t));
    // The relay-side parse refuses the same bad hex.
    try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, "[\"NEG-MSG\",\"a\",\"abc\"]"));
    try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, "[\"NEG-MSG\",\"a\",\"zz\"]"));
    try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, "[\"NEG-ERR\",\"a\"]"));
    try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(allocator, "[\"NEG-ERR\",\"a\",5]"));
}

test "parseClientMessage refuses oversized input" {
    const allocator = std.testing.allocator;

    // Too many filters.
    var many: std.ArrayList(u8) = .empty;
    defer many.deinit(allocator);
    try many.appendSlice(allocator, "[\"REQ\",\"a\"");
    for (0..max_filters + 1) |_| try many.appendSlice(allocator, ",{}");
    try many.append(allocator, ']');
    try std.testing.expectError(Error.InvalidMessage, parseClientMessage(allocator, many.items));
    // One fewer is fine.
    many.items.len -= 4;
    many.appendAssumeCapacity(']');
    var ok = try parseClientMessage(allocator, many.items);
    ok.deinit();

    // A negentropy payload over the cap.
    const big = try allocator.alloc(u8, max_neg_hex_len + 4);
    defer allocator.free(big);
    @memset(big, '0');
    big[0] = '"';
    big[big.len - 1] = '"';
    const text = try std.fmt.allocPrint(allocator, "[\"NEG-MSG\",\"a\",{s}]", .{big});
    defer allocator.free(text);
    try std.testing.expectError(Error.InvalidMessage, parseClientMessage(allocator, text));
}

test "running out of memory while parsing a client message is reported as that" {
    const text = "[\"REQ\",\"s\"," ++ "{\"ids\":[\"" ++ "00" ** 32 ++ "\"],\"kinds\":[1,2],\"#e\":[\"a\"],\"search\":\"x\"}" ++ "]";
    const f = struct {
        fn run(allocator: std.mem.Allocator, t: []const u8) !void {
            var p = try parseClientMessage(allocator, t);
            p.deinit();
        }
    }.run;
    try std.testing.checkAllAllocationFailures(std.testing.allocator, f, .{@as([]const u8, text)});
}

test "a REQ or COUNT with no filter is refused, and a limit past u32 is clamped" {
    const a = std.testing.allocator;
    // A REQ with nothing to match is not a subscription: NIP-01 gives it at
    // least one filter, and a relay that took it would have to guess.
    try std.testing.expectError(Error.InvalidMessage, parseClientMessage(a, "[\"REQ\",\"s\"]"));
    try std.testing.expectError(Error.InvalidMessage, parseClientMessage(a, "[\"COUNT\",\"s\"]"));

    // A limit larger than anything a relay would return is a large limit, not
    // a broken message.
    var p = try parseClientMessage(a, "[\"REQ\",\"s\",{\"limit\":5000000000}]");
    defer p.deinit();
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32)), p.value.req.filters[0].limit);
}

// -- The one-pass parsers against the std.json ones they replaced -------------

const reference = @import("message_reference.zig");

test "parseRelayMessage and parseClientMessage agree with std.json on generated messages" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x656e_7665_6c6f_7065);
    const e: reference.Envelopes = .{ .g = .{ .rand = prng.random(), .arena = arena_state.allocator() } };

    for (0..4000) |_| {
        const relay_text = try e.relay();
        try reference.expectSameRelayMessage(relay_text);
        try reference.expectSameRelayMessage(try e.g.mutate(relay_text));
        const client_text = try e.client();
        try reference.expectSameClientMessage(client_text);
        try reference.expectSameClientMessage(try e.g.mutate(client_text));
        _ = arena_state.reset(.retain_capacity);
    }
}

test "parseRelayMessage agrees with std.json at the edges" {
    const z32 = "\"" ++ "00" ** 32 ++ "\"";
    const z64 = "\"" ++ "00" ** 64 ++ "\"";
    const ev = "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"created_at\":1,\"kind\":1,\"tags\":[[\"e\",\"x\"]],\"content\":\"hi\",\"sig\":" ++ z64 ++ "}";
    const cases = [_][]const u8{
        "[\"EVENT\",\"s\"," ++ ev ++ "]",
        " [ \"EVENT\" , \"s\" , " ++ ev ++ " ] ",
        "[\"EVENT\",\"s\"," ++ ev ++ ",1]",
        "[\"EVENT\",\"s\"," ++ ev ++ ",{\"a\":1,\"a\":2}]",
        "[\"EVENT\",\"s\"]",
        "[\"EVENT\",1," ++ ev ++ "]",
        "[\"EVENT\",\"s\"," ++ ev ++ "] x",
        "[\"EVENT\",\"s\"," ++ ev ++ "",
        "[\"\\u0045VENT\",\"\\u00e9\"," ++ ev ++ "]",
        "[\"EVENT\",\"s\",{\"x\":{\"a\":1,\"a\":2},\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":" ++ z64 ++ "}]",
        "[\"EVENT\",\"s\",{\"x\":1,\"x\":2,\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":" ++ z64 ++ "}]",
        "[\"EVENT\",\"s\",{\"x\":1,\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":" ++ z64 ++ "}]",
        "[\"EVENT\",\"s\",{\"id\":" ++ z32 ++ ",\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"created_at\":1,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":" ++ z64 ++ "}]",
        "[\"OK\"," ++ z32 ++ ",true,\"\"]",
        "[\"OK\"," ++ z32 ++ ",false,\"blocked: no\"]",
        "[\"OK\"," ++ z32 ++ ",null,\"\"]",
        "[\"OK\",\"\\u0030" ++ "0" ** 63 ++ "\",true,\"\"]",
        "[\"OK\",\"" ++ "AB" ** 32 ++ "\",true,\"\"]",
        "[\"OK\"," ++ z32 ++ ",true]",
        "[\"OK\"," ++ z32 ++ ",truex,\"\"]",
        "[\"EOSE\",\"s\"]",
        "[\"EOSE\",\"\"]",
        "[\"EOSE\"]",
        "[\"CLOSED\",\"s\",\"auth-required: x\"]",
        "[\"NOTICE\",\"a\\nb\\ud83d\\ude00\"]",
        "[\"NOTICE\",\"\\ud83d\"]",
        "[\"NOTICE\",\"\xc3\"]",
        "[\"AUTH\",\"challenge\"]",
        "[\"AUTH\"," ++ ev ++ "]",
        "[\"COUNT\",\"s\",{\"count\":5}]",
        "[\"COUNT\",\"s\",{\"count\":5,\"approximate\":true,\"hll\":\"00ff\"}]",
        "[\"COUNT\",\"s\",{\"count\":5,\"approximate\":null}]",
        "[\"COUNT\",\"s\",{\"count\":5,\"count\":6}]",
        "[\"COUNT\",\"s\",{\"count\":18446744073709551615}]",
        "[\"COUNT\",\"s\",{\"count\":18446744073709551616}]",
        "[\"COUNT\",\"s\",{\"count\":-0}]",
        "[\"COUNT\",\"s\",{\"count\":1e2}]",
        "[\"COUNT\",\"s\",{\"count\":5,\"other\":[1]}]",
        "[\"COUNT\",\"s\",{\"count\":5,\"hll\":{\"a\":1,\"a\":1}}]",
        "[\"COUNT\",\"s\",{}]",
        "[\"NEG-MSG\",\"s\",\"61ab\"]",
        "[\"NEG-MSG\",\"s\",\"61a\"]",
        "[\"NEG-MSG\",\"s\",\"zz\"]",
        "[\"NEG-ERR\",\"s\",\"blocked\"]",
        "[\"UNKNOWN\",\"s\"]",
        "[]",
        "[1]",
        "{}",
        "",
        "[",
    };
    for (cases) |c| try reference.expectSameRelayMessage(c);
    for (cases) |c| try reference.expectSameClientMessage(c);
    const client_cases = [_][]const u8{
        "[\"EVENT\"," ++ ev ++ "]",
        "[\"AUTH\"," ++ ev ++ "]",
        "[\"EVENT\"," ++ ev ++ ",1]",
        "[\"EVENT\"]",
        "[\"EVENT\",\"s\"]",
        "[\"REQ\",\"s\",{\"kinds\":[1]}]",
        "[\"CLOSE\",\"s\"]",
    };
    for (client_cases) |c| try reference.expectSameClientMessage(c);
}

test "a parsed relay message outlives the text it was parsed from" {
    const gpa = std.testing.allocator;
    const ev = sampleEvent();
    const text = try encodeEventMsg(gpa, "sub \\ \u{e9}", ev);
    var parsed = try parseRelayMessage(gpa, text);
    defer parsed.deinit();
    const fresh = try gpa.dupe(u8, text);
    defer gpa.free(fresh);
    @memset(text, 'x');
    gpa.free(text);
    try reference.expectSameRelayMessage(fresh);
    try std.testing.expectEqualStrings("sub \\ \u{e9}", parsed.value.event.subscription_id);
    try expectSameEvent(ev, parsed.value.event.event);
}

test "a created_at of 2^63 written as a float is refused, not a crash" {
    const z32 = "\"" ++ "00" ** 32 ++ "\"";
    const z64 = "\"" ++ "00" ** 64 ++ "\"";
    const body = ",\"pubkey\":" ++ z32 ++ ",\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":" ++ z64 ++ "}";
    for ([_][]const u8{ "9223372036854775807.0", "9223372036854775808.0", "9.223372036854775807e18" }) |n| {
        var buf: [512]u8 = undefined;
        const ev = try std.fmt.bufPrint(&buf, "{{\"id\":{s},\"created_at\":{s}{s}", .{ z32, n, body });
        var relay_buf: [600]u8 = undefined;
        const relay_text = try std.fmt.bufPrint(&relay_buf, "[\"EVENT\",\"s\",{s}]", .{ev});
        try std.testing.expectError(Error.InvalidMessage, parseRelayMessage(std.testing.allocator, relay_text));
        var client_buf: [600]u8 = undefined;
        const client_text = try std.fmt.bufPrint(&client_buf, "[\"EVENT\",{s}]", .{ev});
        try std.testing.expectError(Error.InvalidMessage, parseClientMessage(std.testing.allocator, client_text));
    }
}
