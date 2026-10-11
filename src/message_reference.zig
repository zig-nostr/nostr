//! The relay-message parsers this library used before `message.zig` read
//! messages in one pass, kept frozen as the reference the new code is tested
//! against. Tests only: nothing outside the test build imports it, and
//! `root.zig` does not export it.
//!
//! Both build a `std.json.Value` tree for the whole message and read the
//! fields out of it. Do not optimize this file.

const std = @import("std");
const hex = @import("hex.zig");
const event_mod = @import("event.zig");
const event_reference = @import("event_reference.zig");
const filter_mod = @import("filter.zig");
const message = @import("message.zig");

const Event = event_mod.Event;
const Filter = filter_mod.Filter;
const Error = message.Error;
const RelayMessage = message.RelayMessage;
const ParsedRelayMessage = message.ParsedRelayMessage;
const ClientMessage = message.ClientMessage;
const ParsedClientMessage = message.ParsedClientMessage;
const max_filters = message.max_filters;
const max_subscription_id_len = message.max_subscription_id_len;
const max_neg_hex_len = message.max_neg_hex_len;

pub fn parseRelayMessage(gpa: std.mem.Allocator, json_text: []const u8) Error!ParsedRelayMessage {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

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

    return ParsedRelayMessage{ .arena = arena, .value = value };
}

pub fn parseClientMessage(gpa: std.mem.Allocator, json_text: []const u8) Error!ParsedClientMessage {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

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

    return ParsedClientMessage{ .arena = arena, .value = value };
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
    if (s.len > max_neg_hex_len or s.len % 2 != 0) return null;
    for (s) |c| if (!std.ascii.isHex(c)) return null;
    return s;
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

// -- Comparing the parsers ----------------------------------------------------

/// `message.parseRelayMessage` and the reference agree on `text`: the same
/// message, or the same error.
pub fn expectSameRelayMessage(text: []const u8) !void {
    const gpa = std.testing.allocator;
    var fast = message.parseRelayMessage(gpa, text);
    defer if (fast) |*p| p.deinit() else |_| {};
    var slow = parseRelayMessage(gpa, text);
    defer if (slow) |*p| p.deinit() else |_| {};
    const pair = try agree(ParsedRelayMessage, fast, slow, text) orelse return;
    try expectSameRelay(pair[1].value, pair[0].value);
}

/// `message.parseClientMessage` and the reference agree on `text`.
pub fn expectSameClientMessage(text: []const u8) !void {
    const gpa = std.testing.allocator;
    var fast = message.parseClientMessage(gpa, text);
    defer if (fast) |*p| p.deinit() else |_| {};
    var slow = parseClientMessage(gpa, text);
    defer if (slow) |*p| p.deinit() else |_| {};
    const pair = try agree(ParsedClientMessage, fast, slow, text) orelse return;
    try expectSameClient(pair[1].value, pair[0].value);
}

/// Both failed the same way (null), or both parsed (the pair, fast first).
fn agree(comptime T: type, fast: Error!T, slow: Error!T, text: []const u8) !?[2]T {
    const a = fast catch |fast_err| {
        if (slow) |_| {
            std.debug.print("the scan refused what std.json takes ({t}): {s}\n", .{ fast_err, text });
            return error.TestUnexpectedResult;
        } else |slow_err| {
            if (fast_err != slow_err) {
                std.debug.print("the scan said {t}, std.json {t}: {s}\n", .{ fast_err, slow_err, text });
                return error.TestUnexpectedResult;
            }
        }
        return null;
    };
    const b = slow catch |slow_err| {
        std.debug.print("the scan took what std.json refuses ({t}): {s}\n", .{ slow_err, text });
        return error.TestUnexpectedResult;
    };
    return .{ a, b };
}

fn expectSameRelay(want: RelayMessage, got: RelayMessage) !void {
    const t = std.testing;
    try t.expectEqual(std.meta.activeTag(want), std.meta.activeTag(got));
    switch (want) {
        .event => |w| {
            try t.expectEqualStrings(w.subscription_id, got.event.subscription_id);
            try event_reference.expectSameEvent(w.event, got.event.event);
        },
        .ok => |w| {
            try t.expectEqualSlices(u8, &w.event_id, &got.ok.event_id);
            try t.expectEqual(w.accepted, got.ok.accepted);
            try t.expectEqualStrings(w.message, got.ok.message);
        },
        .eose => |w| try t.expectEqualStrings(w.subscription_id, got.eose.subscription_id),
        .closed => |w| {
            try t.expectEqualStrings(w.subscription_id, got.closed.subscription_id);
            try t.expectEqualStrings(w.message, got.closed.message);
        },
        .notice => |w| try t.expectEqualStrings(w.message, got.notice.message),
        .auth => |w| try t.expectEqualStrings(w.challenge, got.auth.challenge),
        .count => |w| {
            try t.expectEqualStrings(w.subscription_id, got.count.subscription_id);
            try t.expectEqual(w.count, got.count.count);
            try t.expectEqual(w.approximate, got.count.approximate);
        },
        .neg_msg => |w| {
            try t.expectEqualStrings(w.sub_id, got.neg_msg.sub_id);
            try t.expectEqualStrings(w.hex, got.neg_msg.hex);
        },
        .neg_err => |w| {
            try t.expectEqualStrings(w.sub_id, got.neg_err.sub_id);
            try t.expectEqualStrings(w.reason, got.neg_err.reason);
        },
    }
}

fn expectSameClient(want: ClientMessage, got: ClientMessage) !void {
    const t = std.testing;
    try t.expectEqual(std.meta.activeTag(want), std.meta.activeTag(got));
    switch (want) {
        .event => |w| try event_reference.expectSameEvent(w, got.event),
        .auth => |w| try event_reference.expectSameEvent(w, got.auth),
        .close => |w| try t.expectEqualStrings(w.subscription_id, got.close.subscription_id),
        .neg_close => |w| try t.expectEqualStrings(w.sub_id, got.neg_close.sub_id),
        .neg_msg => |w| {
            try t.expectEqualStrings(w.sub_id, got.neg_msg.sub_id);
            try t.expectEqualStrings(w.hex, got.neg_msg.hex);
        },
        // Neither side reads these in one pass, so both run the same code;
        // the shape is enough.
        .req => |w| try t.expectEqual(w.filters.len, got.req.filters.len),
        .count => |w| try t.expectEqual(w.filters.len, got.count.filters.len),
        .neg_open => |w| try t.expectEqualStrings(w.initial_hex, got.neg_open.initial_hex),
    }
}

// -- Generated messages -------------------------------------------------------

/// Relay and client messages of every type around generated events, spelled
/// every way JSON allows, sometimes with an element too many or too few or of
/// the wrong type.
pub const Envelopes = struct {
    g: event_reference.Generator,

    fn add(e: Envelopes, out: *std.ArrayList(u8), s: []const u8) !void {
        try out.appendSlice(e.g.arena, s);
    }

    /// A comma between elements, with whitespace around it now and then.
    fn sep(e: Envelopes, out: *std.ArrayList(u8)) !void {
        try e.g.ws(out);
        try out.append(e.g.arena, ',');
        try e.g.ws(out);
    }

    /// A type string: the one asked for, now and then spelled with an escape
    /// or replaced by a near miss.
    fn typeString(e: Envelopes, out: *std.ArrayList(u8), name: []const u8) !void {
        const r = e.g.rand;
        switch (r.uintLessThan(u8, 20)) {
            0 => try e.add(out, "\"\\u0045VENT\""),
            1 => try e.add(out, "\"event\""),
            2 => try e.add(out, "\"NOPE\""),
            3 => try e.add(out, "1"),
            else => try e.g.writeString(out, name),
        }
    }

    /// A value that is not what any slot wants, or is, at random.
    fn anyValue(e: Envelopes, out: *std.ArrayList(u8)) !void {
        const r = e.g.rand;
        switch (r.uintLessThan(u8, 10)) {
            0 => try e.add(out, "null"),
            1 => try e.add(out, "true"),
            2 => try e.add(out, "false"),
            3 => try e.add(out, "-12.5e3"),
            4 => try e.add(out, "18446744073709551616"),
            5 => try e.add(out, "{\"a\":1,\"a\":2}"),
            6 => try e.add(out, "[{\"b\":[]}]"),
            7 => try e.add(out, "{}"),
            else => try e.g.writeString(out, try e.g.string()),
        }
    }

    fn subId(e: Envelopes, out: *std.ArrayList(u8)) !void {
        if (e.g.rand.uintLessThan(u8, 30) == 0) return e.anyValue(out);
        try e.g.writeString(out, try e.g.string());
    }

    fn eventObject(e: Envelopes, out: *std.ArrayList(u8)) !void {
        const r = e.g.rand;
        if (r.uintLessThan(u8, 30) == 0) return e.anyValue(out);
        const ev = try e.g.event();
        if (r.boolean()) {
            try e.add(out, try event_mod.toJson(e.g.arena, ev));
        } else {
            const text = try e.g.text(ev);
            // `text` may carry whitespace around it, which an element may too.
            try e.add(out, text);
        }
    }

    fn negHex(e: Envelopes, out: *std.ArrayList(u8)) !void {
        const r = e.g.rand;
        const n = r.uintLessThan(usize, 40);
        try out.append(e.g.arena, '"');
        for (0..n) |_| try out.append(e.g.arena, "0123456789abcdefABCDEFg"[r.uintLessThan(usize, if (r.uintLessThan(u8, 20) == 0) 23 else 22)]);
        try out.append(e.g.arena, '"');
    }

    fn countObject(e: Envelopes, out: *std.ArrayList(u8)) !void {
        const r = e.g.rand;
        if (r.uintLessThan(u8, 20) == 0) return e.anyValue(out);
        const keys = [_][]const u8{ "count", "approximate", "hll", "other" };
        try out.append(e.g.arena, '{');
        const n = r.uintLessThan(usize, 5);
        var first = true;
        for (0..n) |k| {
            if (!first) try e.sep(out);
            first = false;
            const key = if (k == 0 and r.uintLessThan(u8, 4) != 0) "count" else keys[r.uintLessThan(usize, keys.len)];
            try e.g.writeString(out, key);
            try e.g.ws(out);
            try out.append(e.g.arena, ':');
            try e.g.ws(out);
            if (std.mem.eql(u8, key, "count")) {
                try e.add(out, switch (r.uintLessThan(u8, 10)) {
                    0 => "0",
                    1 => "-1",
                    2 => "-0",
                    3 => "9223372036854775808",
                    4 => "18446744073709551615",
                    5 => "18446744073709551616",
                    6 => "1.0",
                    7 => "007",
                    else => try std.fmt.allocPrint(e.g.arena, "{d}", .{r.int(u32)}),
                });
            } else if (std.mem.eql(u8, key, "approximate")) {
                try e.add(out, if (r.boolean()) "true" else if (r.boolean()) "false" else "null");
            } else if (std.mem.eql(u8, key, "hll")) {
                if (r.uintLessThan(u8, 4) == 0) try e.anyValue(out) else try e.negHex(out);
            } else try e.anyValue(out);
        }
        try out.append(e.g.arena, '}');
    }

    /// The elements after the type; `slots` names what each one should be.
    fn elements(e: Envelopes, out: *std.ArrayList(u8), slots: []const u8) !void {
        const r = e.g.rand;
        // Now and then one too few or one too many.
        const drop = r.uintLessThan(u8, 20) == 0 and slots.len > 0;
        const used = if (drop) slots[0 .. slots.len - 1] else slots;
        for (used) |slot| {
            try e.sep(out);
            switch (slot) {
                's' => try e.subId(out),
                'm' => if (r.uintLessThan(u8, 30) == 0) try e.anyValue(out) else try e.g.writeString(out, try e.g.string()),
                'e' => try e.eventObject(out),
                'i' => if (r.uintLessThan(u8, 20) == 0) try e.anyValue(out) else {
                    var id: [32]u8 = undefined;
                    r.bytes(&id);
                    try e.g.writeHexString(out, &id);
                },
                'b' => try e.add(out, switch (r.uintLessThan(u8, 12)) {
                    0 => "null",
                    1 => "\"true\"",
                    else => if (r.boolean()) "true" else "false",
                }),
                'c' => try e.countObject(out),
                'h' => try e.negHex(out),
                else => unreachable,
            }
        }
        if (r.uintLessThan(u8, 20) == 0) {
            try e.sep(out);
            try e.anyValue(out);
        }
    }

    fn envelope(e: Envelopes, name: []const u8, slots: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        try e.g.ws(&out);
        try out.append(e.g.arena, '[');
        try e.g.ws(&out);
        try e.typeString(&out, name);
        try e.elements(&out, slots);
        try e.g.ws(&out);
        try out.append(e.g.arena, ']');
        try e.g.ws(&out);
        return out.items;
    }

    /// One relay message of a random type.
    pub fn relay(e: Envelopes) ![]u8 {
        const types = [_]struct { []const u8, []const u8 }{
            .{ "EVENT", "se" },   .{ "EVENT", "se" },   .{ "EVENT", "se" },
            .{ "OK", "ibm" },     .{ "EOSE", "s" },     .{ "CLOSED", "sm" },
            .{ "NOTICE", "m" },   .{ "AUTH", "m" },     .{ "COUNT", "sc" },
            .{ "NEG-MSG", "sh" }, .{ "NEG-ERR", "sm" },
        };
        const t = types[e.g.rand.uintLessThan(usize, types.len)];
        return e.envelope(t[0], t[1]);
    }

    /// One client message of a random type, mostly `EVENT` and `AUTH`.
    pub fn client(e: Envelopes) ![]u8 {
        const types = [_]struct { []const u8, []const u8 }{
            .{ "EVENT", "e" },     .{ "EVENT", "e" }, .{ "EVENT", "e" },
            .{ "AUTH", "e" },      .{ "CLOSE", "s" }, .{ "NEG-MSG", "sh" },
            .{ "NEG-CLOSE", "s" },
        };
        const t = types[e.g.rand.uintLessThan(usize, types.len)];
        return e.envelope(t[0], t[1]);
    }
};
