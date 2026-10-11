//! The event JSON code this library used before `event.zig` got its own
//! scanner and serializer, kept frozen as the reference the new code is
//! tested against. Tests only: nothing outside the test build imports it, and
//! `root.zig` does not export it.
//!
//! The parse goes through `std.json` into a typed struct and the serializer
//! appends byte by byte into an `ArrayList`. Both are slow and both are easy
//! to read, which is what a reference is for. Do not optimize this file.

const std = @import("std");
const event_mod = @import("event.zig");
const hex = @import("hex.zig");

const Event = event_mod.Event;
const Tag = event_mod.Tag;

pub fn appendJsonString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) std.mem.Allocator.Error!void {
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
            else => |b| {
                if (b < 0x20) {
                    try list.print(allocator, "\\u{x:0>4}", .{b});
                } else {
                    try list.append(allocator, b);
                }
            },
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

/// sha256 of the canonical serialization.
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

/// Parses wire-format event JSON through `std.json`, into one arena that also
/// holds a copy of the text.
pub fn fromJson(gpa: std.mem.Allocator, json_text: []const u8) !event_mod.Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();
    const owned_text = try allocator.dupe(u8, json_text);
    const wire = try std.json.parseFromSliceLeaky(WireEvent, allocator, owned_text, wire_options);
    return .{
        .arena = arena,
        .value = .{
            .id = try hex.decodeFixed(32, wire.id),
            .pubkey = try hex.decodeFixed(32, wire.pubkey),
            .created_at = wire.created_at,
            .kind = wire.kind,
            .tags = wire.tags,
            .content = wire.content,
            .sig = try hex.decodeFixed(64, wire.sig),
        },
    };
}

// -- Differential checks ------------------------------------------------------

/// Parses `text` with `fromJson` and with the `std.json` reference and fails
/// unless both give the same event or both give the same error. Where both
/// parse, the serializers have to agree byte for byte as well.
pub fn expectSameAsReference(text: []const u8) !void {
    const gpa = std.testing.allocator;
    var fast = event_mod.fromJson(gpa, text);
    defer if (fast) |*p| p.deinit() else |_| {};
    var slow = fromJson(gpa, text);
    defer if (slow) |*p| p.deinit() else |_| {};

    const a = fast catch |fast_err| {
        if (slow) |_| {
            std.debug.print("fromJson refused what std.json takes ({t}): {s}\n", .{ fast_err, text });
            return error.TestUnexpectedResult;
        } else |slow_err| {
            if (fast_err != slow_err) {
                std.debug.print("fromJson said {t}, std.json {t}: {s}\n", .{ fast_err, slow_err, text });
                return error.TestUnexpectedResult;
            }
        }
        return;
    };
    const b = slow catch |slow_err| {
        std.debug.print("fromJson took what std.json refuses ({t}): {s}\n", .{ slow_err, text });
        return error.TestUnexpectedResult;
    };
    try expectSameEvent(b.value, a.value);
    try expectSameSerialization(a.value);
}

fn expectSameEvent(want: Event, got: Event) !void {
    const t = std.testing;
    try t.expectEqualSlices(u8, &want.id, &got.id);
    try t.expectEqualSlices(u8, &want.pubkey, &got.pubkey);
    try t.expectEqual(want.created_at, got.created_at);
    try t.expectEqual(want.kind, got.kind);
    try t.expectEqualSlices(u8, want.content, got.content);
    try t.expectEqualSlices(u8, &want.sig, &got.sig);
    try t.expectEqual(want.tags.len, got.tags.len);
    for (want.tags, got.tags) |wt, gt| {
        try t.expectEqual(wt.len, gt.len);
        for (wt, gt) |ws, gs| try t.expectEqualSlices(u8, ws, gs);
    }
}

/// `toJson`, the canonical form and the id, each against the reference, and
/// each length function against what its writer wrote.
pub fn expectSameSerialization(ev: Event) !void {
    const gpa = std.testing.allocator;
    const t = std.testing;

    const want_json = try toJson(gpa, ev);
    defer gpa.free(want_json);
    const got_json = try event_mod.toJson(gpa, ev);
    defer gpa.free(got_json);
    try t.expectEqualStrings(want_json, got_json);
    try t.expectEqual(got_json.len, event_mod.jsonLen(ev));

    const want_canon = try serializeCanonical(gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    defer gpa.free(want_canon);
    const got_canon = try event_mod.serializeCanonical(gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    defer gpa.free(got_canon);
    try t.expectEqualStrings(want_canon, got_canon);
    try t.expectEqual(got_canon.len, event_mod.canonicalLen(ev.created_at, ev.kind, ev.tags, ev.content));

    // Appending lands after what the list already holds.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try list.appendSlice(gpa, "prefix");
    try event_mod.appendCanonical(&list, gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    try t.expectEqualStrings("prefix", list.items[0..6]);
    try t.expectEqualStrings(want_canon, list.items[6..]);

    const want_id = try computeId(gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    const got_id = try event_mod.computeId(gpa, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    try t.expectEqualSlices(u8, &want_id, &got_id);
}
