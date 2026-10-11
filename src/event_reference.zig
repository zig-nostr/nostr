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

pub fn expectSameEvent(want: Event, got: Event) !void {
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

// -- Generated input for the differential tests -------------------------------

/// Random events, written out with every spelling JSON allows for them, then
/// broken in small ways, for the differential test below.
pub const Generator = struct {
    rand: std.Random,
    arena: std.mem.Allocator,

    /// A code point, weighted towards the ones that need care: the escaped
    /// ASCII bytes, other control bytes, and multi-byte UTF-8 of every length.
    pub fn codePoint(g: Generator) u21 {
        const r = g.rand;
        return switch (r.uintLessThan(u8, 12)) {
            0, 1, 2, 3 => r.intRangeAtMost(u21, 0x20, 0x7e),
            4 => "\"\\/\n\r\t\x08\x0c"[r.uintLessThan(usize, 8)],
            5 => r.uintLessThan(u21, 0x20),
            6 => 0x7f,
            7 => r.intRangeAtMost(u21, 0x80, 0x7ff),
            8 => r.intRangeAtMost(u21, 0x800, 0xd7ff),
            9 => r.intRangeAtMost(u21, 0xe000, 0xffff),
            else => r.intRangeAtMost(u21, 0x10000, 0x10ffff),
        };
    }

    pub fn string(g: Generator) ![]const u8 {
        const r = g.rand;
        const n: usize = switch (r.uintLessThan(u8, 8)) {
            0 => 0,
            1, 2, 3 => r.uintLessThan(usize, 8),
            4, 5 => r.uintLessThan(usize, 40),
            6 => r.uintLessThan(usize, 300),
            else => 64,
        };
        var out: std.ArrayList(u8) = .empty;
        const plain = r.boolean();
        for (0..n) |_| {
            const cp: u21 = if (plain) r.intRangeAtMost(u21, 'a', 'z') else g.codePoint();
            var buf: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(cp, &buf) catch unreachable;
            try out.appendSlice(g.arena, buf[0..len]);
        }
        return out.items;
    }

    pub fn event(g: Generator) !Event {
        const r = g.rand;
        const tag_count: usize = switch (r.uintLessThan(u8, 6)) {
            0 => 0,
            1, 2, 3 => r.uintLessThan(usize, 6),
            4 => r.uintLessThan(usize, 40),
            else => r.uintLessThan(usize, 400),
        };
        const tags = try g.arena.alloc(Tag, tag_count);
        for (tags) |*tag| {
            const fields = try g.arena.alloc([]const u8, r.uintLessThan(usize, 6));
            for (fields) |*f| f.* = try g.string();
            tag.* = fields;
        }
        var ev: Event = .{
            .id = undefined,
            .pubkey = undefined,
            .created_at = switch (r.uintLessThan(u8, 6)) {
                0 => 0,
                1 => std.math.maxInt(i64),
                2 => std.math.minInt(i64),
                3 => -r.intRangeAtMost(i64, 1, 1000),
                else => r.int(i64),
            },
            .kind = switch (r.uintLessThan(u8, 4)) {
                0 => 0,
                1 => std.math.maxInt(u16),
                else => r.int(u16),
            },
            .tags = tags,
            .content = try g.string(),
            .sig = undefined,
        };
        r.bytes(&ev.id);
        r.bytes(&ev.pubkey);
        r.bytes(&ev.sig);
        return ev;
    }

    pub fn ws(g: Generator, out: *std.ArrayList(u8)) !void {
        if (g.rand.uintLessThan(u8, 4) != 0) return;
        for (0..g.rand.intRangeAtMost(usize, 1, 3)) |_| try out.append(g.arena, " \t\n\r"[g.rand.uintLessThan(usize, 4)]);
    }

    /// `s` as a JSON string, each code point spelled raw, with its short
    /// escape, or as `\u` (a surrogate pair above the BMP), at random.
    pub fn writeString(g: Generator, out: *std.ArrayList(u8), s: []const u8) !void {
        const r = g.rand;
        try out.append(g.arena, '"');
        var it = std.unicode.Utf8View.initUnchecked(s).iterator();
        while (it.nextCodepointSlice()) |slice| {
            const cp = std.unicode.utf8Decode(slice) catch unreachable;
            const must = cp < 0x20 or cp == '"' or cp == '\\';
            const choice = r.uintLessThan(u8, 4);
            if (choice == 0 or (must and choice == 1)) {
                if (cp >= 0x10000) {
                    const v = cp - 0x10000;
                    try out.print(g.arena, "\\u{X:0>4}\\u{x:0>4}", .{ 0xD800 + (v >> 10), 0xDC00 + (v & 0x3ff) });
                } else {
                    try out.print(g.arena, "\\u{x:0>4}", .{cp});
                }
            } else if (must or (cp == '/' and choice == 1)) {
                var esc: [6]u8 = undefined;
                try out.appendSlice(g.arena, if (cp == '/') "\\/" else shortEscape(@intCast(cp), &esc));
            } else {
                try out.appendSlice(g.arena, slice);
            }
        }
        try out.append(g.arena, '"');
    }

    pub fn writeHexString(g: Generator, out: *std.ArrayList(u8), bytes: []const u8) !void {
        const digits = if (g.rand.uintLessThan(u8, 8) == 0) "0123456789ABCDEF" else "0123456789abcdef";
        try out.append(g.arena, '"');
        for (bytes) |b| try out.appendSlice(g.arena, &.{ digits[b >> 4], digits[b & 0xf] });
        try out.append(g.arena, '"');
    }

    /// An event object with its fields in a random order, random whitespace,
    /// sometimes an extra key, and numbers sometimes in a form only `std.json`
    /// takes.
    pub fn text(g: Generator, ev: Event) ![]u8 {
        const r = g.rand;
        var out: std.ArrayList(u8) = .empty;
        var order = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
        r.shuffle(u8, &order);
        const with_extra = r.uintLessThan(u8, 4) == 0;
        try g.ws(&out);
        try out.append(g.arena, '{');
        var first = true;
        for (order) |field| {
            if (field == 7 and !with_extra) continue;
            if (!first) try out.append(g.arena, ',');
            first = false;
            try g.ws(&out);
            const name = switch (field) {
                0 => "id",
                1 => "pubkey",
                2 => "created_at",
                3 => "kind",
                4 => "tags",
                5 => "content",
                6 => "sig",
                else => "extra",
            };
            try g.writeString(&out, name);
            try g.ws(&out);
            try out.append(g.arena, ':');
            try g.ws(&out);
            switch (field) {
                0 => try g.writeHexString(&out, &ev.id),
                1 => try g.writeHexString(&out, &ev.pubkey),
                2 => try g.writeNumber(&out, ev.created_at),
                3 => try g.writeNumber(&out, ev.kind),
                4 => {
                    try out.append(g.arena, '[');
                    for (ev.tags, 0..) |tag, ti| {
                        if (ti != 0) try out.append(g.arena, ',');
                        try g.ws(&out);
                        try out.append(g.arena, '[');
                        for (tag, 0..) |f, fi| {
                            if (fi != 0) try out.append(g.arena, ',');
                            try g.ws(&out);
                            try g.writeString(&out, f);
                            try g.ws(&out);
                        }
                        try out.append(g.arena, ']');
                        try g.ws(&out);
                    }
                    try out.append(g.arena, ']');
                },
                5 => try g.writeString(&out, ev.content),
                6 => try g.writeHexString(&out, &ev.sig),
                else => try out.appendSlice(g.arena, switch (r.uintLessThan(u8, 6)) {
                    0 => "null",
                    1 => "[true,false,{\"a\":[1.5e-3,-0,0.25E+2]}]",
                    2 => "{\"nested\":{\"deeper\":[[[]]]}}",
                    3 => "\"\\u00e9\\ud83d\\ude00\"",
                    4 => "-12.5e10",
                    else => "{}",
                }),
            }
            try g.ws(&out);
        }
        try out.append(g.arena, '}');
        try g.ws(&out);
        return out.items;
    }

    pub fn writeNumber(g: Generator, out: *std.ArrayList(u8), v: i64) !void {
        switch (g.rand.uintLessThan(u8, 16)) {
            0 => try out.print(g.arena, "{d}.0", .{v}),
            1 => try out.print(g.arena, "\"{d}\"", .{v}),
            2 => try out.print(g.arena, "{d}e0", .{v}),
            3 => if (v == 0) try out.appendSlice(g.arena, "-0") else try out.print(g.arena, "{d}", .{v}),
            else => try out.print(g.arena, "{d}", .{v}),
        }
    }

    /// Breaks `text` the way a bad sender would: a byte changed, dropped,
    /// duplicated, or a slice of the text repeated or cut off.
    pub fn mutate(g: Generator, text_in: []u8) ![]u8 {
        const touchy = "\"\\{}[],:0-9eu \x00\x80\xc3\xed\xf4";
        const r = g.rand;
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(g.arena, text_in);
        for (0..r.intRangeAtMost(usize, 1, 3)) |_| {
            if (out.items.len == 0) break;
            const at = r.uintLessThan(usize, out.items.len);
            switch (r.uintLessThan(u8, 6)) {
                0 => out.items[at] = r.int(u8),
                1 => out.items[at] = touchy[r.uintLessThan(usize, touchy.len)],
                2 => _ = out.orderedRemove(at),
                3 => try out.insert(g.arena, at, out.items[at]),
                4 => out.items.len = at,
                else => {
                    const len = @min(out.items.len - at, r.uintLessThan(usize, 80));
                    try out.insertSlice(g.arena, at, try g.arena.dupe(u8, out.items[at..][0..len]));
                },
            }
        }
        return out.items;
    }
};

/// The escape `Generator.writeString` uses for a byte it has to escape: the
/// short form where JSON has one, `\u00XX` otherwise.
fn shortEscape(c: u8, buf: *[6]u8) []const u8 {
    return switch (c) {
        '"' => "\\\"",
        '\\' => "\\\\",
        '\n' => "\\n",
        '\r' => "\\r",
        '\t' => "\\t",
        0x08 => "\\b",
        0x0C => "\\f",
        else => std.fmt.bufPrint(buf, "\\u{x:0>4}", .{c}) catch unreachable,
    };
}
