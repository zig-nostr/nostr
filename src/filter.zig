//! NIP-01 subscription filters: the `Filter` struct, its wire-format JSON
//! encoding (as sent inside a `REQ`), and local event matching.
//!
//! A filter is a conjunction of constraints. A `null` field imposes no
//! constraint; a non-null field matches when the event satisfies it. Within a
//! single scalar list (`ids`, `authors`, `kinds`) the values are OR-ed; across
//! different fields the constraints are AND-ed. Tag filters follow the same
//! rule: an event must match at least one value for *each* present tag letter.

const std = @import("std");
const hex = @import("hex.zig");
const json = @import("json.zig");
const event_mod = @import("event.zig");
const Event = event_mod.Event;

/// Constrains events to those carrying a single-letter tag (`#e`, `#p`, `#t`,
/// ...) whose value (the tag's second element) is one of `values`.
pub const TagFilter = struct {
    /// The single-letter tag name, e.g. `'e'`, `'p'`, `'t'`.
    letter: u8,
    values: []const []const u8,
};

pub const Filter = struct {
    /// Exact event ids to match (32-byte, encoded as hex on the wire).
    ids: ?[]const [32]u8 = null,
    /// Exact author pubkeys to match (32-byte x-only, hex on the wire).
    authors: ?[]const [32]u8 = null,
    /// Event kinds to match.
    kinds: ?[]const u16 = null,
    /// Single-letter tag constraints (`#e`, `#p`, ...).
    tags: ?[]const TagFilter = null,
    /// Match events at or after this unix timestamp (`created_at >= since`).
    since: ?i64 = null,
    /// Match events at or before this unix timestamp (`created_at <= until`).
    until: ?i64 = null,
    /// Relay-side cap on how many events to return. Does not affect local
    /// matching; carried so it can be sent to the relay.
    limit: ?u32 = null,

    /// Returns true when `ev` satisfies every present constraint. `limit` is
    /// intentionally ignored — it bounds how many results a relay returns, not
    /// whether a given event matches.
    pub fn matches(self: Filter, ev: Event) bool {
        if (self.ids) |ids| {
            if (!containsHash(ids, ev.id)) return false;
        }
        if (self.authors) |authors| {
            if (!containsHash(authors, ev.pubkey)) return false;
        }
        if (self.kinds) |kinds| {
            if (std.mem.indexOfScalar(u16, kinds, ev.kind) == null) return false;
        }
        if (self.since) |since| {
            if (ev.created_at < since) return false;
        }
        if (self.until) |until| {
            if (ev.created_at > until) return false;
        }
        if (self.tags) |tag_filters| {
            for (tag_filters) |tf| {
                if (!matchesTag(ev, tf)) return false;
            }
        }
        return true;
    }

    /// Appends the wire-format JSON object for this filter to `list`. Only
    /// present (non-null) fields are emitted, so an all-null filter serializes
    /// to `{}` (a relay's "everything" subscription).
    pub fn appendJson(
        self: Filter,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!void {
        try list.append(allocator, '{');
        var first = true;

        if (self.ids) |ids| {
            try appendKey(list, allocator, &first, "ids");
            try appendHexArray(list, allocator, ids);
        }
        if (self.authors) |authors| {
            try appendKey(list, allocator, &first, "authors");
            try appendHexArray(list, allocator, authors);
        }
        if (self.kinds) |kinds| {
            try appendKey(list, allocator, &first, "kinds");
            try appendIntArray(list, allocator, kinds);
        }
        if (self.tags) |tag_filters| {
            for (tag_filters) |tf| {
                const key = [_]u8{ '#', tf.letter };
                try appendKey(list, allocator, &first, &key);
                try appendStringArray(list, allocator, tf.values);
            }
        }
        if (self.since) |since| {
            try appendKey(list, allocator, &first, "since");
            try appendInt(list, allocator, since);
        }
        if (self.until) |until| {
            try appendKey(list, allocator, &first, "until");
            try appendInt(list, allocator, until);
        }
        if (self.limit) |limit| {
            try appendKey(list, allocator, &first, "limit");
            try appendInt(list, allocator, limit);
        }

        try list.append(allocator, '}');
    }
};

fn containsHash(haystack: []const [32]u8, needle: [32]u8) bool {
    for (haystack) |h| {
        if (std.mem.eql(u8, &h, &needle)) return true;
    }
    return false;
}

fn matchesTag(ev: Event, tf: TagFilter) bool {
    for (ev.tags) |tag| {
        // A tag is `[name, value, ...]`; a matchable single-letter tag has at
        // least a name and a value, and its name is exactly one character.
        if (tag.len < 2) continue;
        if (tag[0].len != 1 or tag[0][0] != tf.letter) continue;
        for (tf.values) |v| {
            if (std.mem.eql(u8, tag[1], v)) return true;
        }
    }
    return false;
}

fn appendKey(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    first: *bool,
    key: []const u8,
) std.mem.Allocator.Error!void {
    if (!first.*) try list.append(allocator, ',');
    first.* = false;
    try json.appendString(list, allocator, key);
    try list.append(allocator, ':');
}

fn appendHexArray(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    items: []const [32]u8,
) std.mem.Allocator.Error!void {
    try list.append(allocator, '[');
    for (items, 0..) |item, i| {
        if (i != 0) try list.append(allocator, ',');
        try list.append(allocator, '"');
        try hex.appendHex(list, allocator, &item);
        try list.append(allocator, '"');
    }
    try list.append(allocator, ']');
}

fn appendStringArray(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    items: []const []const u8,
) std.mem.Allocator.Error!void {
    try list.append(allocator, '[');
    for (items, 0..) |item, i| {
        if (i != 0) try list.append(allocator, ',');
        try json.appendString(list, allocator, item);
    }
    try list.append(allocator, ']');
}

fn appendIntArray(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    items: []const u16,
) std.mem.Allocator.Error!void {
    try list.append(allocator, '[');
    for (items, 0..) |item, i| {
        if (i != 0) try list.append(allocator, ',');
        try appendInt(list, allocator, item);
    }
    try list.append(allocator, ']');
}

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    v: anytype,
) std.mem.Allocator.Error!void {
    var buf: [32]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch unreachable;
    try list.appendSlice(allocator, s);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn hb(comptime h: []const u8) [32]u8 {
    return hex.decodeFixed(32, h) catch unreachable;
}

fn encode(allocator: std.mem.Allocator, f: Filter) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try f.appendJson(&list, allocator);
    return list.toOwnedSlice(allocator);
}

test "empty filter serializes to {}" {
    const allocator = std.testing.allocator;
    const s = try encode(allocator, .{});
    defer allocator.free(s);
    try std.testing.expectEqualStrings("{}", s);
}

test "full filter serializes in canonical field order" {
    const allocator = std.testing.allocator;
    const ids = [_][32]u8{hb("aa" ** 32)};
    const authors = [_][32]u8{hb("bb" ** 32)};
    const kinds = [_]u16{ 1, 7 };
    const evals = [_][]const u8{"cc" ** 32};
    const tvals = [_][]const u8{"nostr"};
    const tags = [_]TagFilter{
        .{ .letter = 'e', .values = &evals },
        .{ .letter = 't', .values = &tvals },
    };
    const f = Filter{
        .ids = &ids,
        .authors = &authors,
        .kinds = &kinds,
        .tags = &tags,
        .since = 1700000000,
        .until = 1700003600,
        .limit = 25,
    };
    const s = try encode(allocator, f);
    defer allocator.free(s);

    const expected =
        "{\"ids\":[\"" ++ "aa" ** 32 ++ "\"]," ++
        "\"authors\":[\"" ++ "bb" ** 32 ++ "\"]," ++
        "\"kinds\":[1,7]," ++
        "\"#e\":[\"" ++ "cc" ** 32 ++ "\"]," ++
        "\"#t\":[\"nostr\"]," ++
        "\"since\":1700000000,\"until\":1700003600,\"limit\":25}";
    try std.testing.expectEqualStrings(expected, s);
}

const test_pubkey = "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca";
const test_id = "d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40";

fn sampleEvent() Event {
    return .{
        .id = hb(test_id),
        .pubkey = hb(test_pubkey),
        .created_at = 1700000000,
        .kind = 1,
        .tags = &sample_tags,
        .content = "hello",
        .sig = [_]u8{0} ** 64,
    };
}

const sample_tags = [_]event_mod.Tag{
    &[_][]const u8{ "p", test_pubkey },
    &[_][]const u8{ "t", "zig" },
};

test "matches: empty filter matches any event" {
    try std.testing.expect((Filter{}).matches(sampleEvent()));
}

test "matches: ids constraint" {
    const good = [_][32]u8{hb(test_id)};
    const bad = [_][32]u8{hb("00" ** 32)};
    try std.testing.expect((Filter{ .ids = &good }).matches(sampleEvent()));
    try std.testing.expect(!(Filter{ .ids = &bad }).matches(sampleEvent()));
}

test "matches: authors and kinds" {
    const authors = [_][32]u8{hb(test_pubkey)};
    const kinds_ok = [_]u16{ 0, 1, 7 };
    const kinds_no = [_]u16{ 0, 3 };
    try std.testing.expect((Filter{ .authors = &authors, .kinds = &kinds_ok }).matches(sampleEvent()));
    try std.testing.expect(!(Filter{ .authors = &authors, .kinds = &kinds_no }).matches(sampleEvent()));
}

test "matches: since/until bounds are inclusive" {
    try std.testing.expect((Filter{ .since = 1700000000 }).matches(sampleEvent()));
    try std.testing.expect((Filter{ .until = 1700000000 }).matches(sampleEvent()));
    try std.testing.expect(!(Filter{ .since = 1700000001 }).matches(sampleEvent()));
    try std.testing.expect(!(Filter{ .until = 1699999999 }).matches(sampleEvent()));
}

test "matches: tag filters" {
    const t_ok = [_][]const u8{"zig"};
    const t_no = [_][]const u8{"rust"};
    const p_ok = [_][]const u8{test_pubkey};
    try std.testing.expect((Filter{ .tags = &[_]TagFilter{.{ .letter = 't', .values = &t_ok }} }).matches(sampleEvent()));
    try std.testing.expect(!(Filter{ .tags = &[_]TagFilter{.{ .letter = 't', .values = &t_no }} }).matches(sampleEvent()));
    try std.testing.expect((Filter{ .tags = &[_]TagFilter{.{ .letter = 'p', .values = &p_ok }} }).matches(sampleEvent()));
    // A tag letter not present on the event never matches.
    try std.testing.expect(!(Filter{ .tags = &[_]TagFilter{.{ .letter = 'e', .values = &p_ok }} }).matches(sampleEvent()));
}

test "matches: all constraints AND together" {
    const authors = [_][32]u8{hb(test_pubkey)};
    const kinds = [_]u16{1};
    const t_ok = [_][]const u8{"zig"};
    const f = Filter{
        .authors = &authors,
        .kinds = &kinds,
        .since = 1699999999,
        .until = 1700000001,
        .tags = &[_]TagFilter{.{ .letter = 't', .values = &t_ok }},
    };
    try std.testing.expect(f.matches(sampleEvent()));

    // Flip any one constraint and the whole filter must reject.
    const kinds_no = [_]u16{2};
    var f2 = f;
    f2.kinds = &kinds_no;
    try std.testing.expect(!f2.matches(sampleEvent()));
}
