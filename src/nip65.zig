//! NIP-65 relay list metadata (kind:10002) and outbox-model routing.
//!
//! A NIP-65 event advertises the relays a user reads from and writes to, via
//! `["r", <url>]` tags with an optional `"read"` / `"write"` marker (no marker
//! means both). The outbox ("gossip") model routes without central indexers:
//!
//!   * to READ a user's notes, subscribe to the relays they **write** to;
//!   * to REACH a user, publish to the relays they **read** from.
//!
//! This module parses the event and inverts a set of users' relay lists into
//! per-relay groups, so a client opens one subscription (or publish) per relay
//! covering exactly the users routed there.

const std = @import("std");
const event_mod = @import("event.zig");
const Event = event_mod.Event;

/// The NIP-65 relay list event kind.
pub const kind: u16 = 10002;

pub const RelayEntry = struct {
    url: []const u8,
    /// The user reads from this relay — others publish here to reach them.
    read: bool,
    /// The user writes to this relay — others read here to see their notes.
    write: bool,
};

pub const RelayList = struct {
    entries: []const RelayEntry,
};

pub const ParsedRelayList = struct {
    arena: *std.heap.ArenaAllocator,
    list: RelayList,

    pub fn deinit(self: *ParsedRelayList) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses an event's `["r", ...]` tags into a relay list. The event kind is
/// not enforced (the caller decides), but a well-formed NIP-65 event is
/// kind 10002. A tag with no marker is both read and write; a `"read"` /
/// `"write"` marker restricts it; any other marker is treated leniently as
/// both. Duplicate urls are merged (union of read/write) and empty urls and
/// non-`r` tags are ignored. URLs are copied into the returned arena, so the
/// result does not borrow from `ev`.
pub fn parseRelayList(gpa: std.mem.Allocator, ev: Event) !ParsedRelayList {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    var entries: std.ArrayList(RelayEntry) = .empty;

    for (ev.tags) |tag| {
        if (tag.len < 2) continue;
        if (!std.mem.eql(u8, tag[0], "r")) continue;
        const url = tag[1];
        if (url.len == 0) continue;

        var read = true;
        var write = true;
        if (tag.len >= 3) {
            if (std.mem.eql(u8, tag[2], "read")) {
                write = false;
            } else if (std.mem.eql(u8, tag[2], "write")) {
                read = false;
            }
        }

        if (indexOfUrl(entries.items, url)) |i| {
            entries.items[i].read = entries.items[i].read or read;
            entries.items[i].write = entries.items[i].write or write;
        } else {
            try entries.append(allocator, .{
                .url = try allocator.dupe(u8, url),
                .read = read,
                .write = write,
            });
        }
    }

    return .{
        .arena = arena,
        .list = .{ .entries = try entries.toOwnedSlice(allocator) },
    };
}

fn indexOfUrl(entries: []const RelayEntry, url: []const u8) ?usize {
    for (entries, 0..) |e, i| {
        if (std.mem.eql(u8, e.url, url)) return i;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Outbox routing
// ---------------------------------------------------------------------------

/// A user (pubkey) together with their known relay entries.
pub const PubkeyRelays = struct {
    pubkey: [32]u8,
    entries: []const RelayEntry,
};

/// A relay and the users routed to it.
pub const RelayGroup = struct {
    url: []const u8,
    pubkeys: []const [32]u8,
};

pub const Routes = struct {
    arena: *std.heap.ArenaAllocator,
    groups: []const RelayGroup,

    pub fn deinit(self: *Routes) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Outbox READ routing: to fetch these authors' notes, group them by the
/// relays they **write** to. Each author contributes at most `max_per_author`
/// of their write relays (0 = no limit) to bound fan-out. The result is one
/// group per relay listing the authors to request there.
pub fn readRoutes(gpa: std.mem.Allocator, authors: []const PubkeyRelays, max_per_author: usize) !Routes {
    return route(gpa, authors, .write, max_per_author);
}

/// Inbox WRITE routing: to reach these recipients, group them by the relays
/// they **read** from. Each recipient contributes at most `max_per_author` of
/// their read relays (0 = no limit).
pub fn writeRoutes(gpa: std.mem.Allocator, recipients: []const PubkeyRelays, max_per_author: usize) !Routes {
    return route(gpa, recipients, .read, max_per_author);
}

const Select = enum { read, write };

fn route(
    gpa: std.mem.Allocator,
    people: []const PubkeyRelays,
    select: Select,
    max_per_author: usize,
) !Routes {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    // Relay urls in first-seen order, each with the pubkeys routed to it.
    var urls: std.ArrayList([]const u8) = .empty;
    var members: std.ArrayList(std.ArrayList([32]u8)) = .empty;

    for (people) |person| {
        var used: usize = 0;
        for (person.entries) |entry| {
            const matches = switch (select) {
                .read => entry.read,
                .write => entry.write,
            };
            if (!matches) continue;
            if (max_per_author != 0 and used >= max_per_author) break;
            used += 1;

            const gi = indexOfString(urls.items, entry.url) orelse blk: {
                try urls.append(allocator, try allocator.dupe(u8, entry.url));
                try members.append(allocator, .empty);
                break :blk urls.items.len - 1;
            };
            if (!containsPubkey(members.items[gi].items, person.pubkey)) {
                try members.items[gi].append(allocator, person.pubkey);
            }
        }
    }

    const groups = try allocator.alloc(RelayGroup, urls.items.len);
    for (groups, 0..) |*g, i| {
        g.* = .{ .url = urls.items[i], .pubkeys = try members.items[i].toOwnedSlice(allocator) };
    }

    return .{ .arena = arena, .groups = groups };
}

fn indexOfString(haystack: []const []const u8, needle: []const u8) ?usize {
    for (haystack, 0..) |s, i| {
        if (std.mem.eql(u8, s, needle)) return i;
    }
    return null;
}

fn containsPubkey(haystack: []const [32]u8, needle: [32]u8) bool {
    for (haystack) |p| {
        if (std.mem.eql(u8, &p, &needle)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Tag = event_mod.Tag;

fn eventWithTags(tags: []const Tag) Event {
    return .{
        .id = [_]u8{0} ** 32,
        .pubkey = [_]u8{0} ** 32,
        .created_at = 0,
        .kind = kind,
        .tags = tags,
        .content = "",
        .sig = [_]u8{0} ** 64,
    };
}

test "parseRelayList: markers, defaults, merge, and skips" {
    const allocator = std.testing.allocator;
    const tags = [_]Tag{
        &[_][]const u8{ "r", "wss://both.example" }, // no marker -> read+write
        &[_][]const u8{ "r", "wss://read.example", "read" },
        &[_][]const u8{ "r", "wss://write.example", "write" },
        &[_][]const u8{ "r", "wss://both.example", "write" }, // merges into first
        &[_][]const u8{ "r", "" }, // empty -> skipped
        &[_][]const u8{"r"}, // too short -> skipped
        &[_][]const u8{ "p", "wss://notrelay.example" }, // non-r -> skipped
    };
    var parsed = try parseRelayList(allocator, eventWithTags(&tags));
    defer parsed.deinit();

    const e = parsed.list.entries;
    try std.testing.expectEqual(@as(usize, 3), e.len);
    try std.testing.expectEqualStrings("wss://both.example", e[0].url);
    try std.testing.expect(e[0].read and e[0].write);
    try std.testing.expectEqualStrings("wss://read.example", e[1].url);
    try std.testing.expect(e[1].read and !e[1].write);
    try std.testing.expectEqualStrings("wss://write.example", e[2].url);
    try std.testing.expect(!e[2].read and e[2].write);
}

fn pk(byte: u8) [32]u8 {
    return [_]u8{byte} ** 32;
}

test "readRoutes groups authors by their write relays" {
    const allocator = std.testing.allocator;

    // alice writes to A and B; bob writes to B and C.
    const alice = [_]RelayEntry{
        .{ .url = "wss://A", .read = false, .write = true },
        .{ .url = "wss://B", .read = true, .write = true },
    };
    const bob = [_]RelayEntry{
        .{ .url = "wss://B", .read = false, .write = true },
        .{ .url = "wss://C", .read = true, .write = true },
    };
    const authors = [_]PubkeyRelays{
        .{ .pubkey = pk(0xa1), .entries = &alice },
        .{ .pubkey = pk(0xb0), .entries = &bob },
    };

    var routes = try readRoutes(allocator, &authors, 0);
    defer routes.deinit();

    // Relays A, B, C in first-seen order; B covers both authors.
    try std.testing.expectEqual(@as(usize, 3), routes.groups.len);
    try std.testing.expectEqualStrings("wss://A", routes.groups[0].url);
    try std.testing.expectEqual(@as(usize, 1), routes.groups[0].pubkeys.len);
    try std.testing.expectEqualStrings("wss://B", routes.groups[1].url);
    try std.testing.expectEqual(@as(usize, 2), routes.groups[1].pubkeys.len);
    try std.testing.expectEqualSlices(u8, &pk(0xa1), &routes.groups[1].pubkeys[0]);
    try std.testing.expectEqualSlices(u8, &pk(0xb0), &routes.groups[1].pubkeys[1]);
    try std.testing.expectEqualStrings("wss://C", routes.groups[2].url);
}

test "readRoutes honours max_per_author" {
    const allocator = std.testing.allocator;
    const alice = [_]RelayEntry{
        .{ .url = "wss://A", .read = false, .write = true },
        .{ .url = "wss://B", .read = false, .write = true },
        .{ .url = "wss://C", .read = false, .write = true },
    };
    const authors = [_]PubkeyRelays{.{ .pubkey = pk(0xa1), .entries = &alice }};

    var routes = try readRoutes(allocator, &authors, 2);
    defer routes.deinit();
    // Only the first two write relays are used.
    try std.testing.expectEqual(@as(usize, 2), routes.groups.len);
    try std.testing.expectEqualStrings("wss://A", routes.groups[0].url);
    try std.testing.expectEqualStrings("wss://B", routes.groups[1].url);
}

test "writeRoutes groups recipients by their read relays" {
    const allocator = std.testing.allocator;
    const carol = [_]RelayEntry{
        .{ .url = "wss://inbox", .read = true, .write = false },
        .{ .url = "wss://out", .read = false, .write = true }, // not a read relay
    };
    const recipients = [_]PubkeyRelays{.{ .pubkey = pk(0xc0), .entries = &carol }};

    var routes = try writeRoutes(allocator, &recipients, 0);
    defer routes.deinit();
    try std.testing.expectEqual(@as(usize, 1), routes.groups.len);
    try std.testing.expectEqualStrings("wss://inbox", routes.groups[0].url);
    try std.testing.expectEqualSlices(u8, &pk(0xc0), &routes.groups[0].pubkeys[0]);
}

test "parseRelayList output feeds routing" {
    const allocator = std.testing.allocator;
    const tags = [_]Tag{
        &[_][]const u8{ "r", "wss://w1", "write" },
        &[_][]const u8{ "r", "wss://rw" },
    };
    var parsed = try parseRelayList(allocator, eventWithTags(&tags));
    defer parsed.deinit();

    const authors = [_]PubkeyRelays{.{ .pubkey = pk(0x01), .entries = parsed.list.entries }};
    var routes = try readRoutes(allocator, &authors, 0);
    defer routes.deinit();
    // Both w1 (write-only) and rw (read+write) are write relays.
    try std.testing.expectEqual(@as(usize, 2), routes.groups.len);
}
