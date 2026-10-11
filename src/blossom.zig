//! Blossom media authorization and blob descriptors.
//!
//! Blossom servers (BUD-01, BUD-02, BUD-11) take a `kind:24242` auth event in
//! the `Authorization` header, sent as `Nostr <base64(event json)>` exactly
//! like NIP-98. This module builds that event and header and parses the blob
//! descriptor a server returns. There is no HTTP transport here.
//!
//! BUD-11 asks for the header in unpadded URL-safe base64. The header here is
//! standard base64 with padding, as NIP-98's is, because that is what servers
//! accept: khatru-based servers decode it with a strict standard decoder and
//! refuse the URL-safe form, and Amethyst and Jumble both send standard.

const std = @import("std");
const event = @import("event.zig");
const hex = @import("hex.zig");
const keys = @import("keys.zig");
const nip98 = @import("nip98.zig");

/// The Blossom authorization event kind.
pub const kind: u16 = 24242;

/// The verb carried by the `t` tag.
pub const Action = enum {
    get,
    upload,
    list,
    delete,
    media,

    pub fn name(self: Action) []const u8 {
        return @tagName(self);
    }

    /// The content used when `AuthOptions.content` is null.
    pub fn defaultContent(self: Action) []const u8 {
        return switch (self) {
            .get => "Get Blob",
            .upload => "Upload Blob",
            .list => "List Blobs",
            .delete => "Delete Blob",
            .media => "Upload Media",
        };
    }
};

pub const AuthOptions = struct {
    action: Action,
    /// Human readable reason, the event content. BUD-11 requires one, so
    /// null takes `Action.defaultContent`.
    content: ?[]const u8 = null,
    /// Unix seconds after which the server must refuse the event. Required
    /// by BUD-11.
    expiration: i64,
    /// One `x` tag per blob hash. Used for get, upload, media and delete;
    /// leave empty for list.
    hashes: []const [32]u8 = &.{},
    /// `server` tags scoping the token to these servers. Each is a lowercase
    /// domain name and nothing else (`cdn.example.com`, not a URL). Empty
    /// leaves the token valid on any server, which BUD-11 warns a leaked
    /// delete token makes dangerous.
    servers: []const []const u8 = &.{},
};

pub const AuthError = error{
    /// A server is not a lowercase domain name.
    InvalidServer,
    /// An upload, delete or media token names no blob. BUD-11 requires an
    /// `x` tag for each, and a token without one authorizes any blob.
    MissingHash,
    /// The token would expire at or before the moment it was made.
    InvalidExpiration,
};

/// Whether `s` is what BUD-11 allows in a `server` tag: a lowercase domain
/// name, dot separated labels of letters, digits and inner hyphens.
pub fn isBareDomain(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var labels = std.mem.splitScalar(u8, s, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |ch| switch (ch) {
            'a'...'z', '0'...'9', '-' => {},
            else => return false,
        };
    }
    return true;
}

/// Builds and signs the `kind:24242` event. The event borrows `opts` strings
/// and owns its tag slices, allocated from `allocator`; build it in an arena.
pub fn authEvent(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    opts: AuthOptions,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error || AuthError)!event.Event {
    if (opts.expiration <= created_at) return error.InvalidExpiration;
    switch (opts.action) {
        .upload, .delete, .media => if (opts.hashes.len == 0) return error.MissingHash,
        .get, .list => {},
    }
    for (opts.servers) |srv| if (!isBareDomain(srv)) return error.InvalidServer;

    var tags: std.ArrayList(event.Tag) = .empty;
    try tags.append(allocator, try tag2(allocator, "t", opts.action.name()));
    try tags.append(allocator, try tag2(allocator, "expiration", try std.fmt.allocPrint(allocator, "{d}", .{opts.expiration})));
    for (opts.hashes) |h| {
        try tags.append(allocator, try tag2(allocator, "x", try hex.encode(allocator, &h)));
    }
    for (opts.servers) |srv| try tags.append(allocator, try tag2(allocator, "server", srv));
    const content = opts.content orelse opts.action.defaultContent();
    return event.create(allocator, signer, keypair, created_at, kind, tags.items, content, aux_rand);
}

fn tag2(allocator: std.mem.Allocator, name: []const u8, value: []const u8) std.mem.Allocator.Error!event.Tag {
    const t = try allocator.alloc([]const u8, 2);
    t[0] = name;
    t[1] = value;
    return t;
}

/// The `Authorization` header value for a signed event. Caller frees.
pub fn authHeader(allocator: std.mem.Allocator, ev: event.Event) std.mem.Allocator.Error![]u8 {
    return nip98.encodeHeader(allocator, ev);
}

/// Builds the event and the header in one step. Caller frees.
pub fn buildAuthHeader(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    opts: AuthOptions,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error || AuthError)![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const ev = try authEvent(arena_state.allocator(), signer, keypair, created_at, opts, aux_rand);
    return authHeader(allocator, ev);
}

/// A blob descriptor (BUD-02). Strings borrow from the `Parsed` arena.
///
/// BUD-02 lists every field as present, but only `url` is required here:
/// servers in use leave out the others, and the address is what a note needs.
/// A field that is present with the wrong shape is still refused. A caller
/// that checks the server stored the right bytes compares `sha256`, and has
/// to decide what a missing one means.
pub const BlobDescriptor = struct {
    url: []const u8,
    sha256: ?[32]u8 = null,
    size: ?u64 = null,
    /// MIME type. Older servers omit it.
    type: ?[]const u8 = null,
    /// Unix seconds the server stored the blob.
    uploaded: ?i64 = null,
    /// Optional NIP-94 tags (BUD-08).
    nip94: ?[]const event.Tag = null,
};

pub const ParseError = error{InvalidDescriptor} || std.mem.Allocator.Error;

pub fn Parsed(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: *@This()) void {
            const gpa = self.arena.child_allocator;
            self.arena.deinit();
            gpa.destroy(self.arena);
        }
    };
}

/// Parses one blob descriptor object (an upload or mirror response).
pub fn parseDescriptor(gpa: std.mem.Allocator, json_text: []const u8) ParseError!Parsed(BlobDescriptor) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const root = try parseRoot(a, json_text);
    return .{ .arena = arena, .value = try descriptorFromValue(a, root) };
}

/// Parses a JSON array of blob descriptors (a list response).
pub fn parseDescriptorList(gpa: std.mem.Allocator, json_text: []const u8) ParseError!Parsed([]const BlobDescriptor) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const root = try parseRoot(a, json_text);
    if (root != .array) return error.InvalidDescriptor;
    const out = try a.alloc(BlobDescriptor, root.array.items.len);
    for (root.array.items, 0..) |item, i| out[i] = try descriptorFromValue(a, item);
    return .{ .arena = arena, .value = out };
}

fn parseRoot(a: std.mem.Allocator, json_text: []const u8) ParseError!std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, a, json_text, .{}) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidDescriptor,
    };
}

fn descriptorFromValue(a: std.mem.Allocator, v: std.json.Value) ParseError!BlobDescriptor {
    if (v != .object) return error.InvalidDescriptor;
    const o = v.object;

    const url = try strField(o, "url");
    if (url.len == 0) return error.InvalidDescriptor;
    var sha: ?[32]u8 = null;
    if (o.get("sha256")) |v_sha| switch (v_sha) {
        .string => |h| sha = hex.decodeFixed(32, h) catch return error.InvalidDescriptor,
        .null => {},
        else => return error.InvalidDescriptor,
    };
    var size: ?u64 = null;
    if (o.get("size")) |v_size| switch (v_size) {
        .integer => |n| size = std.math.cast(u64, n) orelse return error.InvalidDescriptor,
        .null => {},
        else => return error.InvalidDescriptor,
    };
    var uploaded: ?i64 = null;
    if (o.get("uploaded")) |v_up| switch (v_up) {
        .integer => |n| uploaded = n,
        .null => {},
        else => return error.InvalidDescriptor,
    };

    var mime: ?[]const u8 = null;
    if (o.get("type")) |t| switch (t) {
        .string => |s| mime = s,
        .null => {},
        else => return error.InvalidDescriptor,
    };

    var nip94: ?[]const event.Tag = null;
    if (o.get("nip94")) |n| switch (n) {
        .null => {},
        .array => |arr| {
            const tags = try a.alloc(event.Tag, arr.items.len);
            for (arr.items, 0..) |tv, i| {
                if (tv != .array) return error.InvalidDescriptor;
                const fields = try a.alloc([]const u8, tv.array.items.len);
                for (tv.array.items, 0..) |fv, j| {
                    if (fv != .string) return error.InvalidDescriptor;
                    fields[j] = fv.string;
                }
                tags[i] = fields;
            }
            nip94 = tags;
        },
        else => return error.InvalidDescriptor,
    };

    return .{ .url = url, .sha256 = sha, .size = size, .type = mime, .uploaded = uploaded, .nip94 = nip94 };
}

fn strField(o: std.json.ObjectMap, name: []const u8) ParseError![]const u8 {
    const v = o.get(name) orelse return error.InvalidDescriptor;
    if (v != .string) return error.InvalidDescriptor;
    return v.string;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testKey(signer: keys.Signer) !keys.KeyPair {
    const secret = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    return signer.keyPairFromSecretKey(secret);
}

test "blossom: upload auth header round trips" {
    const gpa = testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);

    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("blob bytes", &h, .{});
    const hashes = [_][32]u8{h};

    const header = try buildAuthHeader(gpa, signer, kp, 1_700_000_000, .{
        .action = .upload,
        .content = "Upload Blob",
        .expiration = 1_700_003_600,
        .hashes = &hashes,
        .servers = &.{"cdn.example.com"},
    }, null);
    defer gpa.free(header);

    var parsed = try nip98.decodeHeader(gpa, header);
    defer parsed.deinit();
    const ev = parsed.value;
    try testing.expectEqual(@as(u16, 24242), ev.kind);
    try testing.expectEqualStrings("Upload Blob", ev.content);
    try testing.expect(try event.verify(gpa, signer, ev));
    try testing.expectEqual(@as(usize, 4), ev.tags.len);
    try testing.expectEqualStrings("t", ev.tags[0][0]);
    try testing.expectEqualStrings("upload", ev.tags[0][1]);
    try testing.expectEqualStrings("expiration", ev.tags[1][0]);
    try testing.expectEqualStrings("1700003600", ev.tags[1][1]);
    try testing.expectEqualStrings("x", ev.tags[2][0]);
    const want = try hex.encode(gpa, &h);
    defer gpa.free(want);
    try testing.expectEqualStrings(want, ev.tags[2][1]);
    try testing.expectEqualStrings("server", ev.tags[3][0]);
}

test "blossom: list auth has no x tag" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);
    const ev = try authEvent(arena_state.allocator(), signer, kp, 1_700_000_000, .{ .action = .list, .expiration = 1_700_003_600 }, null);
    try testing.expectEqual(@as(usize, 2), ev.tags.len);
    try testing.expectEqualStrings("list", ev.tags[0][1]);
}

test "blossom: descriptor with optional fields" {
    const gpa = testing.allocator;
    const sha = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";
    var full = try parseDescriptor(gpa,
        \\{"url":"https://cdn.example.com/b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553.pdf",
        \\"sha256":"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553",
        \\"size":184292,"type":"application/pdf","uploaded":1725105921,
        \\"nip94":[["url","https://cdn.example.com/x.pdf"],["m","application/pdf"]],"extra":1}
    );
    defer full.deinit();
    const d = full.value;
    try testing.expectEqual(@as(u64, 184292), d.size.?);
    try testing.expectEqual(@as(i64, 1725105921), d.uploaded.?);
    try testing.expectEqualStrings("application/pdf", d.type.?);
    try testing.expectEqualSlices(u8, &try hex.decodeFixed(32, sha), &d.sha256.?);
    try testing.expectEqual(@as(usize, 2), d.nip94.?.len);
    try testing.expectEqualStrings("m", d.nip94.?[1][0]);

    var min = try parseDescriptor(gpa,
        \\{"url":"https://cdn.example.com/a","sha256":"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553","size":1,"uploaded":2}
    );
    defer min.deinit();
    try testing.expect(min.value.type == null);
    try testing.expect(min.value.nip94 == null);

    // What some servers send: the address and nothing else.
    var bare = try parseDescriptor(gpa, "{\"url\":\"https://cdn.example.com/a.png\"}");
    defer bare.deinit();
    try testing.expectEqualStrings("https://cdn.example.com/a.png", bare.value.url);
    try testing.expect(bare.value.sha256 == null);
    try testing.expect(bare.value.size == null);
    try testing.expect(bare.value.uploaded == null);
}

test "blossom: a token always carries a human readable content" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);
    const h = [_][32]u8{[_]u8{7} ** 32};
    const ev = try authEvent(arena_state.allocator(), signer, kp, 1_700_000_000, .{ .action = .delete, .expiration = 1_700_003_600, .hashes = &h }, null);
    try testing.expectEqualStrings("Delete Blob", ev.content);
}

test "blossom: bad descriptors and lists" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidDescriptor, parseDescriptor(gpa, "[]"));
    try testing.expectError(error.InvalidDescriptor, parseDescriptor(gpa, "{\"sha256\":\"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553\"}"));
    try testing.expectError(error.InvalidDescriptor, parseDescriptor(gpa, "{\"url\":\"u\",\"size\":\"1\"}"));
    try testing.expectError(error.InvalidDescriptor, parseDescriptor(gpa, "{\"url\":\"u\",\"sha256\":\"zz\",\"size\":1,\"uploaded\":2}"));
    try testing.expectError(error.InvalidDescriptor, parseDescriptor(gpa, "{\"url\":\"u\",\"sha256\":\"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553\",\"size\":-1,\"uploaded\":2}"));
    try testing.expectError(error.InvalidDescriptor, parseDescriptor(gpa, "nope"));

    var list = try parseDescriptorList(gpa, "[{\"url\":\"u\",\"sha256\":\"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553\",\"size\":3,\"uploaded\":4},{\"url\":\"v\",\"sha256\":\"b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553\",\"size\":5,\"uploaded\":6}]");
    defer list.deinit();
    try testing.expectEqual(@as(usize, 2), list.value.len);
    try testing.expectEqual(@as(u64, 5), list.value[1].size.?);
}

test "blossom: a token is refused when it would authorize more than it says" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = try testKey(signer);
    const h = [_][32]u8{[_]u8{7} ** 32};
    const t0: i64 = 1_700_000_000;

    // Upload, delete and media without a hash authorize any blob.
    for ([_]Action{ .upload, .delete, .media }) |action| {
        try testing.expectError(error.MissingHash, authEvent(a, signer, kp, t0, .{ .action = action, .expiration = t0 + 60 }, null));
    }
    _ = try authEvent(a, signer, kp, t0, .{ .action = .get, .expiration = t0 + 60 }, null);

    // Expired from the start.
    try testing.expectError(error.InvalidExpiration, authEvent(a, signer, kp, t0, .{ .action = .list, .expiration = t0 }, null));
    try testing.expectError(error.InvalidExpiration, authEvent(a, signer, kp, t0, .{ .action = .list, .expiration = t0 - 1 }, null));

    // A server is a lowercase domain, never a URL.
    for ([_][]const u8{ "https://cdn.example.com", "CDN.example.com", "cdn.example.com:443", "cdn.example.com/", "", "-a.com", "a..com" }) |bad| {
        try testing.expectError(error.InvalidServer, authEvent(a, signer, kp, t0, .{ .action = .list, .expiration = t0 + 60, .servers = &.{bad} }, null));
    }

    // Several servers, one tag each.
    const ev = try authEvent(a, signer, kp, t0, .{ .action = .upload, .expiration = t0 + 60, .hashes = &h, .servers = &.{ "cdn.example.com", "blossom.example.org" } }, null);
    var servers: usize = 0;
    for (ev.tags) |t| {
        if (std.mem.eql(u8, t[0], "server")) servers += 1;
    }
    try testing.expectEqual(@as(usize, 2), servers);
}
