//! NIP-86 relay management API.
//!
//! A relay operator manages a relay over HTTP with JSON-RPC style requests,
//! `{"method": ..., "params": [...]}`, answered by `{"result": ..., "error":
//! ...}`. The request is a POST with content type `application/nostr+json+rpc`
//! and a NIP-98 `Authorization` header whose `payload` tag is the sha256 of
//! the request body, so the server knows the signed request is this body.
//!
//! This module encodes requests and parses responses. It does no HTTP;
//! `authHeader` builds the header for an encoded body.

const std = @import("std");
const event = @import("event.zig");
const hex = @import("hex.zig");
const json = @import("json.zig");
const keys = @import("keys.zig");
const nip98 = @import("nip98.zig");

/// The `Content-Type` of a NIP-86 request.
pub const content_type = "application/nostr+json+rpc";

/// A pubkey or event id (hex) or an IP, with an optional reason.
pub const Target = struct {
    value: []const u8,
    reason: ?[]const u8 = null,
};

/// One NIP-86 call with its parameters.
pub const Request = union(enum) {
    supportedmethods,
    banpubkey: Target,
    unbanpubkey: Target,
    listbannedpubkeys,
    allowpubkey: Target,
    unallowpubkey: Target,
    listallowedpubkeys,
    listeventsneedingmoderation,
    allowevent: Target,
    banevent: Target,
    listbannedevents,
    changerelayname: []const u8,
    changerelaydescription: []const u8,
    changerelayicon: []const u8,
    allowkind: u16,
    disallowkind: u16,
    listallowedkinds,
    blockip: Target,
    unblockip: Target,
    listblockedips,

    /// The wire name of the method.
    pub fn method(self: Request) []const u8 {
        return @tagName(self);
    }
};

/// Encodes a request as the JSON body. Caller frees.
pub fn encodeRequest(allocator: std.mem.Allocator, req: Request) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.appendSlice(allocator, "{\"method\":");
    try json.appendString(&list, allocator, req.method());
    try list.appendSlice(allocator, ",\"params\":[");
    switch (req) {
        .banpubkey, .unbanpubkey, .allowpubkey, .unallowpubkey, .allowevent, .banevent, .blockip, .unblockip => |t| {
            try json.appendString(&list, allocator, t.value);
            if (t.reason) |r| {
                try list.append(allocator, ',');
                try json.appendString(&list, allocator, r);
            }
        },
        .changerelayname, .changerelaydescription, .changerelayicon => |s| try json.appendString(&list, allocator, s),
        .allowkind, .disallowkind => |k| try list.print(allocator, "{d}", .{k}),
        else => {},
    }
    try list.appendSlice(allocator, "]}");
    return list.toOwnedSlice(allocator);
}

/// Builds the NIP-98 `Authorization` value for an encoded body: a POST to
/// `url` with the body's sha256 in the `payload` tag. Caller frees.
pub fn authHeader(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    url: []const u8,
    body: []const u8,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error)![]u8 {
    return nip98.authHeader(allocator, signer, keypair, created_at, url, "POST", body, aux_rand);
}

pub const ParseError = error{InvalidResponse} || std.mem.Allocator.Error;

/// A parsed `{result, error}` response. Strings borrow from the arena.
pub const Response = struct {
    arena: *std.heap.ArenaAllocator,
    /// The `result` value, or null when absent or JSON null.
    result: ?std.json.Value,
    /// The `error` message when the server refused the call.
    err: ?[]const u8,

    pub fn deinit(self: *Response) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }

    pub fn isError(self: Response) bool {
        return self.err != null;
    }

    /// A `true`/`false` result (every mutating method).
    pub fn boolResult(self: Response) error{InvalidResponse}!bool {
        const r = self.result orelse return error.InvalidResponse;
        if (r != .bool) return error.InvalidResponse;
        return r.bool;
    }

    /// The `supportedmethods` result: method names.
    pub fn methods(self: Response, allocator: std.mem.Allocator) ParseError![]const []const u8 {
        const arr = try self.array();
        const out = try allocator.alloc([]const u8, arr.len);
        errdefer allocator.free(out);
        for (arr, 0..) |v, i| {
            if (v != .string) return error.InvalidResponse;
            out[i] = v.string;
        }
        return out;
    }

    /// The `listallowedkinds` result.
    pub fn kinds(self: Response, allocator: std.mem.Allocator) ParseError![]const u16 {
        const arr = try self.array();
        const out = try allocator.alloc(u16, arr.len);
        errdefer allocator.free(out);
        for (arr, 0..) |v, i| {
            if (v != .integer) return error.InvalidResponse;
            out[i] = std.math.cast(u16, v.integer) orelse return error.InvalidResponse;
        }
        return out;
    }

    /// The result of `listbannedpubkeys`, `listallowedpubkeys`,
    /// `listbannedevents`, `listeventsneedingmoderation` and
    /// `listblockedips`: objects holding `key` (`pubkey`, `id` or `ip`) and
    /// an optional `reason`. The strings borrow from the response.
    pub fn targets(self: Response, allocator: std.mem.Allocator, key: []const u8) ParseError![]const Target {
        const arr = try self.array();
        const out = try allocator.alloc(Target, arr.len);
        errdefer allocator.free(out);
        for (arr, 0..) |v, i| {
            if (v != .object) return error.InvalidResponse;
            const val = v.object.get(key) orelse return error.InvalidResponse;
            if (val != .string) return error.InvalidResponse;
            var reason: ?[]const u8 = null;
            if (v.object.get("reason")) |r| switch (r) {
                .string => |s| reason = s,
                .null => {},
                else => return error.InvalidResponse,
            };
            out[i] = .{ .value = val.string, .reason = reason };
        }
        return out;
    }

    fn array(self: Response) error{InvalidResponse}![]const std.json.Value {
        const r = self.result orelse return error.InvalidResponse;
        if (r != .array) return error.InvalidResponse;
        return r.array.items;
    }
};

/// Parses a response body. A body carrying an `error` string yields a
/// `Response` with `err` set; one that is not an object is `InvalidResponse`.
pub fn parseResponse(gpa: std.mem.Allocator, body: []const u8) ParseError!Response {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidResponse,
    };
    if (root != .object) return error.InvalidResponse;

    var err: ?[]const u8 = null;
    if (root.object.get("error")) |e| switch (e) {
        .string => |s| err = s,
        .null => {},
        else => return error.InvalidResponse,
    };
    var result: ?std.json.Value = null;
    if (root.object.get("result")) |r| {
        if (r != .null) result = r;
    }
    if (result == null and err == null) return error.InvalidResponse;
    return .{ .arena = arena, .result = result, .err = err };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectEncoded(req: Request, want: []const u8) !void {
    const got = try encodeRequest(testing.allocator, req);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "nip86: request encoding" {
    try expectEncoded(.supportedmethods, "{\"method\":\"supportedmethods\",\"params\":[]}");
    try expectEncoded(.{ .banpubkey = .{ .value = "ab" } }, "{\"method\":\"banpubkey\",\"params\":[\"ab\"]}");
    try expectEncoded(.{ .banpubkey = .{ .value = "ab", .reason = "spam \"x\"" } }, "{\"method\":\"banpubkey\",\"params\":[\"ab\",\"spam \\\"x\\\"\"]}");
    try expectEncoded(.{ .allowevent = .{ .value = "cd", .reason = "ok" } }, "{\"method\":\"allowevent\",\"params\":[\"cd\",\"ok\"]}");
    try expectEncoded(.{ .changerelayname = "My Relay" }, "{\"method\":\"changerelayname\",\"params\":[\"My Relay\"]}");
    try expectEncoded(.{ .allowkind = 30023 }, "{\"method\":\"allowkind\",\"params\":[30023]}");
    try expectEncoded(.{ .blockip = .{ .value = "203.0.113.7" } }, "{\"method\":\"blockip\",\"params\":[\"203.0.113.7\"]}");
    try expectEncoded(.listblockedips, "{\"method\":\"listblockedips\",\"params\":[]}");
    try expectEncoded(.listeventsneedingmoderation, "{\"method\":\"listeventsneedingmoderation\",\"params\":[]}");
}

test "nip86: every method has a name and encodes" {
    const all = [_]Request{
        .supportedmethods,                         .{ .banpubkey = .{ .value = "a" } },   .{ .unbanpubkey = .{ .value = "a" } },
        .listbannedpubkeys,                        .{ .allowpubkey = .{ .value = "a" } }, .{ .unallowpubkey = .{ .value = "a" } },
        .listallowedpubkeys,                       .listeventsneedingmoderation,          .{ .allowevent = .{ .value = "a" } },
        .{ .banevent = .{ .value = "a" } },        .listbannedevents,                     .{ .changerelayname = "n" },
        .{ .changerelaydescription = "d" },        .{ .changerelayicon = "https://i" },   .{ .allowkind = 1 },
        .{ .disallowkind = 1 },                    .listallowedkinds,                     .{ .blockip = .{ .value = "1.2.3.4" } },
        .{ .unblockip = .{ .value = "1.2.3.4" } }, .listblockedips,
    };
    try testing.expectEqual(@typeInfo(Request).@"union".fields.len, all.len);
    for (all) |r| {
        const body = try encodeRequest(testing.allocator, r);
        defer testing.allocator.free(body);
        const want = try std.fmt.allocPrint(testing.allocator, "{{\"method\":\"{s}\",", .{r.method()});
        defer testing.allocator.free(want);
        try testing.expect(std.mem.startsWith(u8, body, want));
    }
}

test "nip86: parse results" {
    const gpa = testing.allocator;

    var ok = try parseResponse(gpa, "{\"result\":true}");
    defer ok.deinit();
    try testing.expect(try ok.boolResult());

    var sm = try parseResponse(gpa, "{\"result\":[\"banpubkey\",\"listbannedpubkeys\"]}");
    defer sm.deinit();
    const names = try sm.methods(gpa);
    defer gpa.free(names);
    try testing.expectEqual(@as(usize, 2), names.len);
    try testing.expectEqualStrings("listbannedpubkeys", names[1]);

    var bp = try parseResponse(gpa, "{\"result\":[{\"pubkey\":\"ab\",\"reason\":\"spam\"},{\"pubkey\":\"cd\"}]}");
    defer bp.deinit();
    const ts = try bp.targets(gpa, "pubkey");
    defer gpa.free(ts);
    try testing.expectEqualStrings("spam", ts[0].reason.?);
    try testing.expect(ts[1].reason == null);
    try testing.expectError(error.InvalidResponse, bp.targets(gpa, "id"));

    var ks = try parseResponse(gpa, "{\"result\":[1,30023]}");
    defer ks.deinit();
    const kinds = try ks.kinds(gpa);
    defer gpa.free(kinds);
    try testing.expectEqual(@as(u16, 30023), kinds[1]);
}

test "nip86: error responses" {
    const gpa = testing.allocator;
    var r = try parseResponse(gpa, "{\"result\":null,\"error\":\"unauthorized\"}");
    defer r.deinit();
    try testing.expect(r.isError());
    try testing.expectEqualStrings("unauthorized", r.err.?);
    try testing.expect(r.result == null);
    try testing.expectError(error.InvalidResponse, r.boolResult());

    var only = try parseResponse(gpa, "{\"error\":\"method not supported\"}");
    defer only.deinit();
    try testing.expect(only.isError());

    try testing.expectError(error.InvalidResponse, parseResponse(gpa, "[]"));
    try testing.expectError(error.InvalidResponse, parseResponse(gpa, "{}"));
    try testing.expectError(error.InvalidResponse, parseResponse(gpa, "nope"));
}

test "nip86: auth header binds the body" {
    const gpa = testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();
    const secret = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    const body = try encodeRequest(gpa, .listbannedpubkeys);
    defer gpa.free(body);
    const url = "https://relay.example.com/";
    const header = try authHeader(gpa, signer, kp, 1_700_000_000, url, body, null);
    defer gpa.free(header);

    _ = try nip98.verifyHeader(gpa, signer, header, .{ .url = url, .method = "POST", .body = body, .now = 1_700_000_000 });
    const other = try encodeRequest(gpa, .listallowedpubkeys);
    defer gpa.free(other);
    try testing.expectError(error.PayloadMismatch, nip98.verifyHeader(gpa, signer, header, .{ .url = url, .method = "POST", .body = other, .now = 1_700_000_000 }));
    try testing.expectEqualStrings("application/nostr+json+rpc", content_type);
}
