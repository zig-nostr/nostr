//! The signer loopback protocol's wire types: the request and response bodies
//! a keyholder daemon and its clients exchange over local HTTP. The shapes
//! live here so every product speaks the identical protocol, byte for byte,
//! without sharing a server: transport, ports, and authentication stay each
//! product's own concern; this module owns only what the bytes mean.
//!
//! The endpoints, by path constant:
//!   - `path_pubkey` (GET): the daemon's state and, once ready, whose key it
//!     holds. Clients poll this to detect a completed ceremony.
//!   - `path_setup` (POST): create a fresh key, or import one (nsec or
//!     ncryptsec). One-shot: a daemon that already holds a key refuses.
//!   - `path_sign` (POST): sign one event. The body carries the unsigned
//!     event JSON; the response carries it signed.
//!   - `path_nip44_encrypt` / `path_nip44_decrypt` (POST): BATCHED NIP-44
//!     conversation-key operations, N items in and N out in order. Batching
//!     is the point: a DM catch-up is thousands of decrypts, and one loopback
//!     round-trip per item would drown in connection overhead.
//!
//! Failures ride `Failure` with a non-2xx status. Parsing mirrors `nip46`:
//! an owned arena per parse, unknown fields ignored (forward compatibility).

const std = @import("std");
const json = @import("json.zig");

pub const path_pubkey = "/pubkey";
pub const path_setup = "/setup";
pub const path_sign = "/sign";
pub const path_nip44_encrypt = "/nip44/encrypt";
pub const path_nip44_decrypt = "/nip44/decrypt";

pub const Error = error{MalformedBody} || std.mem.Allocator.Error;

/// The daemon's lifecycle state as the wire spells it.
pub const state_uninitialized = "uninitialized";
pub const state_ready = "ready";

/// GET /pubkey response: which state the daemon is in, and whose key it
/// holds once ready (64 lowercase hex chars; empty while uninitialized).
pub const Pubkey = struct {
    state: []const u8,
    pubkey: []const u8 = "",

    pub fn toJson(self: Pubkey, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"state\":");
        try json.appendString(&list, gpa, self.state);
        try list.appendSlice(gpa, ",\"pubkey\":");
        try json.appendString(&list, gpa, self.pubkey);
        try list.append(gpa, '}');
        return list.toOwnedSlice(gpa);
    }
};

/// POST /setup request. `method` is "create" or "import"; an import carries
/// the pasted secret (`nsec1…` or `ncryptsec1…`) and, when the secret is an
/// ncryptsec, the passphrase that opens it. How the daemon protects the key
/// at rest afterwards is its own policy, not the wire's.
pub const Setup = struct {
    method: []const u8,
    secret: []const u8 = "",
    passphrase: []const u8 = "",

    pub const method_create = "create";
    pub const method_import = "import";

    pub fn toJson(self: Setup, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"method\":");
        try json.appendString(&list, gpa, self.method);
        if (self.secret.len != 0) {
            try list.appendSlice(gpa, ",\"secret\":");
            try json.appendString(&list, gpa, self.secret);
        }
        if (self.passphrase.len != 0) {
            try list.appendSlice(gpa, ",\"passphrase\":");
            try json.appendString(&list, gpa, self.passphrase);
        }
        try list.append(gpa, '}');
        return list.toOwnedSlice(gpa);
    }
};

/// POST /sign request and response: one event in, the same event out signed.
/// The event travels as its canonical JSON, so the daemon's parser (which
/// verifies before it trusts) is the only one that ever reads it.
pub const SignEvent = struct {
    event: []const u8,

    pub fn toJson(self: SignEvent, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"event\":");
        try json.appendString(&list, gpa, self.event);
        try list.append(gpa, '}');
        return list.toOwnedSlice(gpa);
    }
};

/// POST /nip44/encrypt|decrypt: N plaintexts (or ciphertexts) against one
/// conversation peer, answered by N outputs in the same order.
pub const Cipher = struct {
    peer: []const u8,
    items: []const []const u8,

    pub fn toJson(self: Cipher, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"peer\":");
        try json.appendString(&list, gpa, self.peer);
        try list.appendSlice(gpa, ",\"items\":[");
        for (self.items, 0..) |item, i| {
            if (i != 0) try list.append(gpa, ',');
            try json.appendString(&list, gpa, item);
        }
        try list.appendSlice(gpa, "]}");
        return list.toOwnedSlice(gpa);
    }
};

/// The batched response for either cipher direction.
pub const CipherResult = struct {
    items: []const []const u8,

    pub fn toJson(self: CipherResult, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"items\":[");
        for (self.items, 0..) |item, i| {
            if (i != 0) try list.append(gpa, ',');
            try json.appendString(&list, gpa, item);
        }
        try list.appendSlice(gpa, "]}");
        return list.toOwnedSlice(gpa);
    }
};

/// Any failed request: a non-2xx status whose body says why, plainly.
pub const Failure = struct {
    @"error": []const u8,

    pub fn toJson(self: Failure, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"error\":");
        try json.appendString(&list, gpa, self.@"error");
        try list.append(gpa, '}');
        return list.toOwnedSlice(gpa);
    }
};

/// A parsed value whose fields are backed by an owned arena. Call `deinit`.
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

/// Parses `body` as `T`. Unknown fields are ignored so either side can grow
/// the protocol without breaking the other; a missing required field is a
/// `MalformedBody`. The arena owns real copies: the caller frees `body`.
pub fn parse(comptime T: type, gpa: std.mem.Allocator, body: []const u8) Error!Parsed(T) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const value = std.json.parseFromSliceLeaky(T, arena.allocator(), body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return Error.MalformedBody;
    return .{ .arena = arena, .value = value };
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

test "every wire type round-trips through its JSON" {
    const gpa = testing.allocator;

    const pk = Pubkey{ .state = state_ready, .pubkey = "ab" ** 32 };
    const pk_json = try pk.toJson(gpa);
    defer gpa.free(pk_json);
    var pk_back = try parse(Pubkey, gpa, pk_json);
    defer pk_back.deinit();
    try testing.expectEqualStrings(pk.pubkey, pk_back.value.pubkey);
    try testing.expectEqualStrings(state_ready, pk_back.value.state);

    const setup = Setup{ .method = Setup.method_import, .secret = "nsec1qqq", .passphrase = "hunter2" };
    const setup_json = try setup.toJson(gpa);
    defer gpa.free(setup_json);
    var setup_back = try parse(Setup, gpa, setup_json);
    defer setup_back.deinit();
    try testing.expectEqualStrings("nsec1qqq", setup_back.value.secret);
    try testing.expectEqualStrings("hunter2", setup_back.value.passphrase);

    const sign = SignEvent{ .event = "{\"kind\":1,\"content\":\"hi \\\"quoted\\\"\"}" };
    const sign_json = try sign.toJson(gpa);
    defer gpa.free(sign_json);
    var sign_back = try parse(SignEvent, gpa, sign_json);
    defer sign_back.deinit();
    try testing.expectEqualStrings(sign.event, sign_back.value.event);

    const cipher = Cipher{ .peer = "cd" ** 32, .items = &.{ "one", "two", "three" } };
    const cipher_json = try cipher.toJson(gpa);
    defer gpa.free(cipher_json);
    var cipher_back = try parse(Cipher, gpa, cipher_json);
    defer cipher_back.deinit();
    try testing.expectEqual(@as(usize, 3), cipher_back.value.items.len);
    try testing.expectEqualStrings("three", cipher_back.value.items[2]);

    const fail = Failure{ .@"error" = "keystore already exists" };
    const fail_json = try fail.toJson(gpa);
    defer gpa.free(fail_json);
    var fail_back = try parse(Failure, gpa, fail_json);
    defer fail_back.deinit();
    try testing.expectEqualStrings("keystore already exists", fail_back.value.@"error");
}

test "a create setup omits the secret entirely" {
    const gpa = testing.allocator;
    const setup = Setup{ .method = Setup.method_create };
    const body = try setup.toJson(gpa);
    defer gpa.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "secret") == null);
    try testing.expect(std.mem.indexOf(u8, body, "passphrase") == null);

    var back = try parse(Setup, gpa, body);
    defer back.deinit();
    try testing.expectEqualStrings(Setup.method_create, back.value.method);
    try testing.expectEqualStrings("", back.value.secret);
}

test "unknown fields are tolerated, missing required fields are not" {
    const gpa = testing.allocator;

    // A future daemon may add fields; today's client must not choke.
    var grown = try parse(Pubkey, gpa, "{\"state\":\"ready\",\"pubkey\":\"aa\",\"relays\":[1,2]}");
    defer grown.deinit();
    try testing.expectEqualStrings("aa", grown.value.pubkey);

    // No `method` is not a setup request at all.
    try testing.expectError(Error.MalformedBody, parse(Setup, gpa, "{\"secret\":\"nsec1x\"}"));
    // Junk is junk.
    try testing.expectError(Error.MalformedBody, parse(SignEvent, gpa, "not json"));
}

test "batched cipher items keep their order" {
    const gpa = testing.allocator;
    var items: [40][]const u8 = undefined;
    var bufs: [40][8]u8 = undefined;
    for (&items, 0..) |*it, i| {
        it.* = std.fmt.bufPrint(&bufs[i], "item{d}", .{i}) catch unreachable;
    }
    const req = Cipher{ .peer = "ef" ** 32, .items = &items };
    const body = try req.toJson(gpa);
    defer gpa.free(body);
    var back = try parse(Cipher, gpa, body);
    defer back.deinit();
    try testing.expectEqual(@as(usize, 40), back.value.items.len);
    try testing.expectEqualStrings("item0", back.value.items[0]);
    try testing.expectEqualStrings("item39", back.value.items[39]);
}
