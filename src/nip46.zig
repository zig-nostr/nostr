//! NIP-46 remote signing (Nostr Connect / "bunker").
//!
//! Transport-agnostic protocol layer: the request/response messages, the
//! kind:24133 NIP-44 envelope, and a `Bunker` that answers requests using a
//! local key behind an approval policy. Relay I/O is intentionally out of
//! scope — callers move the `event.Event`s produced and consumed here over
//! whatever transport they use (see `src/relay.zig`); the native signer app
//! wires those together.
//!
//! Requests flow client -> remote-signer, responses flow back. Both are
//! kind:24133 events whose `content` is a NIP-44-encrypted JSON-RPC-like
//! object `p`-tagging the recipient's communication pubkey. Per NIP-46 the
//! remote-signer's communication key MAY differ from the user key it signs
//! with; `Bunker` keeps them as separate fields (set them equal for the common
//! single-key setup).

const std = @import("std");
const keys = @import("keys.zig");
const event = @import("event.zig");
const nip44 = @import("nip44.zig");
const hex = @import("hex.zig");
const json = @import("json.zig");

/// The NIP-46 event kind for both requests and responses.
pub const kind: u16 = 24133;

pub const Error = error{
    /// The event was not kind:24133.
    WrongEventKind,
    /// The decrypted content was not a well-formed request/response object.
    MalformedContent,
} || nip44.Error || keys.Error || hex.Error;

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

/// The subset of NIP-46 methods this library dispatches. Unknown method names
/// parse fine as a `Request` but yield an error response from `Bunker.handle`.
pub const Method = enum {
    connect,
    sign_event,
    ping,
    get_public_key,
    nip44_encrypt,
    nip44_decrypt,
    logout,

    pub fn fromString(s: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "connect", .connect },
            .{ "sign_event", .sign_event },
            .{ "ping", .ping },
            .{ "get_public_key", .get_public_key },
            .{ "nip44_encrypt", .nip44_encrypt },
            .{ "nip44_decrypt", .nip44_decrypt },
            .{ "logout", .logout },
        });
        return map.get(s);
    }

    /// The wire method name — identical to the enum tag by construction.
    pub fn name(self: Method) []const u8 {
        return @tagName(self);
    }
};

// ---------------------------------------------------------------------------
// Request / Response messages
// ---------------------------------------------------------------------------

/// A decrypted NIP-46 request: `{ id, method, params }`.
pub const Request = struct {
    id: []const u8,
    method: []const u8,
    params: []const []const u8,

    /// Serializes to the wire JSON that goes (encrypted) into an event's
    /// `content`. Owned by the caller.
    pub fn toJson(self: Request, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"id\":");
        try json.appendString(&list, gpa, self.id);
        try list.appendSlice(gpa, ",\"method\":");
        try json.appendString(&list, gpa, self.method);
        try list.appendSlice(gpa, ",\"params\":[");
        for (self.params, 0..) |p, i| {
            if (i != 0) try list.append(gpa, ',');
            try json.appendString(&list, gpa, p);
        }
        try list.appendSlice(gpa, "]}");
        return list.toOwnedSlice(gpa);
    }
};

/// A decrypted NIP-46 response: `{ id, result, error? }`. A non-empty `err`
/// signals a failed request.
pub const Response = struct {
    id: []const u8,
    result: []const u8 = "",
    err: []const u8 = "",

    /// Serializes to the wire JSON. The `error` key is emitted only when
    /// `err` is non-empty. Owned by the caller.
    pub fn toJson(self: Response, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        try list.appendSlice(gpa, "{\"id\":");
        try json.appendString(&list, gpa, self.id);
        try list.appendSlice(gpa, ",\"result\":");
        try json.appendString(&list, gpa, self.result);
        if (self.err.len != 0) {
            try list.appendSlice(gpa, ",\"error\":");
            try json.appendString(&list, gpa, self.err);
        }
        try list.append(gpa, '}');
        return list.toOwnedSlice(gpa);
    }
};

const WireRequest = struct {
    id: []const u8,
    method: []const u8,
    params: []const []const u8 = &.{},
};

const WireResponse = struct {
    id: []const u8,
    result: []const u8 = "",
    @"error": []const u8 = "",
};

/// A `Request` whose fields are backed by an owned arena. Call `deinit`.
pub const ParsedRequest = struct {
    arena: *std.heap.ArenaAllocator,
    value: Request,

    pub fn deinit(self: *ParsedRequest) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses decrypted request `content` JSON.
pub fn parseRequest(gpa: std.mem.Allocator, content: []const u8) Error!ParsedRequest {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    // alloc_always so the arena owns real copies — the caller frees `content`.
    const wire = std.json.parseFromSliceLeaky(WireRequest, a, content, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return Error.MalformedContent;
    return .{
        .arena = arena,
        .value = .{ .id = wire.id, .method = wire.method, .params = wire.params },
    };
}

/// A `Response` whose fields are backed by an owned arena. Call `deinit`.
pub const ParsedResponse = struct {
    arena: *std.heap.ArenaAllocator,
    value: Response,

    pub fn deinit(self: *ParsedResponse) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses decrypted response `content` JSON.
pub fn parseResponse(gpa: std.mem.Allocator, content: []const u8) Error!ParsedResponse {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    // alloc_always so the arena owns real copies — the caller frees `content`.
    const wire = std.json.parseFromSliceLeaky(WireResponse, a, content, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return Error.MalformedContent;
    return .{
        .arena = arena,
        .value = .{ .id = wire.id, .result = wire.result, .err = wire.@"error" },
    };
}

// ---------------------------------------------------------------------------
// kind:24133 envelope (NIP-44 seal / open)
// ---------------------------------------------------------------------------

/// A signed kind:24133 event with the arena backing its `content`/`tags`.
/// Publish `event`, then `deinit`.
pub const SealedEvent = struct {
    arena: *std.heap.ArenaAllocator,
    event: event.Event,

    pub fn deinit(self: *SealedEvent) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Wraps `content_json` (a request or response) into a signed kind:24133 event
/// from `sender` to `recipient`: NIP-44-encrypts the content and `p`-tags the
/// recipient. `io` supplies the encryption nonce.
pub fn seal(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    sender: keys.KeyPair,
    recipient: keys.PublicKey,
    content_json: []const u8,
    created_at: i64,
) Error!SealedEvent {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();

    const ciphertext = try nip44.encrypt(a, io, signer, sender.secret_key, recipient, content_json);
    const ptag = try hex.encode(a, &recipient);
    const fields = try a.alloc([]const u8, 2);
    fields[0] = "p";
    fields[1] = ptag;
    const tags = try a.alloc(event.Tag, 1);
    tags[0] = fields;

    const ev = try event.create(a, signer, sender, created_at, kind, tags, ciphertext, null);
    return .{ .arena = arena, .event = ev };
}

/// Decrypts the NIP-44 `content` of an incoming kind:24133 event addressed to
/// us. `my_secret` is our communication secret key; the counterparty is the
/// event's author. Returns the owned plaintext JSON (a request or response).
pub fn open(
    gpa: std.mem.Allocator,
    signer: keys.Signer,
    my_secret: keys.SecretKey,
    ev: event.Event,
) Error![]u8 {
    if (ev.kind != kind) return Error.WrongEventKind;
    return nip44.decrypt(gpa, signer, my_secret, ev.pubkey, ev.content);
}

// ---------------------------------------------------------------------------
// Bunker (remote-signer) dispatch
// ---------------------------------------------------------------------------

/// A per-request approval decision. The native signer maps this onto its UI;
/// tests and headless "auto-approve" modes supply a constant policy.
pub const Decision = enum { approve, reject };

/// An approval hook. `ctx` is an opaque pointer the caller threads through to
/// `decideFn` (e.g. to reach UI state); it is never dereferenced here.
pub const Policy = struct {
    ctx: ?*anyopaque = null,
    decideFn: *const fn (ctx: ?*anyopaque, request: *const Request) Decision,

    pub fn decide(self: Policy, request: *const Request) Decision {
        return self.decideFn(self.ctx, request);
    }
};

fn approveAllFn(_: ?*anyopaque, _: *const Request) Decision {
    return .approve;
}

/// A policy that approves every request (headless / auto-approve mode).
pub fn approveAll() Policy {
    return .{ .decideFn = &approveAllFn };
}

/// A `Response` whose owned strings are backed by an arena. Call `deinit`.
pub const OwnedResponse = struct {
    arena: *std.heap.ArenaAllocator,
    value: Response,

    pub fn deinit(self: *OwnedResponse) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

const WireTemplate = struct {
    kind: u16,
    content: []const u8 = "",
    tags: []const []const []const u8 = &.{},
    created_at: ?i64 = null,
};

/// A NIP-46 remote signer. Holds the libsecp256k1 context and the keys it
/// operates with, and answers decrypted requests behind an approval `policy`.
pub const Bunker = struct {
    signer: keys.Signer,
    /// The user key used to sign events and perform NIP-44 operations.
    user: keys.KeyPair,
    /// The communication key the client talks to. Equal to `user` in the
    /// common single-key setup; kept separate per NIP-46.
    remote: keys.KeyPair,
    /// Optional connect secret the client must echo in `connect` params.
    secret: ?[]const u8 = null,
    policy: Policy,

    /// A single-key bunker where the communication and user keys are the same.
    pub fn initSingleKey(signer: keys.Signer, keypair: keys.KeyPair, policy: Policy) Bunker {
        return .{ .signer = signer, .user = keypair, .remote = keypair, .policy = policy };
    }

    /// Answers a decrypted `request`, returning the response to seal back to
    /// the client. Validation and denied requests become error responses;
    /// only allocation failures propagate as errors.
    pub fn handle(
        self: Bunker,
        gpa: std.mem.Allocator,
        io: std.Io,
        request: Request,
    ) Error!OwnedResponse {
        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        errdefer {
            arena.deinit();
            gpa.destroy(arena);
        }
        const a = arena.allocator();
        const id = try a.dupe(u8, request.id);

        const method = Method.fromString(request.method) orelse
            return errorResponse(arena, id, "unsupported method");

        if (self.policy.decide(&request) == .reject)
            return errorResponse(arena, id, "request denied");

        switch (method) {
            .ping => return okResponse(arena, id, try a.dupe(u8, "pong")),
            .logout => return okResponse(arena, id, try a.dupe(u8, "ack")),
            .connect => {
                if (self.secret) |want| {
                    const got = if (request.params.len >= 2) request.params[1] else "";
                    if (!std.mem.eql(u8, want, got))
                        return errorResponse(arena, id, "invalid secret");
                }
                return okResponse(arena, id, try a.dupe(u8, "ack"));
            },
            .get_public_key => return okResponse(arena, id, try hex.encode(a, &self.user.public_key)),
            .sign_event => {
                if (request.params.len < 1) return errorResponse(arena, id, "missing event");
                const signed = self.signTemplate(a, request.params[0]) catch |e| {
                    if (e == error.OutOfMemory) return error.OutOfMemory;
                    return errorResponse(arena, id, "invalid event");
                };
                return okResponse(arena, id, signed);
            },
            .nip44_encrypt, .nip44_decrypt => {
                if (request.params.len < 2) return errorResponse(arena, id, "missing params");
                const third = hex.decodeFixed(32, request.params[0]) catch
                    return errorResponse(arena, id, "invalid pubkey");
                const out = (if (method == .nip44_encrypt)
                    nip44.encrypt(a, io, self.signer, self.user.secret_key, third, request.params[1])
                else
                    nip44.decrypt(a, self.signer, self.user.secret_key, third, request.params[1])) catch |e|
                    {
                        if (e == error.OutOfMemory) return error.OutOfMemory;
                        return errorResponse(arena, id, "nip44 operation failed");
                    };
                return okResponse(arena, id, out);
            },
        }
    }

    /// Signs a `{kind, content, tags, created_at}` template with the user key
    /// and returns the JSON-stringified signed event. `created_at` is required
    /// (the client stamps it, per NIP-46) — a protocol library shouldn't carry
    /// an ambient clock.
    fn signTemplate(self: Bunker, a: std.mem.Allocator, template_json: []const u8) Error![]u8 {
        const tmpl = std.json.parseFromSliceLeaky(WireTemplate, a, template_json, .{
            .ignore_unknown_fields = true,
        }) catch return Error.MalformedContent;
        const created_at = tmpl.created_at orelse return Error.MalformedContent;
        const ev = try event.create(a, self.signer, self.user, created_at, tmpl.kind, tmpl.tags, tmpl.content, null);
        return event.toJson(a, ev);
    }
};

fn okResponse(arena: *std.heap.ArenaAllocator, id: []const u8, result: []const u8) OwnedResponse {
    return .{ .arena = arena, .value = .{ .id = id, .result = result, .err = "" } };
}

fn errorResponse(arena: *std.heap.ArenaAllocator, id: []const u8, message: []const u8) OwnedResponse {
    return .{ .arena = arena, .value = .{ .id = id, .result = "", .err = message } };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "NIP-46 request JSON round trip" {
    const gpa = testing.allocator;
    const params = [_][]const u8{ "aa", "bb\"c" };
    const req = Request{ .id = "req1", .method = "sign_event", .params = &params };

    const encoded = try req.toJson(gpa);
    defer gpa.free(encoded);
    try testing.expectEqualStrings(
        "{\"id\":\"req1\",\"method\":\"sign_event\",\"params\":[\"aa\",\"bb\\\"c\"]}",
        encoded,
    );

    var parsed = try parseRequest(gpa, encoded);
    defer parsed.deinit();
    try testing.expectEqualStrings("req1", parsed.value.id);
    try testing.expectEqualStrings("sign_event", parsed.value.method);
    try testing.expectEqual(@as(usize, 2), parsed.value.params.len);
    try testing.expectEqualStrings("bb\"c", parsed.value.params[1]);
}

test "NIP-46 response JSON round trip with and without error" {
    const gpa = testing.allocator;

    const ok = Response{ .id = "r", .result = "pong" };
    const ok_json = try ok.toJson(gpa);
    defer gpa.free(ok_json);
    try testing.expectEqualStrings("{\"id\":\"r\",\"result\":\"pong\"}", ok_json);

    const bad = Response{ .id = "r", .err = "denied" };
    const bad_json = try bad.toJson(gpa);
    defer gpa.free(bad_json);
    try testing.expectEqualStrings("{\"id\":\"r\",\"result\":\"\",\"error\":\"denied\"}", bad_json);

    var parsed = try parseResponse(gpa, bad_json);
    defer parsed.deinit();
    try testing.expectEqualStrings("denied", parsed.value.err);
    try testing.expectEqualStrings("", parsed.value.result);
}

test "NIP-46 method parsing" {
    try testing.expectEqual(Method.sign_event, Method.fromString("sign_event").?);
    try testing.expectEqual(Method.nip44_decrypt, Method.fromString("nip44_decrypt").?);
    try testing.expectEqual(@as(?Method, null), Method.fromString("nip04_encrypt"));
    try testing.expectEqualStrings("get_public_key", Method.get_public_key.name());
}

const TestParties = struct {
    signer: keys.Signer,
    client: keys.KeyPair,
    user: keys.KeyPair,

    fn init() !TestParties {
        var signer = try keys.Signer.initRandomized(testing.io);
        errdefer signer.deinit();
        return .{
            .signer = signer,
            .client = try signer.generateKeyPair(testing.io),
            .user = try signer.generateKeyPair(testing.io),
        };
    }

    fn deinit(self: *TestParties) void {
        self.signer.deinit();
    }
};

test "NIP-46 seal/open round trip carries the request unchanged" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();

    const req = Request{ .id = "x1", .method = "ping", .params = &.{} };
    const content = try req.toJson(gpa);
    defer gpa.free(content);

    // Client seals to the remote-signer (here, the user key).
    var sealed = try seal(gpa, testing.io, p.signer, p.client, p.user.public_key, content, 1700000000);
    defer sealed.deinit();
    try testing.expectEqual(kind, sealed.event.kind);
    try testing.expectEqualSlices(u8, &p.client.public_key, &sealed.event.pubkey);
    try testing.expect(try event.verify(gpa, p.signer, sealed.event));

    // Remote-signer opens with its secret and the client (author) pubkey.
    const opened = try open(gpa, p.signer, p.user.secret_key, sealed.event);
    defer gpa.free(opened);
    try testing.expectEqualStrings(content, opened);
}

test "NIP-46 open rejects a non-24133 event" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    const ev = try event.create(gpa, p.signer, p.client, 1700000000, 1, &.{}, "hi", null);
    try testing.expectError(Error.WrongEventKind, open(gpa, p.signer, p.user.secret_key, ev));
}

/// Runs one full client -> bunker -> client exchange and returns the parsed
/// response (caller deinits). `bunker` handles the request; the request event
/// is sealed from the client to the bunker's remote key.
fn exchange(gpa: std.mem.Allocator, p: *TestParties, bunker: Bunker, req: Request) !ParsedResponse {
    const req_json = try req.toJson(gpa);
    defer gpa.free(req_json);

    var req_event = try seal(gpa, testing.io, p.signer, p.client, bunker.remote.public_key, req_json, 1700000000);
    defer req_event.deinit();

    const opened = try open(gpa, p.signer, bunker.remote.secret_key, req_event.event);
    defer gpa.free(opened);
    var parsed_req = try parseRequest(gpa, opened);
    defer parsed_req.deinit();

    var resp = try bunker.handle(gpa, testing.io, parsed_req.value);
    defer resp.deinit();
    const resp_json = try resp.value.toJson(gpa);
    defer gpa.free(resp_json);

    var resp_event = try seal(gpa, testing.io, p.signer, bunker.remote, p.client.public_key, resp_json, 1700000001);
    defer resp_event.deinit();

    const opened_resp = try open(gpa, p.signer, p.client.secret_key, resp_event.event);
    defer gpa.free(opened_resp);
    return parseResponse(gpa, opened_resp);
}

test "NIP-46 bunker signs an event end to end" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    const bunker = Bunker.initSingleKey(p.signer, p.user, approveAll());

    const template = "{\"kind\":1,\"content\":\"hello remote\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};
    const req = Request{ .id = "sign1", .method = "sign_event", .params = &params };

    var resp = try exchange(gpa, &p, bunker, req);
    defer resp.deinit();

    try testing.expectEqualStrings("sign1", resp.value.id);
    try testing.expectEqualStrings("", resp.value.err);

    // The result is a fully signed event by the user key that verifies.
    var signed = try event.fromJson(gpa, resp.value.result);
    defer signed.deinit();
    try testing.expectEqual(@as(u16, 1), signed.value.kind);
    try testing.expectEqualStrings("hello remote", signed.value.content);
    try testing.expectEqualSlices(u8, &p.user.public_key, &signed.value.pubkey);
    try testing.expect(try event.verify(gpa, p.signer, signed.value));
}

test "NIP-46 bunker answers get_public_key and ping" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    const bunker = Bunker.initSingleKey(p.signer, p.user, approveAll());

    {
        const req = Request{ .id = "gp", .method = "get_public_key", .params = &.{} };
        var resp = try exchange(gpa, &p, bunker, req);
        defer resp.deinit();
        const want = try hex.encode(gpa, &p.user.public_key);
        defer gpa.free(want);
        try testing.expectEqualStrings(want, resp.value.result);
    }
    {
        const req = Request{ .id = "pg", .method = "ping", .params = &.{} };
        var resp = try exchange(gpa, &p, bunker, req);
        defer resp.deinit();
        try testing.expectEqualStrings("pong", resp.value.result);
    }
}

test "NIP-46 bunker nip44 encrypt then decrypt round trips" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    const bunker = Bunker.initSingleKey(p.signer, p.user, approveAll());

    // A third party the user is messaging.
    const third = try p.signer.generateKeyPair(testing.io);
    const third_hex = try hex.encode(gpa, &third.public_key);
    defer gpa.free(third_hex);

    const enc_params = [_][]const u8{ third_hex, "secret note" };
    const enc_req = Request{ .id = "e", .method = "nip44_encrypt", .params = &enc_params };
    var enc_resp = try exchange(gpa, &p, bunker, enc_req);
    defer enc_resp.deinit();
    try testing.expectEqualStrings("", enc_resp.value.err);

    // The user can decrypt its own ciphertext back to the plaintext.
    const dec_params = [_][]const u8{ third_hex, enc_resp.value.result };
    const dec_req = Request{ .id = "d", .method = "nip44_decrypt", .params = &dec_params };
    var dec_resp = try exchange(gpa, &p, bunker, dec_req);
    defer dec_resp.deinit();
    try testing.expectEqualStrings("secret note", dec_resp.value.result);
}

test "NIP-46 bunker rejects denied and unknown requests" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();

    const reject = struct {
        fn f(_: ?*anyopaque, _: *const Request) Decision {
            return .reject;
        }
    }.f;
    const bunker = Bunker.initSingleKey(p.signer, p.user, .{ .decideFn = &reject });

    const req = Request{ .id = "z", .method = "get_public_key", .params = &.{} };
    var resp = try exchange(gpa, &p, bunker, req);
    defer resp.deinit();
    try testing.expectEqualStrings("request denied", resp.value.err);
    try testing.expectEqualStrings("", resp.value.result);

    // Unknown methods are rejected even under an approve-all policy.
    const open_bunker = Bunker.initSingleKey(p.signer, p.user, approveAll());
    const unknown = Request{ .id = "u", .method = "nip04_encrypt", .params = &.{} };
    var uresp = try exchange(gpa, &p, open_bunker, unknown);
    defer uresp.deinit();
    try testing.expectEqualStrings("unsupported method", uresp.value.err);
}

test "NIP-46 connect validates an optional secret" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();

    var bunker = Bunker.initSingleKey(p.signer, p.user, approveAll());
    bunker.secret = "hunter2";

    const remote_hex = try hex.encode(gpa, &p.user.public_key);
    defer gpa.free(remote_hex);

    {
        const good = [_][]const u8{ remote_hex, "hunter2" };
        const req = Request{ .id = "c1", .method = "connect", .params = &good };
        var resp = try exchange(gpa, &p, bunker, req);
        defer resp.deinit();
        try testing.expectEqualStrings("ack", resp.value.result);
    }
    {
        const bad = [_][]const u8{ remote_hex, "wrong" };
        const req = Request{ .id = "c2", .method = "connect", .params = &bad };
        var resp = try exchange(gpa, &p, bunker, req);
        defer resp.deinit();
        try testing.expectEqualStrings("invalid secret", resp.value.err);
    }
}
