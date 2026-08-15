//! NIP-46 remote signing (Nostr Connect / "bunker").
//!
//! Transport-agnostic protocol layer: the request/response messages, the
//! kind:24133 NIP-44 envelope, the `bunker://` / `nostrconnect://` connection
//! URIs, and a `Bunker` that answers requests using a local key behind an
//! approval policy. Relay I/O is intentionally out of
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
    /// A connection URI had a bad scheme, pubkey, or missing required field.
    InvalidUri,
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
    /// `client` is the pubkey of the event that carried the request.
    ///
    /// A policy that cannot see who is asking cannot tell the user either, and
    /// an approval prompt that names a method and an event kind but not the
    /// requester asks a human to authorize a signature by a stranger with no
    /// way to notice. The bunker has already established that this client
    /// connected; the policy is where a decision gets made about it.
    decideFn: *const fn (ctx: ?*anyopaque, request: *const Request, client: [32]u8) Decision,

    pub fn decide(self: Policy, request: *const Request, client: [32]u8) Decision {
        return self.decideFn(self.ctx, request, client);
    }
};

fn approveAllFn(_: ?*anyopaque, _: *const Request, _: [32]u8) Decision {
    return .approve;
}

/// A policy that approves every request (headless / auto-approve mode).
pub fn approveAll() Policy {
    return .{ .decideFn = &approveAllFn };
}

/// Operator-configured least-privilege authorization, built into a `Policy`.
/// A null allowlist means "no restriction"; a non-null one is an allowlist.
/// `connect`, `ping`, and `logout` are always permitted (rejecting them would
/// only break the client handshake, not protect the key), and an unknown method
/// fails closed. The default (both allowlists null) decides in O(1) with no
/// allocation; a kind allowlist parses only a `sign_event` template's `kind`
/// field, off the hot path and dwarfed by the signing a permitted request
/// triggers. Pass to `policy()` by pointer as `ctx`, so it must outlive the
/// bunker that holds the returned policy.
pub const PolicyConfig = struct {
    /// Allocator used to parse an event template's kind when `allowed_kinds`
    /// is set; unused when it is null.
    gpa: std.mem.Allocator,
    /// Key-touching methods the signer will honor; null = no restriction.
    /// `connect`/`ping`/`logout` are always allowed regardless.
    allowed_methods: ?[]const Method = null,
    /// Event kinds the signer will `sign_event` for; null = any kind.
    allowed_kinds: ?[]const u16 = null,

    /// Builds the `Policy` backed by this config. `self` must outlive the
    /// bunker that holds the returned policy (it is threaded through as `ctx`).
    pub fn policy(self: *const PolicyConfig) Policy {
        return .{ .ctx = @constCast(self), .decideFn = &decidePolicyConfig };
    }
};

/// Methods a `PolicyConfig` never restricts: rejecting them would break the
/// NIP-46 handshake/liveness, not protect the key.
fn policyConfigAlwaysAllowed(method: Method) bool {
    return switch (method) {
        .connect, .ping, .logout => true,
        else => false,
    };
}

fn decidePolicyConfig(ctx: ?*anyopaque, request: *const Request, _: [32]u8) Decision {
    const cfg: *const PolicyConfig = @ptrCast(@alignCast(ctx.?));

    // Unknown/unsupported method: fail closed. (The bunker rejects these too,
    // but the policy must never approve something it can't classify.)
    const method = Method.fromString(request.method) orelse return .reject;

    if (!policyConfigAlwaysAllowed(method)) {
        if (cfg.allowed_methods) |allowed| {
            if (std.mem.indexOfScalar(Method, allowed, method) == null) return .reject;
        }
    }

    if (method == .sign_event) {
        if (cfg.allowed_kinds) |kinds| {
            const event_kind = signEventKind(cfg.gpa, request) orelse return .reject;
            if (std.mem.indexOfScalar(u16, kinds, event_kind) == null) return .reject;
        }
    }

    return .approve;
}

/// Parses the `kind` from a `sign_event` request's event template (params[0]),
/// or null if it is missing or unparseable (the caller treats null as "deny").
pub fn signEventKind(gpa: std.mem.Allocator, request: *const Request) ?u16 {
    if (request.params.len < 1) return null;
    const parsed = std.json.parseFromSlice(
        struct { kind: u16 },
        gpa,
        request.params[0],
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    defer parsed.deinit();
    return parsed.value.kind;
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
/// Equality that does not stop at the first differing byte.
///
/// The connect secret is a bearer token, and an attacker may present a guess as
/// often as they like. A comparison that returns early tells them how much of
/// their guess was right. The length is compared openly, which leaks only the
/// length, as every such comparison does.
fn secretEql(want: []const u8, got: []const u8) bool {
    if (want.len != got.len) return false;
    var diff: u8 = 0;
    for (want, got) |a, b| diff |= a ^ b;
    return diff == 0;
}

/// How many clients a bunker will remember as connected at once.
///
/// A person runs a handful: a desktop client, a phone, a web client. The oldest
/// is dropped when a new one arrives, and a dropped client simply has to
/// `connect` again, which is a round trip rather than a lockout.
pub const max_authorized_clients = 16;

/// Who has completed `connect`, as a thing of its own that several threads can
/// share.
///
/// It is separate from `Bunker`, and the caller's, because of how a signer on
/// more than one relay is built. Each relay runs its own thread with its own
/// `Bunker`, since each needs its own secp256k1 context, and the connect state
/// has to be the SAME across all of them. Otherwise a client that connected
/// over one relay and whose next request happens to arrive on another is told
/// "not connected": everything needed to reach the signer is in the token, so
/// a client publishes to every relay in it and which one gets there first is
/// nobody's choice.
///
/// Locked, because those threads reach it at the same time. Contention is
/// near-zero: connects are human-paced and the critical section is a scan of at
/// most sixteen keys.
pub const AuthorizedClients = struct {
    lock: std.atomic.Value(bool) = .init(false),
    ids: [max_authorized_clients][32]u8 = undefined,
    len: usize = 0,

    fn acquire(self: *AuthorizedClients) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
    }

    fn release(self: *AuthorizedClients) void {
        self.lock.store(false, .release);
    }

    pub fn isAuthorized(self: *AuthorizedClients, client: [32]u8) bool {
        self.acquire();
        defer self.release();
        for (self.ids[0..self.len]) |known| {
            if (std.mem.eql(u8, &known, &client)) return true;
        }
        return false;
    }

    /// Records `client` as connected. Idempotent; drops the oldest when full.
    pub fn authorize(self: *AuthorizedClients, client: [32]u8) void {
        self.acquire();
        defer self.release();
        for (self.ids[0..self.len]) |known| {
            if (std.mem.eql(u8, &known, &client)) return;
        }
        if (self.len == self.ids.len) {
            std.mem.copyForwards([32]u8, self.ids[0 .. self.ids.len - 1], self.ids[1..]);
            self.len -= 1;
        }
        self.ids[self.len] = client;
        self.len += 1;
    }

    /// Forgets `client`, so its next request has to connect again.
    pub fn revoke(self: *AuthorizedClients, client: [32]u8) void {
        self.acquire();
        defer self.release();
        for (self.ids[0..self.len], 0..) |known, i| {
            if (!std.mem.eql(u8, &known, &client)) continue;
            std.mem.copyForwards([32]u8, self.ids[i .. self.len - 1], self.ids[i + 1 .. self.len]);
            self.len -= 1;
            return;
        }
    }

    /// Forgets everybody. What signing out of a signer has to do: a session that
    /// outlives the key it was granted against is a client still holding an
    /// authorization for an account that is no longer here.
    pub fn clear(self: *AuthorizedClients) void {
        self.acquire();
        defer self.release();
        self.len = 0;
    }

    pub fn count(self: *AuthorizedClients) usize {
        self.acquire();
        defer self.release();
        return self.len;
    }
};

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
    /// Clients that have completed `connect`. Borrowed, not owned: see
    /// `AuthorizedClients` for why it is shared rather than held here.
    ///
    /// Without this the connect secret protected nothing. It was checked inside
    /// the `connect` branch and nowhere else, and nothing recorded who had
    /// passed it, so a client could skip `connect` entirely and send
    /// `sign_event` as its first message. That is not a narrow hole: the
    /// bunker's pubkey is published in the `bunker://` token the user hands
    /// out, in the single-key setup it IS the user's own pubkey, and the relays
    /// are in the same token. Everything needed to reach this signer is public
    /// by design, so who is asking has to be established here.
    clients: *AuthorizedClients,

    /// A single-key bunker where the communication and user keys are the same.
    pub fn initSingleKey(
        signer: keys.Signer,
        keypair: keys.KeyPair,
        policy: Policy,
        clients: *AuthorizedClients,
    ) Bunker {
        return .{ .signer = signer, .user = keypair, .remote = keypair, .policy = policy, .clients = clients };
    }

    /// Whether `client` has completed a `connect` with this bunker.
    pub fn isAuthorized(self: *const Bunker, client: [32]u8) bool {
        return self.clients.isAuthorized(client);
    }

    /// Records `client` as connected. Idempotent; drops the oldest when full.
    pub fn authorize(self: *Bunker, client: [32]u8) void {
        self.clients.authorize(client);
    }

    /// Forgets `client`, so its next request has to connect again.
    pub fn revoke(self: *Bunker, client: [32]u8) void {
        self.clients.revoke(client);
    }

    /// Whether a method may be answered for a client that has not connected.
    ///
    /// `connect` is how a client becomes authorized, `ping` is liveness and
    /// touches nothing, and `get_public_key` returns a value that is already
    /// public: it is in the `bunker://` token the user hands out. Everything
    /// else either uses the key or says what it is willing to do with it, and
    /// needs a client that got past the secret.
    fn openToStrangers(method: Method) bool {
        return switch (method) {
            .connect, .ping, .get_public_key => true,
            else => false,
        };
    }

    /// Answers a decrypted `request` from `client`, returning the response to
    /// seal back. Validation, unauthorized and denied requests become error
    /// responses; only allocation failures propagate as errors.
    ///
    /// `client` is the pubkey of the event that carried the request, which is
    /// the only identity a NIP-46 client has.
    pub fn handle(
        self: *Bunker,
        gpa: std.mem.Allocator,
        io: std.Io,
        request: Request,
        client: [32]u8,
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

        // Who is asking, before what they are asking for. A client that has not
        // connected is a stranger who read a public pubkey off a public relay.
        if (!openToStrangers(method) and !self.isAuthorized(client))
            return errorResponse(arena, id, "not connected");

        if (self.policy.decide(&request, client) == .reject)
            return errorResponse(arena, id, "request denied");

        switch (method) {
            .ping => return okResponse(arena, id, try a.dupe(u8, "pong")),
            .logout => {
                // Ending a session means ending it: the next request from this
                // client has to present the secret again.
                self.revoke(client);
                return okResponse(arena, id, try a.dupe(u8, "ack"));
            },
            .connect => {
                if (self.secret) |want| {
                    const got = if (request.params.len >= 2) request.params[1] else "";
                    if (!secretEql(want, got))
                        return errorResponse(arena, id, "invalid secret");
                }
                self.authorize(client);
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

/// Builds the event that accepts a `nostrconnect://` invitation: the signer's
/// answer to a client that advertised itself and is waiting to be adopted.
///
/// The part that is not guessable from the flow, and that every implementation
/// gets right only by being told: **the URI's `secret` is not the connect
/// method's secret, and the reply carries it as the RESULT, in place of
/// `"ack"`.** It is how the client knows the signer that answered is the one it
/// invited, and it is the whole security of this direction. nsec.app says so in
/// a comment where it fabricates the request ("this is not nip46 connect
/// method's 'secret' so we can't pass it using method params, instead we will
/// reply with this 'secret' instead of 'ack'"), and nostr-tools' client is the
/// other half: it subscribes for kind:24133 addressed to itself and adopts the
/// first event whose decrypted `result` equals the secret it published, taking
/// that event's author as the signer.
///
/// So the client is not waiting on an id it chose, and `request_id` is only for
/// its logs. The signer's own pubkey reaches the client as the event's author,
/// which is why this must be sealed by the key the signer will keep answering
/// with, not a throwaway.
///
/// Authorizing the client is the CALLER's job, and deliberately not done here:
/// this builds an event, and whether it is ever published is the caller's
/// decision. Publishing without authorizing leaves a client that believes it is
/// connected and is refused on its first real request.
pub fn acceptNostrConnect(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    remote: keys.KeyPair,
    uri: NostrConnectUri,
    request_id: []const u8,
    created_at: i64,
) Error!SealedEvent {
    const body = try (Response{ .id = request_id, .result = uri.secret }).toJson(gpa);
    defer gpa.free(body);
    return seal(gpa, io, signer, remote, uri.client_pubkey, body, created_at);
}

// ---------------------------------------------------------------------------
// Connection URIs (bunker:// and nostrconnect://)
// ---------------------------------------------------------------------------

/// A parsed `bunker://` token — a remote-signer-initiated connection.
pub const BunkerUri = struct {
    remote_signer_pubkey: [32]u8,
    relays: []const []const u8,
    secret: ?[]const u8,
};

/// A parsed `nostrconnect://` token — a client-initiated connection. `secret`
/// is required; the client MUST validate it against the connect response.
pub const NostrConnectUri = struct {
    client_pubkey: [32]u8,
    relays: []const []const u8,
    secret: []const u8,
    perms: ?[]const u8 = null,
    name: ?[]const u8 = null,
    url: ?[]const u8 = null,
    image: ?[]const u8 = null,
};

/// Options for `buildNostrConnectUri`.
pub const NostrConnectOptions = struct {
    relays: []const []const u8,
    secret: []const u8,
    perms: ?[]const u8 = null,
    name: ?[]const u8 = null,
    url: ?[]const u8 = null,
    image: ?[]const u8 = null,
};

/// A `BunkerUri` backed by an owned arena. Call `deinit`.
pub const ParsedBunkerUri = struct {
    arena: *std.heap.ArenaAllocator,
    value: BunkerUri,

    pub fn deinit(self: *ParsedBunkerUri) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// A `NostrConnectUri` backed by an owned arena. Call `deinit`.
pub const ParsedNostrConnectUri = struct {
    arena: *std.heap.ArenaAllocator,
    value: NostrConnectUri,

    pub fn deinit(self: *ParsedNostrConnectUri) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

const UriParts = struct {
    pubkey: [32]u8,
    relays: std.ArrayList([]const u8),
    secret: ?[]const u8,
    perms: ?[]const u8,
    name: ?[]const u8,
    url: ?[]const u8,
    image: ?[]const u8,
};

/// Splits `<scheme>://<pubkey-hex>?<query>` and percent-decodes the recognized
/// query parameters into `a`. Repeated `relay` keys accumulate; unknown keys
/// are ignored.
fn parseUriParts(a: std.mem.Allocator, s: []const u8, scheme: []const u8) Error!UriParts {
    if (!std.mem.startsWith(u8, s, scheme)) return Error.InvalidUri;
    const rest = s[scheme.len..];
    const q = std.mem.indexOfScalar(u8, rest, '?');
    const pubkey_hex = if (q) |i| rest[0..i] else rest;
    const query = if (q) |i| rest[i + 1 ..] else "";

    var parts: UriParts = .{
        .pubkey = hex.decodeFixed(32, pubkey_hex) catch return Error.InvalidUri,
        .relays = .empty,
        .secret = null,
        .perms = null,
        .name = null,
        .url = null,
        .image = null,
    };

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const raw = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "relay")) {
            try parts.relays.append(a, try percentDecode(a, raw));
        } else if (std.mem.eql(u8, key, "secret")) {
            parts.secret = try percentDecode(a, raw);
        } else if (std.mem.eql(u8, key, "perms")) {
            parts.perms = try percentDecode(a, raw);
        } else if (std.mem.eql(u8, key, "name")) {
            parts.name = try percentDecode(a, raw);
        } else if (std.mem.eql(u8, key, "url")) {
            parts.url = try percentDecode(a, raw);
        } else if (std.mem.eql(u8, key, "image")) {
            parts.image = try percentDecode(a, raw);
        }
    }
    return parts;
}

/// Parses a `bunker://<remote-signer-pubkey>?relay=...&secret=...` token.
pub fn parseBunkerUri(gpa: std.mem.Allocator, s: []const u8) Error!ParsedBunkerUri {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    var parts = try parseUriParts(a, s, "bunker://");
    return .{ .arena = arena, .value = .{
        .remote_signer_pubkey = parts.pubkey,
        .relays = try parts.relays.toOwnedSlice(a),
        .secret = parts.secret,
    } };
}

/// Parses a `nostrconnect://<client-pubkey>?relay=...&secret=...&...` token.
/// The `secret` query parameter is required.
pub fn parseNostrConnectUri(gpa: std.mem.Allocator, s: []const u8) Error!ParsedNostrConnectUri {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();
    var parts = try parseUriParts(a, s, "nostrconnect://");
    const secret = parts.secret orelse return Error.InvalidUri;
    return .{ .arena = arena, .value = .{
        .client_pubkey = parts.pubkey,
        .relays = try parts.relays.toOwnedSlice(a),
        .secret = secret,
        .perms = parts.perms,
        .name = parts.name,
        .url = parts.url,
        .image = parts.image,
    } };
}

/// Builds a `bunker://` token (owned by the caller).
pub fn buildBunkerUri(
    gpa: std.mem.Allocator,
    remote_signer_pubkey: [32]u8,
    relays: []const []const u8,
    secret: ?[]const u8,
) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "bunker://");
    try hex.appendHex(&out, gpa, &remote_signer_pubkey);
    var sep: u8 = '?';
    for (relays) |r| try appendUriParam(&out, gpa, &sep, "relay", r);
    if (secret) |sec| try appendUriParam(&out, gpa, &sep, "secret", sec);
    return out.toOwnedSlice(gpa);
}

/// Builds a `nostrconnect://` token (owned by the caller).
pub fn buildNostrConnectUri(
    gpa: std.mem.Allocator,
    client_pubkey: [32]u8,
    opts: NostrConnectOptions,
) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "nostrconnect://");
    try hex.appendHex(&out, gpa, &client_pubkey);
    var sep: u8 = '?';
    for (opts.relays) |r| try appendUriParam(&out, gpa, &sep, "relay", r);
    try appendUriParam(&out, gpa, &sep, "secret", opts.secret);
    if (opts.perms) |v| try appendUriParam(&out, gpa, &sep, "perms", v);
    if (opts.name) |v| try appendUriParam(&out, gpa, &sep, "name", v);
    if (opts.url) |v| try appendUriParam(&out, gpa, &sep, "url", v);
    if (opts.image) |v| try appendUriParam(&out, gpa, &sep, "image", v);
    return out.toOwnedSlice(gpa);
}

fn appendUriParam(
    out: *std.ArrayList(u8),
    gpa: std.mem.Allocator,
    sep: *u8,
    key: []const u8,
    value: []const u8,
) std.mem.Allocator.Error!void {
    try out.append(gpa, sep.*);
    sep.* = '&';
    try out.appendSlice(gpa, key);
    try out.append(gpa, '=');
    try appendPercentEncoded(out, gpa, value);
}

/// Percent-decodes a query value into `a` (`%XX` -> byte, `+` -> space).
fn percentDecode(a: std.mem.Allocator, s: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        switch (s[i]) {
            '%' => {
                if (i + 2 >= s.len) return Error.InvalidUri;
                const hi = std.fmt.charToDigit(s[i + 1], 16) catch return Error.InvalidUri;
                const lo = std.fmt.charToDigit(s[i + 2], 16) catch return Error.InvalidUri;
                try out.append(a, (@as(u8, hi) << 4) | lo);
                i += 2;
            },
            '+' => try out.append(a, ' '),
            else => try out.append(a, s[i]),
        }
    }
    return out.toOwnedSlice(a);
}

/// Percent-encodes `s` into `out` (RFC 3986 unreserved bytes pass through).
fn appendPercentEncoded(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) std.mem.Allocator.Error!void {
    const upper = "0123456789ABCDEF";
    for (s) |c| {
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => try out.append(gpa, c),
            else => {
                try out.append(gpa, '%');
                try out.append(gpa, upper[c >> 4]);
                try out.append(gpa, upper[c & 0x0f]);
            },
        }
    }
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
fn connectFirst(gpa: std.mem.Allocator, p: *TestParties, bunker: *Bunker) !void {
    var resp = try exchange(gpa, p, bunker, .{ .id = "c0", .method = "connect", .params = &.{} });
    defer resp.deinit();
    try testing.expectEqualStrings("ack", resp.value.result);
}

fn exchange(gpa: std.mem.Allocator, p: *TestParties, bunker: *Bunker, req: Request) !ParsedResponse {
    const req_json = try req.toJson(gpa);
    defer gpa.free(req_json);

    var req_event = try seal(gpa, testing.io, p.signer, p.client, bunker.remote.public_key, req_json, 1700000000);
    defer req_event.deinit();

    const opened = try open(gpa, p.signer, bunker.remote.secret_key, req_event.event);
    defer gpa.free(opened);
    var parsed_req = try parseRequest(gpa, opened);
    defer parsed_req.deinit();

    var resp = try bunker.handle(gpa, testing.io, parsed_req.value, req_event.event.pubkey);
    defer resp.deinit();
    const resp_json = try resp.value.toJson(gpa);
    defer gpa.free(resp_json);

    var resp_event = try seal(gpa, testing.io, p.signer, bunker.remote, p.client.public_key, resp_json, 1700000001);
    defer resp_event.deinit();

    const opened_resp = try open(gpa, p.signer, p.client.secret_key, resp_event.event);
    defer gpa.free(opened_resp);
    return parseResponse(gpa, opened_resp);
}

test "a client that never connected gets nothing signed" {
    // The connect secret used to be checked inside the connect branch and
    // nowhere else, and nothing recorded who had passed it. So a client could
    // skip connect entirely and send sign_event as its first message, and the
    // signer would answer. That is not a narrow hole: the bunker's pubkey is
    // published in the `bunker://` token the user hands out, in the single-key
    // setup it IS the user's own pubkey, and the relays are in the same token.
    // Everything needed to reach this signer is public by design.
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    var bunker_clients: AuthorizedClients = .{};
    var bunker = Bunker.initSingleKey(p.signer, p.user, approveAll(), &bunker_clients);
    bunker.secret = "hunter2";

    const template = "{\"kind\":1,\"content\":\"not yours to sign\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};

    // Straight to sign_event, no connect. This is the whole attack.
    {
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "a", .method = "sign_event", .params = &params });
        defer resp.deinit();
        try testing.expectEqualStrings("not connected", resp.value.err);
        try testing.expectEqualStrings("", resp.value.result);
    }
    // Decryption is a key operation too, and it is how a private list or a
    // gift-wrapped message would be read out of the user's account.
    {
        const args = [_][]const u8{ "aa" ** 32, "whatever" };
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "b", .method = "nip44_decrypt", .params = &args });
        defer resp.deinit();
        try testing.expectEqualStrings("not connected", resp.value.err);
    }
    // A wrong secret does not get you in, and does not leave you half in.
    {
        const wrong = [_][]const u8{ "aa" ** 32, "hunter3" };
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "c", .method = "connect", .params = &wrong });
        defer resp.deinit();
        try testing.expectEqualStrings("invalid secret", resp.value.err);
    }
    {
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "d", .method = "sign_event", .params = &params });
        defer resp.deinit();
        try testing.expectEqualStrings("not connected", resp.value.err);
    }

    // The right secret does, and then the same request works. A guard that also
    // blocks the legitimate client is not a fix.
    {
        const right = [_][]const u8{ "aa" ** 32, "hunter2" };
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "e", .method = "connect", .params = &right });
        defer resp.deinit();
        try testing.expectEqualStrings("ack", resp.value.result);
    }
    {
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "f", .method = "sign_event", .params = &params });
        defer resp.deinit();
        try testing.expectEqualStrings("", resp.value.err);
        try testing.expect(resp.value.result.len > 0);
    }

    // And logout means it: the next request presents the secret again.
    {
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "g", .method = "logout", .params = &.{} });
        defer resp.deinit();
        try testing.expectEqualStrings("ack", resp.value.result);
    }
    {
        var resp = try exchange(gpa, &p, &bunker, .{ .id = "h", .method = "sign_event", .params = &params });
        defer resp.deinit();
        try testing.expectEqualStrings("not connected", resp.value.err);
    }
}

test "a bunker remembers several clients and forgets the oldest" {
    var signer_ctx = keys.Signer.init();
    defer signer_ctx.deinit();
    const kp = try signer_ctx.keyPairFromSecretKey([_]u8{0x77} ** 32);
    var bunker_clients: AuthorizedClients = .{};
    var bunker = Bunker.initSingleKey(signer_ctx, kp, approveAll(), &bunker_clients);

    // A person runs a handful of clients at once, so one must not evict another.
    var first: [32]u8 = undefined;
    for (0..max_authorized_clients) |i| {
        var client = [_]u8{0} ** 32;
        client[0] = @intCast(i + 1);
        if (i == 0) first = client;
        bunker.authorize(client);
        try testing.expect(bunker.isAuthorized(client));
    }
    try testing.expect(bunker.isAuthorized(first));

    // Full. The OLDEST goes: a dropped client reconnects, which is one round
    // trip, where evicting the newest would lock out the client that just
    // arrived and would loop.
    const newcomer = [_]u8{0xfe} ** 32;
    bunker.authorize(newcomer);
    try testing.expect(bunker.isAuthorized(newcomer));
    try testing.expect(!bunker.isAuthorized(first));
    var second = [_]u8{0} ** 32;
    second[0] = 2;
    try testing.expect(bunker.isAuthorized(second));

    // Connecting twice is not two entries, or sixteen reconnects would evict
    // every other client the user has.
    const before = bunker.clients.count();
    bunker.authorize(newcomer);
    try testing.expectEqual(before, bunker.clients.count());

    bunker.revoke(newcomer);
    try testing.expect(!bunker.isAuthorized(newcomer));
    try testing.expect(bunker.isAuthorized(second));
}

test "NIP-46 bunker signs an event end to end" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    var bunker_clients: AuthorizedClients = .{};
    var bunker = Bunker.initSingleKey(p.signer, p.user, approveAll(), &bunker_clients);
    try connectFirst(gpa, &p, &bunker);

    const template = "{\"kind\":1,\"content\":\"hello remote\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};
    const req = Request{ .id = "sign1", .method = "sign_event", .params = &params };

    var resp = try exchange(gpa, &p, &bunker, req);
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
    var bunker_clients: AuthorizedClients = .{};
    var bunker = Bunker.initSingleKey(p.signer, p.user, approveAll(), &bunker_clients);

    {
        const req = Request{ .id = "gp", .method = "get_public_key", .params = &.{} };
        var resp = try exchange(gpa, &p, &bunker, req);
        defer resp.deinit();
        const want = try hex.encode(gpa, &p.user.public_key);
        defer gpa.free(want);
        try testing.expectEqualStrings(want, resp.value.result);
    }
    {
        const req = Request{ .id = "pg", .method = "ping", .params = &.{} };
        var resp = try exchange(gpa, &p, &bunker, req);
        defer resp.deinit();
        try testing.expectEqualStrings("pong", resp.value.result);
    }
}

test "NIP-46 bunker nip44 encrypt then decrypt round trips" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();
    var bunker_clients: AuthorizedClients = .{};
    var bunker = Bunker.initSingleKey(p.signer, p.user, approveAll(), &bunker_clients);
    try connectFirst(gpa, &p, &bunker);

    // A third party the user is messaging.
    const third = try p.signer.generateKeyPair(testing.io);
    const third_hex = try hex.encode(gpa, &third.public_key);
    defer gpa.free(third_hex);

    const enc_params = [_][]const u8{ third_hex, "secret note" };
    const enc_req = Request{ .id = "e", .method = "nip44_encrypt", .params = &enc_params };
    var enc_resp = try exchange(gpa, &p, &bunker, enc_req);
    defer enc_resp.deinit();
    try testing.expectEqualStrings("", enc_resp.value.err);

    // The user can decrypt its own ciphertext back to the plaintext.
    const dec_params = [_][]const u8{ third_hex, enc_resp.value.result };
    const dec_req = Request{ .id = "d", .method = "nip44_decrypt", .params = &dec_params };
    var dec_resp = try exchange(gpa, &p, &bunker, dec_req);
    defer dec_resp.deinit();
    try testing.expectEqualStrings("secret note", dec_resp.value.result);
}

test "NIP-46 bunker rejects denied and unknown requests" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();

    const reject = struct {
        fn f(_: ?*anyopaque, _: *const Request, _: [32]u8) Decision {
            return .reject;
        }
    }.f;
    var bunker_clients: AuthorizedClients = .{};
    var bunker = Bunker.initSingleKey(p.signer, p.user, .{ .decideFn = &reject }, &bunker_clients);

    const req = Request{ .id = "z", .method = "get_public_key", .params = &.{} };
    var resp = try exchange(gpa, &p, &bunker, req);
    defer resp.deinit();
    try testing.expectEqualStrings("request denied", resp.value.err);
    try testing.expectEqualStrings("", resp.value.result);

    // Unknown methods are rejected even under an approve-all policy.
    var open_bunker_clients: AuthorizedClients = .{};
    var open_bunker = Bunker.initSingleKey(p.signer, p.user, approveAll(), &open_bunker_clients);
    const unknown = Request{ .id = "u", .method = "nip04_encrypt", .params = &.{} };
    var uresp = try exchange(gpa, &p, &open_bunker, unknown);
    defer uresp.deinit();
    try testing.expectEqualStrings("unsupported method", uresp.value.err);
}

test "NIP-46 connect validates an optional secret" {
    const gpa = testing.allocator;
    var p = try TestParties.init();
    defer p.deinit();

    var bunker_clients: AuthorizedClients = .{};

    var bunker = Bunker.initSingleKey(p.signer, p.user, approveAll(), &bunker_clients);
    bunker.secret = "hunter2";

    const remote_hex = try hex.encode(gpa, &p.user.public_key);
    defer gpa.free(remote_hex);

    {
        const good = [_][]const u8{ remote_hex, "hunter2" };
        const req = Request{ .id = "c1", .method = "connect", .params = &good };
        var resp = try exchange(gpa, &p, &bunker, req);
        defer resp.deinit();
        try testing.expectEqualStrings("ack", resp.value.result);
    }
    {
        const bad = [_][]const u8{ remote_hex, "wrong" };
        const req = Request{ .id = "c2", .method = "connect", .params = &bad };
        var resp = try exchange(gpa, &p, &bunker, req);
        defer resp.deinit();
        try testing.expectEqualStrings("invalid secret", resp.value.err);
    }
}

test "NIP-46 parses the spec nostrconnect example" {
    const gpa = testing.allocator;
    const uri = "nostrconnect://83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5" ++
        "?relay=wss%3A%2F%2Frelay1.example.com" ++
        "&perms=nip44_encrypt%2Cnip44_decrypt%2Csign_event%3A13%2Csign_event%3A14%2Csign_event%3A1059" ++
        "&name=My+Client&secret=0s8j2djs&relay=wss%3A%2F%2Frelay2.example2.com";
    var parsed = try parseNostrConnectUri(gpa, uri);
    defer parsed.deinit();

    const want_pk = try hex.decodeFixed(32, "83f3b2ae6aa368e8275397b9c26cf550101d63ebaab900d19dd4a4429f5ad8f5");
    try testing.expectEqualSlices(u8, &want_pk, &parsed.value.client_pubkey);
    try testing.expectEqual(@as(usize, 2), parsed.value.relays.len);
    try testing.expectEqualStrings("wss://relay1.example.com", parsed.value.relays[0]);
    try testing.expectEqualStrings("wss://relay2.example2.com", parsed.value.relays[1]);
    try testing.expectEqualStrings("0s8j2djs", parsed.value.secret);
    try testing.expectEqualStrings("My Client", parsed.value.name.?);
    try testing.expectEqualStrings(
        "nip44_encrypt,nip44_decrypt,sign_event:13,sign_event:14,sign_event:1059",
        parsed.value.perms.?,
    );
}

test "NIP-46 parses a bunker uri with an unencoded relay" {
    const gpa = testing.allocator;
    const uri = "bunker://" ++ ("ab" ** 32) ++ "?relay=wss://relay.example.com&secret=xyz789";
    var parsed = try parseBunkerUri(gpa, uri);
    defer parsed.deinit();
    try testing.expectEqualSlices(u8, &([_]u8{0xab} ** 32), &parsed.value.remote_signer_pubkey);
    try testing.expectEqual(@as(usize, 1), parsed.value.relays.len);
    try testing.expectEqualStrings("wss://relay.example.com", parsed.value.relays[0]);
    try testing.expectEqualStrings("xyz789", parsed.value.secret.?);
}

test "NIP-46 bunker uri build/parse round trip" {
    const gpa = testing.allocator;
    const remote = [_]u8{0x2c} ** 32;
    const relays = [_][]const u8{ "wss://relay.one", "wss://relay.two" };
    const uri = try buildBunkerUri(gpa, remote, &relays, "s3cr3t");
    defer gpa.free(uri);
    // Relay URLs are percent-encoded in the output.
    try testing.expect(std.mem.indexOf(u8, uri, "wss%3A%2F%2Frelay.one") != null);

    var parsed = try parseBunkerUri(gpa, uri);
    defer parsed.deinit();
    try testing.expectEqualSlices(u8, &remote, &parsed.value.remote_signer_pubkey);
    try testing.expectEqual(@as(usize, 2), parsed.value.relays.len);
    try testing.expectEqualStrings("wss://relay.one", parsed.value.relays[0]);
    try testing.expectEqualStrings("wss://relay.two", parsed.value.relays[1]);
    try testing.expectEqualStrings("s3cr3t", parsed.value.secret.?);
}

test "NIP-46 nostrconnect uri build/parse round trip" {
    const gpa = testing.allocator;
    const client = [_]u8{0x5f} ** 32;
    const relays = [_][]const u8{"wss://relay.example.com"};
    const uri = try buildNostrConnectUri(gpa, client, .{
        .relays = &relays,
        .secret = "abc",
        .perms = "sign_event:1,nip44_encrypt",
        .name = "My Client",
    });
    defer gpa.free(uri);

    var parsed = try parseNostrConnectUri(gpa, uri);
    defer parsed.deinit();
    try testing.expectEqualSlices(u8, &client, &parsed.value.client_pubkey);
    try testing.expectEqualStrings("wss://relay.example.com", parsed.value.relays[0]);
    try testing.expectEqualStrings("abc", parsed.value.secret);
    try testing.expectEqualStrings("sign_event:1,nip44_encrypt", parsed.value.perms.?);
    try testing.expectEqualStrings("My Client", parsed.value.name.?);
    try testing.expectEqual(@as(?[]const u8, null), parsed.value.url);
}

test "NIP-46 uri parsing rejects bad input" {
    const gpa = testing.allocator;
    // Wrong scheme.
    try testing.expectError(Error.InvalidUri, parseBunkerUri(gpa, "https://example.com"));
    // Pubkey is not 64 hex chars.
    try testing.expectError(Error.InvalidUri, parseBunkerUri(gpa, "bunker://deadbeef?relay=wss://r"));
    // nostrconnect without the required secret.
    try testing.expectError(
        Error.InvalidUri,
        parseNostrConnectUri(gpa, "nostrconnect://" ++ ("ab" ** 32) ++ "?relay=wss://r"),
    );
}

test "PolicyConfig default approves every supported request" {
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const p = cfg.policy();

    const gpk = Request{ .id = "1", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(Decision.approve, p.decide(&gpk, [_]u8{0} ** 32));

    const tmpl = "{\"kind\":4,\"content\":\"x\",\"tags\":[],\"created_at\":1}";
    const se = Request{ .id = "2", .method = "sign_event", .params = &[_][]const u8{tmpl} };
    try testing.expectEqual(Decision.approve, p.decide(&se, [_]u8{0} ** 32));
}

test "PolicyConfig method allowlist blocks a key-touching method but never connect/ping" {
    const allowed = [_]Method{ .get_public_key, .sign_event };
    var cfg = PolicyConfig{ .gpa = testing.allocator, .allowed_methods = &allowed };
    const p = cfg.policy();

    // A sign-only bunker refuses nip44_decrypt so a client can't read the
    // user's DMs through it.
    const dec = Request{ .id = "1", .method = "nip44_decrypt", .params = &[_][]const u8{ "aa", "bb" } };
    try testing.expectEqual(Decision.reject, p.decide(&dec, [_]u8{0} ** 32));

    // connect/ping are always allowed even though they're not listed.
    const con = Request{ .id = "2", .method = "connect", .params = &.{} };
    try testing.expectEqual(Decision.approve, p.decide(&con, [_]u8{0} ** 32));
    const png = Request{ .id = "3", .method = "ping", .params = &.{} };
    try testing.expectEqual(Decision.approve, p.decide(&png, [_]u8{0} ** 32));

    // A listed method still passes.
    const gpk = Request{ .id = "4", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(Decision.approve, p.decide(&gpk, [_]u8{0} ** 32));
}

test "PolicyConfig kind allowlist gates sign_event by event kind, failing closed" {
    const kinds = [_]u16{1};
    var cfg = PolicyConfig{ .gpa = testing.allocator, .allowed_kinds = &kinds };
    const p = cfg.policy();

    const note = "{\"kind\":1,\"content\":\"gm\",\"tags\":[],\"created_at\":1}";
    const ok = Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{note} };
    try testing.expectEqual(Decision.approve, p.decide(&ok, [_]u8{0} ** 32));

    const del = "{\"kind\":5,\"content\":\"\",\"tags\":[],\"created_at\":1}";
    const no = Request{ .id = "2", .method = "sign_event", .params = &[_][]const u8{del} };
    try testing.expectEqual(Decision.reject, p.decide(&no, [_]u8{0} ** 32));

    // Unparseable template → deny.
    const junk = Request{ .id = "3", .method = "sign_event", .params = &[_][]const u8{"not json"} };
    try testing.expectEqual(Decision.reject, p.decide(&junk, [_]u8{0} ** 32));

    // A kind restriction doesn't affect non-signing methods.
    const gpk = Request{ .id = "4", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(Decision.approve, p.decide(&gpk, [_]u8{0} ** 32));
}

test "PolicyConfig rejects an unknown method" {
    var cfg = PolicyConfig{ .gpa = testing.allocator };
    const p = cfg.policy();
    const bogus = Request{ .id = "1", .method = "delete_everything", .params = &.{} };
    try testing.expectEqual(Decision.reject, p.decide(&bogus, [_]u8{0} ** 32));
}

test "a client that connected on one relay is known on the others" {
    // What a signer on more than one relay is. Each relay runs its own thread
    // with its own Bunker, because each needs its own secp256k1 context, and
    // they share one record of who has connected.
    //
    // Without the sharing, a client that connects over one relay and whose next
    // request happens to arrive on another is told "not connected". Which relay
    // gets there first is nobody's choice: everything needed to reach the signer
    // is in the token, so a client publishes to every relay in it.
    var p = try TestParties.init();
    defer p.deinit();

    var shared: AuthorizedClients = .{};
    var relay_a = Bunker.initSingleKey(p.signer, p.user, approveAll(), &shared);
    var relay_b = Bunker.initSingleKey(p.signer, p.user, approveAll(), &shared);

    const client = [_]u8{0x31} ** 32;
    try testing.expect(!relay_a.isAuthorized(client));
    try testing.expect(!relay_b.isAuthorized(client));

    // Connects over A.
    relay_a.authorize(client);
    try testing.expect(relay_a.isAuthorized(client));
    // And is known on B, which is the whole point.
    try testing.expect(relay_b.isAuthorized(client));

    // Signing out on one relay signs out on all of them, for the same reason:
    // a session that survives on another relay is a revocation that did not
    // revoke anything.
    relay_b.revoke(client);
    try testing.expect(!relay_a.isAuthorized(client));
    try testing.expect(!relay_b.isAuthorized(client));
}

test "clearing the set ends every session, on every relay" {
    // What signing out of the signer itself has to do. A client still holding an
    // authorization granted against a key that is no longer loaded is a session
    // outliving the account it belonged to.
    var shared: AuthorizedClients = .{};
    for (0..4) |i| {
        var id = [_]u8{0} ** 32;
        id[0] = @intCast(i);
        shared.authorize(id);
    }
    try testing.expectEqual(@as(usize, 4), shared.count());

    shared.clear();
    try testing.expectEqual(@as(usize, 0), shared.count());
    for (0..4) |i| {
        var id = [_]u8{0} ** 32;
        id[0] = @intCast(i);
        try testing.expect(!shared.isAuthorized(id));
    }
}

test "two relay threads authorizing at once do not lose a client" {
    // The set is reached from every relay thread. `authorize` scans for a
    // duplicate and then appends, and without the lock covering both, two
    // threads can pass the scan and write the same slot, or write past it.
    const rounds = 200;
    const racers = 4;

    for (0..rounds) |round| {
        var shared: AuthorizedClients = .{};
        var gate = std.atomic.Value(bool).init(false);

        const Racer = struct {
            fn run(set: *AuthorizedClients, key: [32]u8, g: *std.atomic.Value(bool)) void {
                while (!g.load(.acquire)) {}
                set.authorize(key);
            }
        };

        var id = [_]u8{0} ** 32;
        id[0] = @intCast(round % 256);
        var threads: [racers]std.Thread = undefined;
        for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Racer.run, .{ &shared, id, &gate });
        gate.store(true, .release);
        for (threads) |t| t.join();

        // One client connected, however many threads said so.
        try testing.expectEqual(@as(usize, 1), shared.count());
        try testing.expect(shared.isAuthorized(id));
    }
}

test "accepting a nostrconnect invitation replies with the secret, not ack" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var signer = keys.Signer.init();
    defer signer.deinit();
    const remote = try signer.keyPairFromSecretKey([_]u8{0x21} ** 32);
    const client = try signer.keyPairFromSecretKey([_]u8{0x22} ** 32);

    var client_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&client_hex, "{x}", .{client.public_key});
    const uri_text = try std.fmt.allocPrint(
        gpa,
        "nostrconnect://{s}?relay=wss%3A%2F%2Fr.example&secret=hunter2&name=Coracle",
        .{client_hex},
    );
    defer gpa.free(uri_text);

    var parsed = try parseNostrConnectUri(gpa, uri_text);
    defer parsed.deinit();

    var sealed = try acceptNostrConnect(gpa, io, signer, remote, parsed.value, "req-1", 1_800_000_000);
    defer sealed.deinit();

    // Addressed to the client, and authored by the key the signer keeps
    // answering with: that author is how the client learns who its signer is.
    try std.testing.expectEqualSlices(u8, &remote.public_key, &sealed.event.pubkey);
    try std.testing.expectEqual(@as(u16, kind), sealed.event.kind);

    // The client decrypts with its own key and checks the RESULT against the
    // secret it published. "ack" here would be silently ignored by every
    // client, and the connection would simply never complete.
    const plain = try nip44.decrypt(gpa, signer, client.secret_key, remote.public_key, sealed.event.content);
    defer gpa.free(plain);
    const response = try std.json.parseFromSlice(struct {
        id: []const u8,
        result: []const u8,
    }, gpa, plain, .{ .ignore_unknown_fields = true });
    defer response.deinit();
    try std.testing.expectEqualStrings("hunter2", response.value.result);
    try std.testing.expect(!std.mem.eql(u8, "ack", response.value.result));
}

test "a nostrconnect secret with JSON in it survives the round trip" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var signer = keys.Signer.init();
    defer signer.deinit();
    const remote = try signer.keyPairFromSecretKey([_]u8{0x23} ** 32);
    const client = try signer.keyPairFromSecretKey([_]u8{0x24} ** 32);

    // The secret is a stranger's string copied out of a URI, so it reaches the
    // response builder unvetted. Escaping it is why this belongs in the library
    // rather than being a format string at each call site.
    var client_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&client_hex, "{x}", .{client.public_key});
    const uri_text = try std.fmt.allocPrint(
        gpa,
        "nostrconnect://{s}?relay=wss%3A%2F%2Fr.example&secret=a%22b%5C%22%2C%22result%22%3A%22ack",
        .{client_hex},
    );
    defer gpa.free(uri_text);

    var parsed = try parseNostrConnectUri(gpa, uri_text);
    defer parsed.deinit();
    var sealed = try acceptNostrConnect(gpa, io, signer, remote, parsed.value, "req-2", 1_800_000_000);
    defer sealed.deinit();

    const plain = try nip44.decrypt(gpa, signer, client.secret_key, remote.public_key, sealed.event.content);
    defer gpa.free(plain);
    const response = try std.json.parseFromSlice(struct {
        id: []const u8,
        result: []const u8,
    }, gpa, plain, .{ .ignore_unknown_fields = true });
    defer response.deinit();
    // One field, holding the whole thing, rather than a smuggled second key.
    try std.testing.expectEqualStrings(parsed.value.secret, response.value.result);
}
