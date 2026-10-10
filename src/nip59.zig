//! NIP-59 gift wrap and NIP-17 private direct messages.
//!
//! A message travels in three layers:
//!
//!   - rumor: the real event, with its id computed but no signature, so a
//!     leaked rumor proves nothing about who wrote it.
//!   - seal (kind 13): the rumor's JSON, NIP-44 encrypted from the author to
//!     the recipient and signed by the author. Its tags are empty, so it names
//!     the author and nothing else.
//!   - gift wrap (kind 1059): the seal's JSON, NIP-44 encrypted from a fresh
//!     one-time key to the recipient, signed by that key and `p`-tagged to the
//!     recipient so relays can route it.
//!
//! The seal and wrap timestamps are moved a random amount up to two days into
//! the past, so neither layer gives away when the message was written. Only
//! the rumor carries the real time.
//!
//! Authorship rests on the seal alone: the wrap is signed by a throwaway key
//! and the rumor is not signed at all. So `unwrap` checks the seal's signature
//! and refuses a rumor whose `pubkey` is not the seal's signer. Without that
//! check anyone could seal a rumor bearing someone else's pubkey and have it
//! shown as theirs.

const std = @import("std");
const event = @import("event.zig");
const hex = @import("hex.zig");
const json = @import("json.zig");
const keys = @import("keys.zig");
const nip44 = @import("nip44.zig");

pub const seal_kind: u16 = 13;
pub const gift_wrap_kind: u16 = 1059;
/// The ephemeral gift wrap. Same structure as kind 1059; relays do not store
/// it. `unwrap` accepts both.
pub const ephemeral_gift_wrap_kind: u16 = 21059;
/// NIP-17 chat message.
pub const direct_message_kind: u16 = 14;

/// The widest a seal or wrap timestamp is moved into the past, in seconds.
pub const max_timestamp_tweak: i64 = 2 * 24 * 60 * 60;

pub const Error = error{
    /// The outer event is not a gift wrap, or the inner one is not a seal.
    WrongKind,
    /// The gift wrap's id or signature does not check out.
    InvalidWrapSignature,
    /// The seal's id or signature does not check out.
    InvalidSealSignature,
    /// The decrypted seal is not a well-formed event.
    InvalidSeal,
    /// The decrypted rumor is not a well-formed unsigned event.
    InvalidRumor,
    /// The rumor's id is not the hash of its own fields.
    RumorIdMismatch,
    /// The rumor claims an author other than the key that signed the seal.
    SenderMismatch,
    /// A direct message was given no recipients.
    NoRecipients,
    /// The randomness source failed.
    RandomFailed,
} || nip44.Error || keys.Error || std.mem.Allocator.Error;

/// An unsigned event. `id` is the NIP-01 hash of the other fields.
pub const Rumor = struct {
    id: [32]u8,
    pubkey: keys.PublicKey,
    created_at: i64,
    kind: u16,
    tags: []const event.Tag,
    content: []const u8,

    /// Builds a rumor and computes its id. `tags` and `content` are borrowed.
    pub fn init(
        allocator: std.mem.Allocator,
        pubkey: keys.PublicKey,
        created_at: i64,
        kind: u16,
        tags: []const event.Tag,
        content: []const u8,
    ) std.mem.Allocator.Error!Rumor {
        return .{
            .id = try event.computeId(allocator, pubkey, created_at, kind, tags, content),
            .pubkey = pubkey,
            .created_at = created_at,
            .kind = kind,
            .tags = tags,
            .content = content,
        };
    }

    /// Whether `id` is the hash of the rumor's own fields.
    pub fn idMatches(self: Rumor, allocator: std.mem.Allocator) std.mem.Allocator.Error!bool {
        const computed = try event.computeId(allocator, self.pubkey, self.created_at, self.kind, self.tags, self.content);
        return std.mem.eql(u8, &computed, &self.id);
    }
};

/// Serializes a rumor to JSON: the event wire format with no `sig` field.
pub fn rumorToJson(allocator: std.mem.Allocator, rumor: Rumor) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);

    try list.appendSlice(allocator, "{\"id\":\"");
    try hex.appendHex(&list, allocator, &rumor.id);
    try list.appendSlice(allocator, "\",\"pubkey\":\"");
    try hex.appendHex(&list, allocator, &rumor.pubkey);
    try list.print(allocator, "\",\"created_at\":{d},\"kind\":{d},\"tags\":[", .{ rumor.created_at, rumor.kind });
    for (rumor.tags, 0..) |tag, ti| {
        if (ti != 0) try list.append(allocator, ',');
        try list.append(allocator, '[');
        for (tag, 0..) |field, fi| {
            if (fi != 0) try list.append(allocator, ',');
            try json.appendString(&list, allocator, field);
        }
        try list.append(allocator, ']');
    }
    try list.appendSlice(allocator, "],\"content\":");
    try json.appendString(&list, allocator, rumor.content);
    try list.append(allocator, '}');

    return list.toOwnedSlice(allocator);
}

/// A signed event (a seal or a gift wrap) and the arena that backs its tags
/// and content. Call `deinit` to free it.
pub const Owned = struct {
    arena: *std.heap.ArenaAllocator,
    event: event.Event,

    pub fn deinit(self: *Owned) void {
        freeArena(self.arena);
    }
};

/// Seals `rumor` from `sender` to `recipient`: a kind 13 event with empty
/// tags whose content is the NIP-44 encryption of the rumor's JSON, signed by
/// `sender`, dated a random time up to two days in the past.
///
/// Refuses a rumor whose pubkey is not `sender` (the recipient would reject
/// it) or whose id does not match its fields.
pub fn seal(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    sender: keys.KeyPair,
    recipient: keys.PublicKey,
    rumor: Rumor,
) Error!Owned {
    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const ev = try sealLeaky(arena.allocator(), io, signer, sender, recipient, rumor);
    return .{ .arena = arena, .event = ev };
}

/// Gift-wraps `seal_event` to `recipient`: a kind 1059 event signed by a
/// fresh one-time key, tagged `["p", recipient]` followed by `extra_tags`,
/// whose content is the NIP-44 encryption of the seal's JSON, dated a random
/// time up to two days in the past. The one-time secret key is wiped before
/// returning and never used again.
pub fn wrap(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    seal_event: event.Event,
    recipient: keys.PublicKey,
    extra_tags: []const event.Tag,
) Error!Owned {
    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const ev = try wrapLeaky(arena.allocator(), io, signer, seal_event, recipient, extra_tags);
    return .{ .arena = arena, .event = ev };
}

/// The rumor inside a gift wrap and the author proven by its seal. Call
/// `deinit` to free it.
pub const Unwrapped = struct {
    arena: *std.heap.ArenaAllocator,
    rumor: Rumor,
    /// The seal's signer, which the rumor's pubkey has been checked against.
    sender: keys.PublicKey,

    pub fn deinit(self: *Unwrapped) void {
        freeArena(self.arena);
    }
};

/// Opens a gift wrap addressed to `recipient_sk`. In order, it checks:
///
///   1. the wrap is kind 1059 (or 21059), and its id and signature verify;
///   2. its content decrypts (NIP-44, MAC checked) to a well-formed event;
///   3. that event is kind 13, and its id and signature verify;
///   4. the seal's content decrypts to a well-formed unsigned event;
///   5. the rumor's id is the hash of its fields;
///   6. the rumor's pubkey is the seal's signer.
///
/// Any failure returns an error and nothing from inside the wrap.
pub fn unwrap(
    gpa: std.mem.Allocator,
    signer: keys.Signer,
    recipient_sk: keys.SecretKey,
    wrap_event: event.Event,
) Error!Unwrapped {
    if (wrap_event.kind != gift_wrap_kind and wrap_event.kind != ephemeral_gift_wrap_kind) return Error.WrongKind;
    if (!try event.verify(gpa, signer, wrap_event)) return Error.InvalidWrapSignature;

    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const a = arena.allocator();

    const seal_json = try nip44.decrypt(a, signer, recipient_sk, wrap_event.pubkey, wrap_event.content);
    const seal_value = std.json.parseFromSliceLeaky(std.json.Value, a, seal_json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidSeal,
    };
    const seal_event = event.fromValueLeaky(a, seal_value) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidSeal,
    };
    if (seal_event.kind != seal_kind) return Error.WrongKind;
    if (!try event.verify(a, signer, seal_event)) return Error.InvalidSealSignature;

    const rumor_json = try nip44.decrypt(a, signer, recipient_sk, seal_event.pubkey, seal_event.content);
    const rumor = try parseRumorLeaky(a, rumor_json);
    if (!try rumor.idMatches(a)) return Error.RumorIdMismatch;
    if (!std.mem.eql(u8, &rumor.pubkey, &seal_event.pubkey)) return Error.SenderMismatch;

    return .{ .arena = arena, .rumor = rumor, .sender = seal_event.pubkey };
}

/// A NIP-17 message: the kind 14 rumor and one gift wrap per distinct
/// recipient, plus one to the sender so their other clients can show what
/// they sent. Publish each wrap to its `p`-tagged pubkey's inbox relays.
/// Call `deinit` to free it.
pub const DirectMessage = struct {
    arena: *std.heap.ArenaAllocator,
    rumor: Rumor,
    wraps: []const event.Event,

    pub fn deinit(self: *DirectMessage) void {
        freeArena(self.arena);
    }
};

/// Builds a NIP-17 chat message from `sender` to `recipients`: a kind 14
/// rumor dated now, with one `p` tag per distinct recipient, an `e` tag for
/// `reply_to` and a `subject` tag when given, then sealed and wrapped
/// separately for each recipient and for the sender. Each wrap has its own
/// one-time key. A recipient listed twice gets one tag and one wrap; a sender
/// listed as a recipient is not wrapped to twice.
pub fn privateDirectMessage(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    sender: keys.KeyPair,
    recipients: []const keys.PublicKey,
    content: []const u8,
    reply_to: ?[32]u8,
    subject: ?[]const u8,
) Error!DirectMessage {
    if (recipients.len == 0) return Error.NoRecipients;

    const arena = try newArena(gpa);
    errdefer freeArena(arena);
    const a = arena.allocator();

    var distinct: std.ArrayList(keys.PublicKey) = .empty;
    for (recipients) |pk| {
        if (!contains(distinct.items, pk)) try distinct.append(a, pk);
    }

    var tags: std.ArrayList(event.Tag) = .empty;
    for (distinct.items) |pk| try tags.append(a, try tag2(a, "p", &pk));
    if (reply_to) |id| try tags.append(a, try tag2(a, "e", &id));
    if (subject) |s| {
        const fields = try a.alloc([]const u8, 2);
        fields[0] = "subject";
        fields[1] = try a.dupe(u8, s);
        try tags.append(a, fields);
    }

    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    const rumor = try Rumor.init(a, sender.public_key, now, direct_message_kind, tags.items, try a.dupe(u8, content));

    var targets = distinct;
    if (!contains(targets.items, sender.public_key)) try targets.append(a, sender.public_key);

    const wraps = try a.alloc(event.Event, targets.items.len);
    for (targets.items, wraps) |pk, *out| {
        const sealed = try sealLeaky(a, io, signer, sender, pk, rumor);
        out.* = try wrapLeaky(a, io, signer, sealed, pk, &.{});
    }

    return .{ .arena = arena, .rumor = rumor, .wraps = wraps };
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn newArena(gpa: std.mem.Allocator) std.mem.Allocator.Error!*std.heap.ArenaAllocator {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    return arena;
}

fn freeArena(arena: *std.heap.ArenaAllocator) void {
    const gpa = arena.child_allocator;
    arena.deinit();
    gpa.destroy(arena);
}

fn contains(list: []const keys.PublicKey, pk: keys.PublicKey) bool {
    for (list) |x| {
        if (std.mem.eql(u8, &x, &pk)) return true;
    }
    return false;
}

fn tag2(a: std.mem.Allocator, name: []const u8, bytes: []const u8) std.mem.Allocator.Error!event.Tag {
    const fields = try a.alloc([]const u8, 2);
    fields[0] = name;
    fields[1] = try hex.encode(a, bytes);
    return fields;
}

/// A timestamp between `max_timestamp_tweak` seconds and one second before
/// now. Never now itself, so a layer's time never equals the moment it was
/// made.
fn randomPastTimestamp(io: std.Io) Error!i64 {
    var buf: [8]u8 = undefined;
    io.randomSecure(&buf) catch return Error.RandomFailed;
    const r = std.mem.readInt(u64, &buf, .little);
    const offset: i64 = 1 + @as(i64, @intCast(r % @as(u64, @intCast(max_timestamp_tweak))));
    return std.Io.Timestamp.now(io, .real).toSeconds() - offset;
}

fn auxRand(io: std.Io) Error![32]u8 {
    var aux: [32]u8 = undefined;
    io.randomSecure(&aux) catch return Error.RandomFailed;
    return aux;
}

/// `seal`, allocating into an arena-like `a` that must outlive the event.
fn sealLeaky(
    a: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    sender: keys.KeyPair,
    recipient: keys.PublicKey,
    rumor: Rumor,
) Error!event.Event {
    if (!std.mem.eql(u8, &rumor.pubkey, &sender.public_key)) return Error.SenderMismatch;
    if (!try rumor.idMatches(a)) return Error.RumorIdMismatch;
    const rumor_json = try rumorToJson(a, rumor);
    return sealJsonLeaky(a, io, signer, sender, recipient, rumor_json);
}

/// Seals already-serialized rumor JSON without checking it. Tests use this to
/// build the forged seals `unwrap` must refuse.
fn sealJsonLeaky(
    a: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    sender: keys.KeyPair,
    recipient: keys.PublicKey,
    rumor_json: []const u8,
) Error!event.Event {
    const ciphertext = try nip44.encrypt(a, io, signer, sender.secret_key, recipient, rumor_json);
    const created_at = try randomPastTimestamp(io);
    return event.create(a, signer, sender, created_at, seal_kind, &.{}, ciphertext, try auxRand(io));
}

/// `wrap`, allocating into an arena-like `a` that must outlive the event.
fn wrapLeaky(
    a: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    seal_event: event.Event,
    recipient: keys.PublicKey,
    extra_tags: []const event.Tag,
) Error!event.Event {
    if (seal_event.kind != seal_kind) return Error.WrongKind;
    return wrapAnyLeaky(a, io, signer, seal_event, recipient, extra_tags);
}

fn wrapAnyLeaky(
    a: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    inner: event.Event,
    recipient: keys.PublicKey,
    extra_tags: []const event.Tag,
) Error!event.Event {
    var ephemeral = try signer.generateKeyPair(io);
    defer std.crypto.secureZero(u8, &ephemeral.secret_key);

    const inner_json = try event.toJson(a, inner);
    const ciphertext = try nip44.encrypt(a, io, signer, ephemeral.secret_key, recipient, inner_json);

    const tags = try a.alloc(event.Tag, 1 + extra_tags.len);
    tags[0] = try tag2(a, "p", &recipient);
    for (extra_tags, tags[1..]) |src, *dst| {
        const fields = try a.alloc([]const u8, src.len);
        for (src, fields) |s, *d| d.* = try a.dupe(u8, s);
        dst.* = fields;
    }

    const created_at = try randomPastTimestamp(io);
    return event.create(a, signer, ephemeral, created_at, gift_wrap_kind, tags, ciphertext, try auxRand(io));
}

/// A rumor on the wire: an event without `sig`. A `sig` field, if a sender
/// left one in, is ignored, along with any other key NIP-01 does not name.
const WireRumor = struct {
    id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    kind: u16,
    tags: []const []const []const u8,
    content: []const u8,
};

fn parseRumorLeaky(a: std.mem.Allocator, rumor_json: []const u8) Error!Rumor {
    const wire = std.json.parseFromSliceLeaky(WireRumor, a, rumor_json, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidRumor,
    };
    return .{
        .id = hex.decodeFixed(32, wire.id) catch return Error.InvalidRumor,
        .pubkey = hex.decodeFixed(32, wire.pubkey) catch return Error.InvalidRumor,
        .created_at = wire.created_at,
        .kind = wire.kind,
        .tags = wire.tags,
        .content = wire.content,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexTo(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn parseEvent(text: []const u8) !event.Parsed {
    return event.fromJson(testing.allocator, text);
}

fn nowSeconds() i64 {
    return std.Io.Timestamp.now(testing.io, .real).toSeconds();
}

fn findTag(tags: []const event.Tag, name: []const u8) ?event.Tag {
    for (tags) |t| {
        if (t.len > 0 and std.mem.eql(u8, t[0], name)) return t;
    }
    return null;
}

test "nip59: seal, wrap and unwrap round trip" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);

    const tags = [_]event.Tag{&.{ "t", "party" }};
    const rumor = try Rumor.init(testing.allocator, alice.public_key, 1700000000, 1, &tags, "Are you going to the party tonight?");

    var sealed = try seal(testing.allocator, testing.io, signer, alice, bob.public_key, rumor);
    defer sealed.deinit();
    try testing.expectEqual(seal_kind, sealed.event.kind);
    try testing.expectEqual(@as(usize, 0), sealed.event.tags.len);
    try testing.expectEqualSlices(u8, &alice.public_key, &sealed.event.pubkey);
    try testing.expect(try event.verify(testing.allocator, signer, sealed.event));

    const extra = [_]event.Tag{&.{ "expiration", "1800000000" }};
    var wrapped = try wrap(testing.allocator, testing.io, signer, sealed.event, bob.public_key, &extra);
    defer wrapped.deinit();
    try testing.expectEqual(gift_wrap_kind, wrapped.event.kind);
    try testing.expect(try event.verify(testing.allocator, signer, wrapped.event));
    try testing.expect(!std.mem.eql(u8, &wrapped.event.pubkey, &alice.public_key));
    try testing.expectEqual(@as(usize, 2), wrapped.event.tags.len);
    try testing.expectEqualStrings("p", wrapped.event.tags[0][0]);
    const bob_hex = std.fmt.bytesToHex(bob.public_key, .lower);
    try testing.expectEqualStrings(&bob_hex, wrapped.event.tags[0][1]);
    try testing.expectEqualStrings("expiration", wrapped.event.tags[1][0]);

    // Through the wire format, as a relay would deliver it.
    const wire = try event.toJson(testing.allocator, wrapped.event);
    defer testing.allocator.free(wire);
    var parsed = try parseEvent(wire);
    defer parsed.deinit();

    var opened = try unwrap(testing.allocator, signer, bob.secret_key, parsed.value);
    defer opened.deinit();
    try testing.expectEqualSlices(u8, &alice.public_key, &opened.sender);
    try testing.expectEqualSlices(u8, &rumor.id, &opened.rumor.id);
    try testing.expectEqual(@as(u16, 1), opened.rumor.kind);
    try testing.expectEqual(@as(i64, 1700000000), opened.rumor.created_at);
    try testing.expectEqualStrings("Are you going to the party tonight?", opened.rumor.content);
    try testing.expectEqualStrings("party", opened.rumor.tags[0][1]);
}

test "nip59: rumor JSON escapes content and has no sig" {
    const pk = hexTo(32, "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9");
    const tags = [_]event.Tag{&.{ "p", "a\"b" }};
    const rumor = try Rumor.init(testing.allocator, pk, 5, 14, &tags, "line\nnext\x01");
    const text = try rumorToJson(testing.allocator, rumor);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "\"sig\"") == null);
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const back = try parseRumorLeaky(a.allocator(), text);
    try testing.expect(try back.idMatches(a.allocator()));
    try testing.expectEqualStrings("line\nnext\x01", back.content);
    try testing.expectEqualStrings("a\"b", back.tags[0][1]);
}

test "nip59: the NIP's worked example rumor id and gift wrap" {
    // Keys and events from the example in NIP-59.
    const author_pk = hexTo(32, "611df01bfcf85c26ae65453b772d8f1dfd25c264621c0277e1fc1518686faef9");
    const recipient_sk = hexTo(32, "e108399bd8424357a710b606ae0c13166d853d327e47a6e5e038197346bdbf45");

    const rumor = try Rumor.init(testing.allocator, author_pk, 1691518405, 1, &.{}, "Are you going to the party tonight?");
    try testing.expectEqualSlices(u8, &hexTo(32, "9dd003c6d3b73b74a85a9ab099469ce251653a7af76f523671ab828acd2a0ef9"), &rumor.id);

    var signer = keys.Signer.init();
    defer signer.deinit();
    var parsed = try parseEvent(
        \\{"content":"AhC3Qj/QsKJFWuf6xroiYip+2yK95qPwJjVvFujhzSguJWb/6TlPpBW0CGFwfufCs2Zyb0JeuLmZhNlnqecAAalC4ZCugB+I9ViA5pxLyFfQjs1lcE6KdX3euCHBLAnE9GL/+IzdV9vZnfJH6atVjvBkNPNzxU+OLCHO/DAPmzmMVx0SR63frRTCz6Cuth40D+VzluKu1/Fg2Q1LSst65DE7o2efTtZ4Z9j15rQAOZfE9jwMCQZt27rBBK3yVwqVEriFpg2mHXc1DDwHhDADO8eiyOTWF1ghDds/DxhMcjkIi/o+FS3gG1dG7gJHu3KkGK5UXpmgyFKt+421m5o++RMD/BylS3iazS1S93IzTLeGfMCk+7IKxuSCO06k1+DaasJJe8RE4/rmismUvwrHu/HDutZWkvOAhd4z4khZo7bJLtiCzZCZ74lZcjOB4CYtuAX2ZGpc4I1iOKkvwTuQy9BWYpkzGg3ZoSWRD6ty7U+KN+fTTmIS4CelhBTT15QVqD02JxfLF7nA6sg3UlYgtiGw61oH68lSbx16P3vwSeQQpEB5JbhofW7t9TLZIbIW/ODnI4hpwj8didtk7IMBI3Ra3uUP7ya6vptkd9TwQkd/7cOFaSJmU+BIsLpOXbirJACMn+URoDXhuEtiO6xirNtrPN8jYqpwvMUm5lMMVzGT3kMMVNBqgbj8Ln8VmqouK0DR+gRyNb8fHT0BFPwsHxDskFk5yhe5c/2VUUoKCGe0kfCcX/EsHbJLUUtlHXmTqaOJpmQnW1tZ/siPwKRl6oEsIJWTUYxPQmrM2fUpYZCuAo/29lTLHiHMlTbarFOd6J/ybIbICy2gRRH/LFSryty3Cnf6aae+A9uizFBUdCwTwffc3vCBae802+R92OL78bbqHKPbSZOXNC+6ybqziezwG+OPWHx1Qk39RYaF0aFsM4uZWrFic97WwVrH5i+/Nsf/OtwWiuH0gV/SqvN1hnkxCTF/+XNn/laWKmS3e7wFzBsG8+qwqwmO9aVbDVMhOmeUXRMkxcj4QreQkHxLkCx97euZpC7xhvYnCHarHTDeD6nVK+xzbPNtzeGzNpYoiMqxZ9bBJwMaHnEoI944Vxoodf51cMIIwpTmmRvAzI1QgrfnOLOUS7uUjQ/IZ1Qa3lY08Nqm9MAGxZ2Ou6R0/Z5z30ha/Q71q6meAs3uHQcpSuRaQeV29IASmye2A2Nif+lmbhV7w8hjFYoaLCRsdchiVyNjOEM4VmxUhX4VEvw6KoCAZ/XvO2eBF/SyNU3Of4SO","kind":1059,"created_at":1703021488,"pubkey":"18b1a75918f1f2c90c23da616bce317d36e348bcf5f7ba55e75949319210c87c","id":"5c005f3ccf01950aa8d131203248544fb1e41a0d698e846bd419cec3890903ac","sig":"35fabdae4634eb630880a1896a886e40fd6ea8a60958e30b89b33a93e6235df750097b04f9e13053764251b8bc5dd7e8e0794a3426a90b6bcc7e5ff660f54259","tags":[["p","166bf3765ebd1fc55decfe395beff2ea3b2a4e0a8946e7eb578512b555737c99"]]}
    );
    defer parsed.deinit();

    var opened = try unwrap(testing.allocator, signer, recipient_sk, parsed.value);
    defer opened.deinit();
    try testing.expectEqualSlices(u8, &author_pk, &opened.sender);
    try testing.expectEqualSlices(u8, &rumor.id, &opened.rumor.id);
    try testing.expectEqualStrings("Are you going to the party tonight?", opened.rumor.content);
}

test "nip59: the NIP-17 example wraps open for the receiver and the sender" {
    // From the example in NIP-17: "Hola, que tal?", one wrap to the receiver
    // and one to the sender.
    const sender_sk = hexTo(32, "71f8de50a46c9996a21123280c6217c48f67d1378ff4fb14d4f7612181a1ebde");
    const sender_pk = hexTo(32, "44900586091b284416a0c001f677f9c49f7639a55c3f1e2ec130a8e1a7998e1b");
    const receiver_sk = hexTo(32, "511cbb07ec2028bd2dcd039c447581a7f754df9d9a0e5c16b19a5422ab391563");

    var signer = keys.Signer.init();
    defer signer.deinit();

    var to_receiver = try parseEvent(
        \\{"id":"2886780f7349afc1344047524540ee716f7bdc1b64191699855662330bf235d8","pubkey":"8f8a7ec43b77d25799281207e1a47f7a654755055788f7482653f9c9661c6d51","created_at":1703128320,"kind":1059,"tags":[["p","918e2da906df4ccd12c8ac672d8335add131a4cf9d27ce42b3bb3625755f0788"]],"content":"AsqzdlMsG304G8h08bE67dhAR1gFTzTckUUyuvndZ8LrGCvwI4pgC3d6hyAK0Wo9gtkLqSr2rT2RyHlE5wRqbCOlQ8WvJEKwqwIJwT5PO3l2RxvGCHDbd1b1o40ZgIVwwLCfOWJ86I5upXe8K5AgpxYTOM1BD+SbgI5jOMA8tgpRoitJedVSvBZsmwAxXM7o7sbOON4MXHzOqOZpALpS2zgBDXSAaYAsTdEM4qqFeik+zTk3+L6NYuftGidqVluicwSGS2viYWr5OiJ1zrj1ERhYSGLpQnPKrqDaDi7R1KrHGFGyLgkJveY/45y0rv9aVIw9IWF11u53cf2CP7akACel2WvZdl1htEwFu/v9cFXD06fNVZjfx3OssKM/uHPE9XvZttQboAvP5UoK6lv9o3d+0GM4/3zP+yO3C0NExz1ZgFmbGFz703YJzM+zpKCOXaZyzPjADXp8qBBeVc5lmJqiCL4solZpxA1865yPigPAZcc9acSUlg23J1dptFK4n3Tl5HfSHP+oZ/QS/SHWbVFCtq7ZMQSRxLgEitfglTNz9P1CnpMwmW/Y4Gm5zdkv0JrdUVrn2UO9ARdHlPsW5ARgDmzaxnJypkfoHXNfxGGXWRk0sKLbz/ipnaQP/eFJv/ibNuSfqL6E4BnN/tHJSHYEaTQ/PdrA2i9laG3vJti3kAl5Ih87ct0w/tzYfp4SRPhEF1zzue9G/16eJEMzwmhQ5Ec7jJVcVGa4RltqnuF8unUu3iSRTQ+/MNNUkK6Mk+YuaJJs6Fjw6tRHuWi57SdKKv7GGkr0zlBUU2Dyo1MwpAqzsCcCTeQSv+8qt4wLf4uhU9Br7F/L0ZY9bFgh6iLDCdB+4iABXyZwT7Ufn762195hrSHcU4Okt0Zns9EeiBOFxnmpXEslYkYBpXw70GmymQfJlFOfoEp93QKCMS2DAEVeI51dJV1e+6t3pCSsQN69Vg6jUCsm1TMxSs2VX4BRbq562+VffchvW2BB4gMjsvHVUSRl8i5/ZSDlfzSPXcSGALLHBRzy+gn0oXXJ/447VHYZJDL3Ig8+QW5oFMgnWYhuwI5QSLEyflUrfSz+Pdwn/5eyjybXKJftePBD9Q+8NQ8zulU5sqvsMeIx/bBUx0fmOXsS3vjqCXW5IjkmSUV7q54GewZqTQBlcx+90xh/LSUxXex7UwZwRnifvyCbZ+zwNTHNb12chYeNjMV7kAIr3cGQv8vlOMM8ajyaZ5KVy7HpSXQjz4PGT2/nXbL5jKt8Lx0erGXsSsazkdoYDG3U","sig":"a3c6ce632b145c0869423c1afaff4a6d764a9b64dedaf15f170b944ead67227518a72e455567ca1c2a0d187832cecbde7ed478395ec4c95dd3e71749ed66c480"}
    );
    defer to_receiver.deinit();
    var to_sender = try parseEvent(
        \\{"id":"162b0611a1911cfcb30f8a5502792b346e535a45658b3a31ae5c178465509721","pubkey":"626be2af274b29ea4816ad672ee452b7cf96bbb4836815a55699ae402183f512","created_at":1702711587,"kind":1059,"tags":[["p","44900586091b284416a0c001f677f9c49f7639a55c3f1e2ec130a8e1a7998e1b"]],"content":"AsTClTzr0gzXXji7uye5UB6LYrx3HDjWGdkNaBS6BAX9CpHa+Vvtt5oI2xJrmWLen+Fo2NBOFazvl285Gb3HSM82gVycrzx1HUAaQDUG6HI7XBEGqBhQMUNwNMiN2dnilBMFC3Yc8ehCJT/gkbiNKOpwd2rFibMFRMDKai2mq2lBtPJF18oszKOjA+XlOJV8JRbmcAanTbEK5nA/GnG3eGUiUzhiYBoHomj3vztYYxc0QYHOx0WxiHY8dsC6jPsXC7f6k4P+Hv5ZiyTfzvjkSJOckel1lZuE5SfeZ0nduqTlxREGeBJ8amOykgEIKdH2VZBZB+qtOMc7ez9dz4wffGwBDA7912NFS2dPBr6txHNxBUkDZKFbuD5wijvonZDvfWq43tZspO4NutSokZB99uEiRH8NAUdGTiNb25m9JcDhVfdmABqTg5fIwwTwlem5aXIy8b66lmqqz2LBzJtnJDu36bDwkILph3kmvaKPD8qJXmPQ4yGpxIbYSTCohgt2/I0TKJNmqNvSN+IVoUuC7ZOfUV9lOV8Ri0AMfSr2YsdZ9ofV5o82ClZWlWiSWZwy6ypa7CuT1PEGHzywB4CZ5ucpO60Z7hnBQxHLiAQIO/QhiBp1rmrdQZFN6PUEjFDloykoeHe345Yqy9Ke95HIKUCS9yJurD+nZjjgOxZjoFCsB1hQAwINTIS3FbYOibZnQwv8PXvcSOqVZxC9U0+WuagK7IwxzhGZY3vLRrX01oujiRrevB4xbW7Oxi/Agp7CQGlJXCgmRE8Rhm+Vj2s+wc/4VLNZRHDcwtfejogjrjdi8p6nfUyqoQRRPARzRGUnnCbh+LqhigT6gQf3sVilnydMRScEc0/YYNLWnaw9nbyBa7wFBAiGbJwO40k39wj+xT6HTSbSUgFZzopxroO3f/o4+ubx2+IL3fkev22mEN38+dFmYF3zE+hpE7jVxrJpC3EP9PLoFgFPKCuctMnjXmeHoiGs756N5r1Mm1ffZu4H19MSuALJlxQR7VXE/LzxRXDuaB2u9days/6muP6gbGX1ASxbJd/ou8+viHmSC/ioHzNjItVCPaJjDyc6bv+gs1NPCt0qZ69G+JmgHW/PsMMeL4n5bh74g0fJSHqiI9ewEmOG/8bedSREv2XXtKV39STxPweceIOh0k23s3N6+wvuSUAJE7u1LkDo14cobtZ/MCw/QhimYPd1u5HnEJvRhPxz0nVPz0QqL/YQeOkAYk7uzgeb2yPzJ6DBtnTnGDkglekhVzQBFRJdk740LEj6swkJ","sig":"c94e74533b482aa8eeeb54ae72a5303e0b21f62909ca43c8ef06b0357412d6f8a92f96e1a205102753777fd25321a58fba3fb384eee114bd53ce6c06a1c22bab"}
    );
    defer to_sender.deinit();

    var a = try unwrap(testing.allocator, signer, receiver_sk, to_receiver.value);
    defer a.deinit();
    var b = try unwrap(testing.allocator, signer, sender_sk, to_sender.value);
    defer b.deinit();
    for ([_]*const Unwrapped{ &a, &b }) |u| {
        try testing.expectEqualSlices(u8, &sender_pk, &u.sender);
        try testing.expectEqual(direct_message_kind, u.rumor.kind);
        try testing.expectEqualStrings("Hola, que tal?", u.rumor.content);
    }
    try testing.expectEqualSlices(u8, &a.rumor.id, &b.rumor.id);

    // Each copy is for its own key only.
    try testing.expectError(Error.InvalidMac, unwrap(testing.allocator, signer, sender_sk, to_receiver.value));
}

test "nip59: opens a gift wrap made by nak" {
    // `nak event -k 14 -c 'hello from nak' -p <B> --ts 1760000000 | nak gift
    // wrap --sec <A> -p <B>` (nak v0.21.2), with throwaway keys A and B.
    const a_pk = hexTo(32, "040d3d6cffbf3939ef2c10619e618d6ee342452deb0535995a48af5677576825");
    const b_sk = hexTo(32, "06a4151ff98781afce81c3adb9e55d05261d4157472068d34871c99586e08dd2");

    var signer = keys.Signer.init();
    defer signer.deinit();
    var parsed = try parseEvent(
        \\{"kind":1059,"id":"ca8c89088430b246f1a47cbc6afc4c2597fffb78c5df1301d4d175fe2f587c4e","pubkey":"4acfd868767e6c766d092900142329602aa8b2534f17a63c3a45485ea23464b7","created_at":1791629984,"tags":[["p","106bba9fb2d07c2f841cbd305e831dd21455fd3c6a262d7693b86b4b3a989bfd"]],"content":"AqiSY6d+c/SCtWJZgRUClZ2nFbkCgjwN/4B9bLAwV9MsuNUUJSlU4GYnwJ4CVeL9J0j1eIaBA5gRzgEAlWmf/YQY1oRgDKVU1vcGaQmLZ6b1IWrGW3dYvaf6vj8MRd6opILpvh9jHsmz9X8VsLkpahGWvY/CYYWwtChpYK2KBk5bkwp7f0mKhQRY8U4AMNFdAabgDBLygrAcoYCwHvdRit41jKwkhD5zOl28CKxWhSGw0h4Re5e+0/HsqjuRBnBqFIVqIUYZXGwfPjJx4jFRWcCuMviRmjQmfuaKgOIEuZ2jUMGwPw6JCWwg+iD8vT/ym8/a93qHy/zvpjkWBMG2tqHLwyMVurRADT604gDPrfSF13Zfhgzm/MUHcN1N8S76nAOx1x1W+Z2ThtCmIAH/yunwxJLnkwumKu1riO32JXQ8GO6YF7zHhnMsEAxMBCYGzy/GXln4ovVIKQtq69WRwNvIRT1tkMg6T2pqAFvboJBqiW8fZBPU31teGUBXnHHSHJk6fRoXrBptuX9wEAIL3i0BExL9qKuTl47Kvb67/aiLmk9dXNmU3aYuIWP4wE6T19sr7AYsI/ap3qsaMLwnXKgc72QIiOwiOKgCgpmKyRPohi2T/l/kvJnAb38Ti1WYXKUxNgjGSt5zjtB9k7j4VdqmuZ5Uk/C7dG2tZewolZvV7e9Sr3ea16LgmZo0r2PMwe23N4K8HT2YGKY+UfyQYwp35idNtR2xyhKgXVk2AibT+R86dvtkGc0D8FLyNcT7sFEuWLhWL1stjH52Ysvy9QCnzF7O6k7uNtuL4imQ2AtTBGxQaWhC1FCbgvTgsObGYffHnzWHfpCHVvkSnIOJt6xf1/hHM2dJArF4AiooAx/6WNdLUm/HZs7m7rdkG1/VEP1K5Yum7jZZ9rcfW3Pb3HLRAcfLnivT+gcvO/UdkiiE9FX8fTsPmc47mhEPyIYAxTWAojXUKyZDGVoPVotphV5FYrEGTVnYykGrIlhoCh0H6BUFWac0Er7v//xbuwd0ERoLKiw9QSES6TefCtTaz/LYxSS/CioAS5JBE/680kgYMoQ1HKkST6+E7GDVmasqtmC21A5YIdC2xCmt/ogEWUtIxeXmuX7CnFWgOOKJRJoGaM36RIFOhQzG9XK2w/mg8YWIAVYDeQWyaZTWBsk/xF3PD+2NgeYiwK9AsKS3fUpXBOSEG6zJwh8dPJzPQQYg0zMrjRM4BIE4U+HD2DLImLH65a2XNYnykvbNGAQaBPtqu6He5ksx71UUiMW7ftA+f7uP","sig":"d7bc82c5c2a02304f10f17c31ff248df138eb7445e0b4797865b41fd1bc70a9803a0ac96af91db25a10f94b66d8badc732152ea295bb60a8a876634e963d7c02"}
    );
    defer parsed.deinit();

    var opened = try unwrap(testing.allocator, signer, b_sk, parsed.value);
    defer opened.deinit();
    try testing.expectEqualSlices(u8, &a_pk, &opened.sender);
    try testing.expectEqualSlices(u8, &hexTo(32, "0c96f17fe42f80d3aa73949ee164078d4e470a59157d620bf31833ccba024111"), &opened.rumor.id);
    try testing.expectEqual(direct_message_kind, opened.rumor.kind);
    try testing.expectEqual(@as(i64, 1760000000), opened.rumor.created_at);
    try testing.expectEqualStrings("hello from nak", opened.rumor.content);
}

test "nip59: a tampered wrap or seal is refused" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const hi = try Rumor.init(a, alice.public_key, 1700000000, 14, &.{}, "hi");
    const bye = try Rumor.init(a, alice.public_key, 1700000000, 14, &.{}, "bye");
    const sealed = try sealLeaky(a, testing.io, signer, alice, bob.public_key, hi);
    const other = try sealLeaky(a, testing.io, signer, alice, bob.public_key, bye);

    // A seal whose content was swapped after signing.
    var swapped = sealed;
    swapped.content = other.content;
    try testing.expectError(Error.InvalidSealSignature, unwrap(testing.allocator, signer, bob.secret_key, try wrapLeaky(a, testing.io, signer, swapped, bob.public_key, &.{})));

    // A seal with one bit of its signature flipped.
    var bad_sig = sealed;
    bad_sig.sig[0] ^= 1;
    try testing.expectError(Error.InvalidSealSignature, unwrap(testing.allocator, signer, bob.secret_key, try wrapLeaky(a, testing.io, signer, bad_sig, bob.public_key, &.{})));

    const w = try wrapLeaky(a, testing.io, signer, sealed, bob.public_key, &.{});

    // A wrap with a re-dated created_at: the id no longer matches.
    var redated = w;
    redated.created_at += 1;
    try testing.expectError(Error.InvalidWrapSignature, unwrap(testing.allocator, signer, bob.secret_key, redated));

    // A wrap with a flipped signature bit.
    var wrap_sig = w;
    wrap_sig.sig[63] ^= 0x80;
    try testing.expectError(Error.InvalidWrapSignature, unwrap(testing.allocator, signer, bob.secret_key, wrap_sig));

    // Not a gift wrap at all.
    var wrong_kind = w;
    wrong_kind.kind = 1;
    try testing.expectError(Error.WrongKind, unwrap(testing.allocator, signer, bob.secret_key, wrong_kind));

    // The untouched wrap still opens.
    var opened = try unwrap(testing.allocator, signer, bob.secret_key, w);
    defer opened.deinit();
    try testing.expectEqualStrings("hi", opened.rumor.content);
}

test "nip59: a rumor claiming another author is refused" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);
    const eve = try signer.generateKeyPair(testing.io);

    // Eve writes a rumor in Alice's name.
    const forged = try Rumor.init(testing.allocator, alice.public_key, 1700000000, 14, &.{}, "send Eve the keys");

    // `seal` will not sign it for her.
    try testing.expectError(Error.SenderMismatch, seal(testing.allocator, testing.io, signer, eve, bob.public_key, forged));

    // So she seals the JSON herself, validly signed by her own key.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sealed = try sealJsonLeaky(a, testing.io, signer, eve, bob.public_key, try rumorToJson(a, forged));
    const w = try wrapLeaky(a, testing.io, signer, sealed, bob.public_key, &.{});

    try testing.expectError(Error.SenderMismatch, unwrap(testing.allocator, signer, bob.secret_key, w));
}

test "nip59: a malformed or mis-hashed rumor and a non-seal are refused" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);

    var rumor = try Rumor.init(testing.allocator, alice.public_key, 1700000000, 14, &.{}, "original");
    rumor.content = "edited";
    try testing.expectError(Error.RumorIdMismatch, seal(testing.allocator, testing.io, signer, alice, bob.public_key, rumor));

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sealed = try sealJsonLeaky(a, testing.io, signer, alice, bob.public_key, try rumorToJson(a, rumor));
    const w = try wrapLeaky(a, testing.io, signer, sealed, bob.public_key, &.{});
    try testing.expectError(Error.RumorIdMismatch, unwrap(testing.allocator, signer, bob.secret_key, w));

    // A seal of something that is not an event.
    const junk = try sealJsonLeaky(a, testing.io, signer, alice, bob.public_key, "not json");
    try testing.expectError(Error.InvalidRumor, unwrap(testing.allocator, signer, bob.secret_key, try wrapLeaky(a, testing.io, signer, junk, bob.public_key, &.{})));

    // A wrap around a signed note instead of a seal.
    const note = try event.create(a, signer, alice, 1700000000, 1, &.{}, "plain note", null);
    try testing.expectError(Error.WrongKind, wrap(testing.allocator, testing.io, signer, note, bob.public_key, &.{}));
    const around_note = try wrapAnyLeaky(a, testing.io, signer, note, bob.public_key, &.{});
    try testing.expectError(Error.WrongKind, unwrap(testing.allocator, signer, bob.secret_key, around_note));
}

test "nip59: the wrong recipient key cannot open a wrap" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);
    const eve = try signer.generateKeyPair(testing.io);

    var dm = try privateDirectMessage(testing.allocator, testing.io, signer, alice, &.{bob.public_key}, "for Bob only", null, null);
    defer dm.deinit();
    for (dm.wraps) |w| {
        try testing.expectError(Error.InvalidMac, unwrap(testing.allocator, signer, eve.secret_key, w));
    }
}

test "nip59: seal and wrap timestamps are in the past, within two days" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);

    const before = nowSeconds();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rumor = try Rumor.init(a, alice.public_key, before, 14, &.{}, "when?");

    var stamps: [16]i64 = undefined;
    var i: usize = 0;
    while (i < stamps.len) : (i += 2) {
        const s = try sealLeaky(a, testing.io, signer, alice, bob.public_key, rumor);
        const w = try wrapLeaky(a, testing.io, signer, s, bob.public_key, &.{});
        stamps[i] = s.created_at;
        stamps[i + 1] = w.created_at;
    }
    const after = nowSeconds();

    var all_same = true;
    for (stamps) |t| {
        try testing.expect(t < after);
        try testing.expect(t >= before - max_timestamp_tweak);
        if (t != stamps[0]) all_same = false;
    }
    try testing.expect(!all_same);
}

test "nip59: NIP-17 message wraps once per recipient and once to the sender" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);
    const carol = try signer.generateKeyPair(testing.io);

    const parent = hexTo(32, "2886780f7349afc1344047524540ee716f7bdc1b64191699855662330bf235d8");
    const before = nowSeconds();
    // Bob listed twice still gets one tag and one wrap.
    var dm = try privateDirectMessage(
        testing.allocator,
        testing.io,
        signer,
        alice,
        &.{ bob.public_key, carol.public_key, bob.public_key },
        "dinner at 8?",
        parent,
        "plans",
    );
    defer dm.deinit();

    try testing.expectEqual(direct_message_kind, dm.rumor.kind);
    try testing.expect(dm.rumor.created_at >= before);
    try testing.expectEqual(@as(usize, 4), dm.rumor.tags.len);
    try testing.expectEqualStrings("p", dm.rumor.tags[0][0]);
    try testing.expectEqualStrings("p", dm.rumor.tags[1][0]);
    const parent_hex = std.fmt.bytesToHex(parent, .lower);
    try testing.expectEqualStrings(&parent_hex, findTag(dm.rumor.tags, "e").?[1]);
    try testing.expectEqualStrings("plans", findTag(dm.rumor.tags, "subject").?[1]);

    // Bob, Carol and Alice herself.
    try testing.expectEqual(@as(usize, 3), dm.wraps.len);
    const readers = [_]keys.KeyPair{ bob, carol, alice };
    for (dm.wraps, readers) |w, reader| {
        const want = std.fmt.bytesToHex(reader.public_key, .lower);
        try testing.expectEqualStrings(&want, w.tags[0][1]);
        var opened = try unwrap(testing.allocator, signer, reader.secret_key, w);
        defer opened.deinit();
        try testing.expectEqualSlices(u8, &alice.public_key, &opened.sender);
        try testing.expectEqualSlices(u8, &dm.rumor.id, &opened.rumor.id);
        try testing.expectEqualStrings("dinner at 8?", opened.rumor.content);
    }

    // Every wrap has its own one-time key, none of them a participant's.
    for (dm.wraps, 0..) |w, x| {
        for (readers) |r| try testing.expect(!std.mem.eql(u8, &w.pubkey, &r.public_key));
        for (dm.wraps[x + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, &w.pubkey, &other.pubkey));
    }

    try testing.expectError(Error.NoRecipients, privateDirectMessage(testing.allocator, testing.io, signer, alice, &.{}, "x", null, null));
}

test "nip59: a sender who lists themselves is wrapped to once" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);
    var dm = try privateDirectMessage(testing.allocator, testing.io, signer, alice, &.{ alice.public_key, bob.public_key }, "note to self and Bob", null, null);
    defer dm.deinit();
    try testing.expectEqual(@as(usize, 2), dm.wraps.len);
}
