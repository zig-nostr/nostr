//! NIP-77 negentropy syncing of event sets.
//!
//! An implementation of Negentropy protocol version 1 (`0x61`), the binary
//! range-based set reconciliation protocol NIP-77 carries hex-encoded in its
//! `NEG-OPEN` and `NEG-MSG` messages. Two sides each hold a set of
//! `(timestamp, id)` items; the initiator learns which ids it has that the
//! other side lacks and which ids it lacks that the other side has.
//!
//! This matches the reference implementation (hoytech/negentropy, the C++
//! `negentropy.h` and the JavaScript `Negentropy.js`) message for message:
//! the same 16-way range split, the same switch to an id list below 32
//! items, the same minimal bounds, and the same frame size limit behaviour.
//! The tests replay transcripts recorded from the JavaScript reference and
//! compare the messages byte for byte.
//!
//! This module works on raw message bytes. `toHex` and `fromHex` convert to
//! and from the hex form that travels inside the NIP-77 envelopes.
//!
//!     var storage = try Storage.fromSlice(gpa, items);
//!     defer storage.deinit(gpa);
//!     var client = try Initiator.init(&storage, .{});
//!     const msg = try client.initiate(gpa);
//!     // send msg, receive the reply, then:
//!     var r = try client.reconcile(gpa, reply);
//!     defer r.deinit(gpa);
//!     // r.have, r.need; r.message is the next message, or null when done.

const std = @import("std");
const hex = @import("hex.zig");
const store_mod = @import("store.zig");
const Filter = @import("filter.zig").Filter;
const message = @import("message.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// The protocol version byte for Negentropy V1.
pub const protocol_version: u8 = 0x61;
pub const id_size = 32;
pub const fingerprint_size = 16;
/// The reserved timestamp meaning "infinity". No item may use it.
pub const max_timestamp: u64 = std.math.maxInt(u64);
/// The smallest non-zero frame size limit the reference accepts.
pub const min_frame_size_limit: u64 = 4096;
/// The frame size limit both sides use unless told otherwise. Tied to what
/// the NIP-77 envelope parser accepts: a message is hex-encoded on the wire,
/// so twice this has to stay under `message.max_neg_hex_len`, or a peer on
/// default options would send a frame the other side refuses to read.
pub const default_frame_size_limit: u64 = 500_000;

comptime {
    std.debug.assert(2 * default_frame_size_limit <= message.max_neg_hex_len);
}
/// How many sub-ranges a differing range is split into. A range with fewer
/// than twice this many items is sent as an id list instead.
const buckets: usize = 16;

/// One record to reconcile: an event's `created_at` and its id.
pub const Item = store_mod.SyncItem;

pub const Error = error{
    OutOfMemory,
    /// The message is truncated, has an overlong varint, an id prefix longer
    /// than 32 bytes, or an unknown range mode.
    Malformed,
    /// The first byte is not a negentropy protocol version (0x60..0x6F).
    InvalidProtocolVersion,
    /// The responder answered with a protocol version this side cannot speak.
    UnsupportedProtocolVersion,
    /// A non-zero frame size limit below 4096.
    FrameSizeLimitTooSmall,
    /// `initiate` was called twice on one initiator.
    AlreadyInitiated,
    /// `reconcile` was called on an initiator before `initiate`.
    NotInitiated,
    /// The same (timestamp, id) appears twice in the input to `Storage`.
    DuplicateItem,
    /// An item uses the reserved infinity timestamp.
    InvalidTimestamp,
    /// The initiator went past `Options.max_rounds`.
    TooManyRounds,
};

pub const Mode = enum(u64) {
    skip = 0,
    fingerprint = 1,
    id_list = 2,
};

pub const Options = struct {
    /// Upper bound on the size of each message this side produces, in bytes.
    /// A non-zero value must be at least 4096. Work that does not fit is
    /// handed back as a single fingerprint range and picked up in a later
    /// round, exactly as the reference does. The default keeps every message
    /// small enough for `message.parseRelayMessage` and
    /// `message.parseClientMessage` to read once hex-encoded, and keeps a
    /// responder's reply from growing without bound on a query an untrusted
    /// peer chose. Zero means no limit, for a peer that is not speaking
    /// through those parsers.
    frame_size_limit: u64 = default_frame_size_limit,
    /// The initiator gives up with `error.TooManyRounds` after this many
    /// replies. Without a frame size limit a reconciliation finishes in a
    /// handful of rounds; with a small limit and a large difference it can
    /// take hundreds. The bound exists so a peer that never converges cannot
    /// keep the initiator busy forever.
    max_rounds: u32 = 10_000,
};

// -- Varint ------------------------------------------------------------------

/// Writes `n` as a varint into the tail of `buf` and returns that tail:
/// base-128 digits, most significant first, the high bit set on every byte
/// but the last.
fn varIntBytes(n: u64, buf: *[10]u8) []const u8 {
    var i: usize = buf.len;
    var v = n;
    while (true) {
        i -= 1;
        buf[i] = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) break;
    }
    for (buf[i .. buf.len - 1]) |*b| b.* |= 0x80;
    return buf[i..];
}

/// Appends `n` as a varint.
pub fn appendVarInt(out: *std.ArrayList(u8), gpa: std.mem.Allocator, n: u64) Error!void {
    var buf: [10]u8 = undefined;
    try out.appendSlice(gpa, varIntBytes(n, &buf));
}

/// Reads a varint from the front of `in`, advancing it. A varint that runs
/// off the end or does not fit in 64 bits is `error.Malformed`.
pub fn decodeVarInt(in: *[]const u8) Error!u64 {
    var res: u64 = 0;
    while (true) {
        if (in.len == 0) return error.Malformed;
        const byte = in.*[0];
        in.* = in.*[1..];
        if (res >> 57 != 0) return error.Malformed;
        res = (res << 7) | (byte & 0x7f);
        if (byte & 0x80 == 0) return res;
    }
}

fn takeBytes(in: *[]const u8, n: usize) Error![]const u8 {
    if (in.len < n) return error.Malformed;
    const out = in.*[0..n];
    in.* = in.*[n..];
    return out;
}

// -- Bound -------------------------------------------------------------------

/// A range boundary: a timestamp and an id prefix of `len` bytes, the rest of
/// the id being zero. Compared as the item it pads out to.
pub const Bound = struct {
    timestamp: u64 = 0,
    id: [id_size]u8 = [_]u8{0} ** id_size,
    len: u8 = 0,

    pub fn infinity() Bound {
        return .{ .timestamp = max_timestamp };
    }

    pub fn ofItem(item: Item) Bound {
        return .{ .timestamp = item.created_at, .id = item.id, .len = id_size };
    }

    fn asItem(self: Bound) Item {
        return .{ .created_at = self.timestamp, .id = self.id };
    }
};

/// The shortest bound that sorts above `prev` and at or below `curr`.
fn minimalBound(prev: Item, curr: Item) Bound {
    if (curr.created_at != prev.created_at) return .{ .timestamp = curr.created_at };
    var shared: usize = 0;
    while (shared < id_size and curr.id[shared] == prev.id[shared]) shared += 1;
    const len = @min(shared + 1, id_size);
    var b: Bound = .{ .timestamp = curr.created_at, .len = @intCast(len) };
    @memcpy(b.id[0..len], curr.id[0..len]);
    return b;
}

// -- Fingerprint -------------------------------------------------------------

/// The fingerprint of a set of ids: the first 16 bytes of
/// sha256(sum of the ids as 256-bit little-endian integers mod 2^256 ||
/// varint(count)).
pub fn fingerprintOf(sum: u256, count: u64) [fingerprint_size]u8 {
    var acc: [id_size]u8 = undefined;
    std.mem.writeInt(u256, &acc, sum, .little);
    var buf: [10]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(&acc);
    h.update(varIntBytes(count, &buf));
    return h.finalResult()[0..fingerprint_size].*;
}

// -- Storage -----------------------------------------------------------------

/// A sealed, sorted set of items. Keeps a running sum of ids so any range's
/// fingerprint costs one subtraction and one hash.
pub const Storage = struct {
    items: []Item,
    /// prefix[i] is the sum of the ids of items[0..i], mod 2^256.
    prefix: []u256,

    /// Copies `input`, sorts it by (timestamp, id) and seals it. Duplicates
    /// and the reserved infinity timestamp are rejected.
    pub fn fromSlice(gpa: std.mem.Allocator, input: []const Item) Error!Storage {
        const items = try gpa.dupe(Item, input);
        errdefer gpa.free(items);
        std.mem.sort(Item, items, {}, Item.lessThan);
        return seal(gpa, items);
    }

    /// The items of every stored event matching `filter`, read through
    /// `Store.syncItems`. With `options.max_items` set, a filter matching more
    /// fails early with `error.TooManyItems`; a relay answers that with
    /// `NEG-ERR "blocked: too many records"`.
    pub fn fromStore(gpa: std.mem.Allocator, s: *store_mod.Store, filter: Filter, options: store_mod.SyncOptions) (Error || store_mod.Error)!Storage {
        const items = try s.syncItems(gpa, filter, options);
        errdefer gpa.free(items);
        return seal(gpa, items);
    }

    /// Takes ownership of `items`, which must already be sorted.
    fn seal(gpa: std.mem.Allocator, items: []Item) Error!Storage {
        const prefix = try gpa.alloc(u256, items.len + 1);
        errdefer gpa.free(prefix);
        prefix[0] = 0;
        for (items, 0..) |item, i| {
            if (item.created_at == max_timestamp) return error.InvalidTimestamp;
            if (i > 0 and items[i - 1].created_at == item.created_at and
                std.mem.eql(u8, &items[i - 1].id, &item.id)) return error.DuplicateItem;
            prefix[i + 1] = prefix[i] +% std.mem.readInt(u256, &item.id, .little);
        }
        return .{ .items = items, .prefix = prefix };
    }

    pub fn deinit(self: *Storage, gpa: std.mem.Allocator) void {
        gpa.free(self.items);
        gpa.free(self.prefix);
        self.* = undefined;
    }

    pub fn size(self: *const Storage) usize {
        return self.items.len;
    }

    /// The fingerprint of items[begin..end].
    pub fn fingerprint(self: *const Storage, begin: usize, end: usize) [fingerprint_size]u8 {
        return fingerprintOf(self.prefix[end] -% self.prefix[begin], end - begin);
    }

    /// The first index in [begin, end) whose item is not below `bound`, or
    /// `end`.
    pub fn findLowerBound(self: *const Storage, begin: usize, end: usize, bound: Bound) usize {
        const target = bound.asItem();
        var lo = begin;
        var hi = end;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (Item.lessThan({}, self.items[mid], target)) lo = mid + 1 else hi = mid;
        }
        return lo;
    }
};

// -- Engine ------------------------------------------------------------------

/// What one initiator round produced. All slices are owned; free with
/// `deinit`.
pub const Reconciled = struct {
    /// The next message to send, or null when reconciliation is complete.
    message: ?[]u8,
    /// Ids this side has and the other side does not.
    have: [][id_size]u8,
    /// Ids the other side has and this side does not.
    need: [][id_size]u8,

    pub fn deinit(self: *Reconciled, gpa: std.mem.Allocator) void {
        if (self.message) |m| gpa.free(m);
        gpa.free(self.have);
        gpa.free(self.need);
        self.* = undefined;
    }
};

const IdList = std.ArrayList([id_size]u8);

const Engine = struct {
    storage: *const Storage,
    frame_size_limit: u64,
    last_in: u64 = 0,
    last_out: u64 = 0,

    fn init(storage: *const Storage, options: Options) Error!Engine {
        if (options.frame_size_limit != 0 and options.frame_size_limit < min_frame_size_limit)
            return error.FrameSizeLimitTooSmall;
        return .{ .storage = storage, .frame_size_limit = options.frame_size_limit };
    }

    fn exceeded(self: *const Engine, n: usize) bool {
        return self.frame_size_limit != 0 and n > self.frame_size_limit - 200;
    }

    fn decodeTimestampIn(self: *Engine, in: *[]const u8) Error!u64 {
        const raw = try decodeVarInt(in);
        const t: u64 = if (raw == 0) max_timestamp else raw - 1;
        // Saturates at infinity, as the reference does.
        const sum = @addWithOverflow(t, self.last_in);
        self.last_in = if (sum[1] != 0) max_timestamp else sum[0];
        return self.last_in;
    }

    fn decodeBound(self: *Engine, in: *[]const u8) Error!Bound {
        const t = try self.decodeTimestampIn(in);
        const len = try decodeVarInt(in);
        if (len > id_size) return error.Malformed;
        const prefix = try takeBytes(in, @intCast(len));
        var b: Bound = .{ .timestamp = t, .len = @intCast(len) };
        @memcpy(b.id[0..prefix.len], prefix);
        return b;
    }

    fn appendBound(self: *Engine, out: *std.ArrayList(u8), gpa: std.mem.Allocator, b: Bound) Error!void {
        if (b.timestamp == max_timestamp) {
            self.last_out = max_timestamp;
            try appendVarInt(out, gpa, 0);
        } else {
            // Wrapping, as the reference's unsigned arithmetic does, so a
            // peer that sends bounds out of order cannot trip a panic.
            const delta = b.timestamp -% self.last_out;
            self.last_out = b.timestamp;
            try appendVarInt(out, gpa, delta +% 1);
        }
        try appendVarInt(out, gpa, b.len);
        try out.appendSlice(gpa, b.id[0..b.len]);
    }

    fn splitRange(self: *Engine, out: *std.ArrayList(u8), gpa: std.mem.Allocator, lower: usize, upper: usize, upper_bound: Bound) Error!void {
        const items = self.storage.items;
        const n = upper - lower;
        if (n < buckets * 2) {
            try self.appendBound(out, gpa, upper_bound);
            try appendVarInt(out, gpa, @intFromEnum(Mode.id_list));
            try appendVarInt(out, gpa, n);
            try out.ensureUnusedCapacity(gpa, n * id_size);
            for (items[lower..upper]) |item| out.appendSliceAssumeCapacity(&item.id);
            return;
        }
        const per = n / buckets;
        const extra = n % buckets;
        var curr = lower;
        for (0..buckets) |i| {
            const bucket_size = per + @intFromBool(i < extra);
            const fp = self.storage.fingerprint(curr, curr + bucket_size);
            curr += bucket_size;
            const next = if (curr == upper) upper_bound else minimalBound(items[curr - 1], items[curr]);
            try self.appendBound(out, gpa, next);
            try appendVarInt(out, gpa, @intFromEnum(Mode.fingerprint));
            try out.appendSlice(gpa, &fp);
        }
    }

    fn flushSkip(self: *Engine, o: *std.ArrayList(u8), gpa: std.mem.Allocator, skip: *bool, prev_bound: Bound) Error!void {
        if (!skip.*) return;
        skip.* = false;
        try self.appendBound(o, gpa, prev_bound);
        try appendVarInt(o, gpa, @intFromEnum(Mode.skip));
    }

    /// One pass over an incoming message, following the reference's
    /// `reconcileAux` step for step. `have`/`need` are filled only for the
    /// initiator. Every iteration consumes at least two bytes of `query_in`,
    /// so the work is bounded by its length.
    fn reconcileAux(
        self: *Engine,
        gpa: std.mem.Allocator,
        query_in: []const u8,
        initiator: bool,
        have: *IdList,
        need: *IdList,
    ) Error![]u8 {
        self.last_in = 0;
        self.last_out = 0;
        var query = query_in;

        var full: std.ArrayList(u8) = .empty;
        errdefer full.deinit(gpa);
        try full.append(gpa, protocol_version);

        if (query.len == 0) return error.Malformed;
        const version = query[0];
        query = query[1..];
        if (version < 0x60 or version > 0x6f) return error.InvalidProtocolVersion;
        if (version != protocol_version) {
            if (initiator) return error.UnsupportedProtocolVersion;
            return full.toOwnedSlice(gpa);
        }

        const storage = self.storage;
        const storage_size = storage.size();
        var prev_bound: Bound = .{};
        var prev_index: usize = 0;
        var skip = false;

        var o: std.ArrayList(u8) = .empty;
        defer o.deinit(gpa);
        var resp: std.ArrayList(u8) = .empty;
        defer resp.deinit(gpa);
        // For an initiator's id list: false while an id is seen in their list
        // only, true once matched against ours or reported.
        var theirs: std.AutoHashMapUnmanaged([id_size]u8, bool) = .empty;
        defer theirs.deinit(gpa);

        while (query.len != 0) {
            o.clearRetainingCapacity();

            const curr_bound = try self.decodeBound(&query);
            const mode_raw = try decodeVarInt(&query);

            const lower = prev_index;
            var upper = storage.findLowerBound(prev_index, storage_size, curr_bound);

            switch (mode_raw) {
                @intFromEnum(Mode.skip) => skip = true,
                @intFromEnum(Mode.fingerprint) => {
                    const their_fp = try takeBytes(&query, fingerprint_size);
                    const our_fp = storage.fingerprint(lower, upper);
                    if (!std.mem.eql(u8, their_fp, &our_fp)) {
                        try self.flushSkip(&o, gpa, &skip, prev_bound);
                        try self.splitRange(&o, gpa, lower, upper, curr_bound);
                    } else {
                        skip = true;
                    }
                },
                @intFromEnum(Mode.id_list) => {
                    const num = try decodeVarInt(&query);
                    if (num > query.len / id_size) return error.Malformed;
                    const ids = try takeBytes(&query, @intCast(num * id_size));

                    if (initiator) {
                        skip = true;
                        theirs.clearRetainingCapacity();
                        try theirs.ensureTotalCapacity(gpa, @intCast(num));
                        var i: usize = 0;
                        while (i < ids.len) : (i += id_size) {
                            theirs.putAssumeCapacity(ids[i..][0..id_size].*, false);
                        }
                        for (storage.items[lower..upper]) |item| {
                            if (theirs.getPtr(item.id)) |found| {
                                found.* = true;
                            } else {
                                try have.append(gpa, item.id);
                            }
                        }
                        // In the order they were listed, each once.
                        i = 0;
                        while (i < ids.len) : (i += id_size) {
                            const found = theirs.getPtr(ids[i..][0..id_size].*).?;
                            if (!found.*) {
                                try need.append(gpa, ids[i..][0..id_size].*);
                                found.* = true;
                            }
                        }
                    } else {
                        try self.flushSkip(&o, gpa, &skip, prev_bound);

                        // The ids are gathered before the bound is written,
                        // since the frame size limit can cut the walk short
                        // and move the bound down to where it stopped.
                        var end_bound = curr_bound;
                        var count: u64 = 0;
                        resp.clearRetainingCapacity();
                        var idx = lower;
                        while (idx < upper) : (idx += 1) {
                            if (self.exceeded(full.items.len + resp.items.len)) {
                                end_bound = Bound.ofItem(storage.items[idx]);
                                upper = idx;
                                break;
                            }
                            try resp.appendSlice(gpa, &storage.items[idx].id);
                            count += 1;
                        }

                        try self.appendBound(&o, gpa, end_bound);
                        try appendVarInt(&o, gpa, @intFromEnum(Mode.id_list));
                        try appendVarInt(&o, gpa, count);
                        try o.appendSlice(gpa, resp.items);

                        try full.appendSlice(gpa, o.items);
                        o.clearRetainingCapacity();
                    }
                },
                else => return error.Malformed,
            }

            if (self.exceeded(full.items.len + o.items.len)) {
                // Out of room: stop here and hand back everything from here
                // on as one fingerprint range, taken up in the next round.
                const remaining = storage.fingerprint(upper, storage_size);
                try self.appendBound(&full, gpa, Bound.infinity());
                try appendVarInt(&full, gpa, @intFromEnum(Mode.fingerprint));
                try full.appendSlice(gpa, &remaining);
                break;
            }
            try full.appendSlice(gpa, o.items);

            prev_index = upper;
            prev_bound = curr_bound;
        }

        return full.toOwnedSlice(gpa);
    }
};

/// The side that starts a reconciliation and learns the differences.
pub const Initiator = struct {
    engine: Engine,
    max_rounds: u32,
    rounds: u32 = 0,
    initiated: bool = false,

    /// `storage` must outlive the initiator and stay unchanged while it runs.
    pub fn init(storage: *const Storage, options: Options) Error!Initiator {
        return .{ .engine = try Engine.init(storage, options), .max_rounds = options.max_rounds };
    }

    /// The first message: the whole timestamp/id space split into ranges.
    /// The caller owns the returned bytes.
    pub fn initiate(self: *Initiator, gpa: std.mem.Allocator) Error![]u8 {
        if (self.initiated) return error.AlreadyInitiated;
        self.initiated = true;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        try out.append(gpa, protocol_version);
        self.engine.last_out = 0;
        try self.engine.splitRange(&out, gpa, 0, self.engine.storage.size(), Bound.infinity());
        return out.toOwnedSlice(gpa);
    }

    /// Processes the responder's message. Returns the ids found to differ in
    /// this round and the next message, or null once nothing is left to
    /// reconcile. With a frame size limit on either side an id can be
    /// reported in more than one round, as the reference notes; callers that
    /// cannot take duplicates should track what they have seen.
    pub fn reconcile(self: *Initiator, gpa: std.mem.Allocator, msg: []const u8) Error!Reconciled {
        if (!self.initiated) return error.NotInitiated;
        if (self.rounds >= self.max_rounds) return error.TooManyRounds;
        self.rounds += 1;

        var have: IdList = .empty;
        defer have.deinit(gpa);
        var need: IdList = .empty;
        defer need.deinit(gpa);
        const out = try self.engine.reconcileAux(gpa, msg, true, &have, &need);
        errdefer gpa.free(out);

        const have_owned = try have.toOwnedSlice(gpa);
        errdefer gpa.free(have_owned);
        const need_owned = try need.toOwnedSlice(gpa);

        if (out.len == 1) {
            gpa.free(out);
            return .{ .message = null, .have = have_owned, .need = need_owned };
        }
        return .{ .message = out, .have = have_owned, .need = need_owned };
    }
};

/// The side that answers. It learns nothing about the differences itself;
/// it only replies so the initiator can.
pub const Responder = struct {
    engine: Engine,

    /// `storage` must outlive the responder and stay unchanged while it runs.
    pub fn init(storage: *const Storage, options: Options) Error!Responder {
        return .{ .engine = try Engine.init(storage, options) };
    }

    /// The reply to one initiator message. The caller owns the returned bytes.
    /// A message in another protocol version from 0x60 to 0x6F gets the
    /// single byte `0x61` back, so the initiator can fall back to version 1.
    pub fn reconcile(self: *Responder, gpa: std.mem.Allocator, msg: []const u8) Error![]u8 {
        var unused_have: IdList = .empty;
        var unused_need: IdList = .empty;
        return self.engine.reconcileAux(gpa, msg, false, &unused_have, &unused_need);
    }
};

/// Hex-encodes a message for a NIP-77 envelope. The caller owns the result.
pub fn toHex(gpa: std.mem.Allocator, msg: []const u8) Error![]u8 {
    return hex.encode(gpa, msg);
}

/// Decodes a hex message from a NIP-77 envelope. The caller owns the result.
pub fn fromHex(gpa: std.mem.Allocator, text: []const u8) (Error || hex.Error)![]u8 {
    return hex.decode(gpa, text);
}

// -- tests -------------------------------------------------------------------

const testing = std.testing;

test "nip77: varint encodes base-128 big-endian with continuation bits" {
    const gpa = testing.allocator;
    const cases = [_]struct { n: u64, bytes: []const u8 }{
        .{ .n = 0, .bytes = &.{0x00} },
        .{ .n = 1, .bytes = &.{0x01} },
        .{ .n = 127, .bytes = &.{0x7f} },
        .{ .n = 128, .bytes = &.{ 0x81, 0x00 } },
        .{ .n = 255, .bytes = &.{ 0x81, 0x7f } },
        .{ .n = 16384, .bytes = &.{ 0x81, 0x80, 0x00 } },
        .{ .n = max_timestamp, .bytes = &.{ 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f } },
    };
    for (cases) |case| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try appendVarInt(&out, gpa, case.n);
        try testing.expectEqualSlices(u8, case.bytes, out.items);
        var in: []const u8 = case.bytes;
        try testing.expectEqual(case.n, try decodeVarInt(&in));
        try testing.expectEqual(@as(usize, 0), in.len);
    }
    // Truncated, too wide for 64 bits, and a run of continuation bytes.
    var short: []const u8 = &.{ 0x81, 0x80 };
    try testing.expectError(error.Malformed, decodeVarInt(&short));
    var wide: []const u8 = &.{ 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
    try testing.expectError(error.Malformed, decodeVarInt(&wide));
    var endless: []const u8 = &([_]u8{0x80} ** 64);
    try testing.expectError(error.Malformed, decodeVarInt(&endless));
}

test "nip77: fingerprint of the empty set is sha256 of 32 zero bytes and a zero count" {
    // The first 16 bytes of sha256 over 33 zero bytes.
    const want = try hex.decodeFixed(16, "7f9c9e31ac8256ca2f258583df262dbc");
    try testing.expectEqualSlices(u8, &want, &fingerprintOf(0, 0));
}

test "nip77: the id sum is little-endian and wraps mod 2^256" {
    const gpa = testing.allocator;
    const a: Item = .{ .created_at = 1, .id = [_]u8{0xff} ** 32 };
    var b: Item = .{ .created_at = 2, .id = [_]u8{0} ** 32 };
    b.id[0] = 2;
    var storage = try Storage.fromSlice(gpa, &.{ b, a });
    defer storage.deinit(gpa);
    // (2^256 - 1) + 2 = 1 mod 2^256.
    try testing.expectEqualSlices(u8, &fingerprintOf(1, 2), &storage.fingerprint(0, 2));
    try testing.expectEqualSlices(u8, &fingerprintOf(2, 1), &storage.fingerprint(1, 2));
}

test "nip77: storage rejects duplicates and the infinity timestamp" {
    const gpa = testing.allocator;
    const it: Item = .{ .created_at = 5, .id = [_]u8{7} ** 32 };
    try testing.expectError(error.DuplicateItem, Storage.fromSlice(gpa, &.{ it, it }));
    const inf: Item = .{ .created_at = max_timestamp, .id = [_]u8{7} ** 32 };
    try testing.expectError(error.InvalidTimestamp, Storage.fromSlice(gpa, &.{inf}));
}

test "nip77: minimal bound uses the shortest distinguishing id prefix" {
    var p: Item = .{ .created_at = 10, .id = [_]u8{0xaa} ** 32 };
    var c: Item = p;
    c.id[2] = 0xab;
    const b = minimalBound(p, c);
    try testing.expectEqual(@as(u8, 3), b.len);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xaa, 0xab }, b.id[0..3]);
    p.created_at = 9;
    try testing.expectEqual(@as(u8, 0), minimalBound(p, c).len);
}

// The sets for the transcript tests, built the way the recording script built
// them for the JavaScript reference: id = sha256("nip77-" ++ i), timestamp =
// 1700000000 + (id[1] << 8 | id[2]) % spread, and id[0] % 10 decides
// membership (0: initiator only, 1: responder only, otherwise both).
fn transcriptSets(gpa: std.mem.Allocator, n: usize, spread: u64) !struct { a: []Item, b: []Item } {
    var a: std.ArrayList(Item) = .empty;
    defer a.deinit(gpa);
    var b: std.ArrayList(Item) = .empty;
    defer b.deinit(gpa);
    for (0..n) |i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "nip77-{d}", .{i}) catch unreachable;
        var id: [32]u8 = undefined;
        Sha256.hash(name, &id, .{});
        const ts = 1700000000 + ((@as(u64, id[1]) << 8 | id[2]) % spread);
        const m = id[0] % 10;
        if (m != 1) try a.append(gpa, .{ .created_at = ts, .id = id });
        if (m != 0) try b.append(gpa, .{ .created_at = ts, .id = id });
    }
    const out_a = try a.toOwnedSlice(gpa);
    errdefer gpa.free(out_a);
    return .{ .a = out_a, .b = try b.toOwnedSlice(gpa) };
}

fn sortIds(ids: [][32]u8) void {
    std.mem.sort([32]u8, ids, {}, struct {
        fn lt(_: void, x: [32]u8, y: [32]u8) bool {
            return std.mem.order(u8, &x, &y) == .lt;
        }
    }.lt);
}

fn dedupSorted(gpa: std.mem.Allocator, ids: []const [32]u8) ![][32]u8 {
    const copy = try gpa.dupe([32]u8, ids);
    defer gpa.free(copy);
    sortIds(copy);
    var out: IdList = .empty;
    errdefer out.deinit(gpa);
    for (copy, 0..) |id, i| {
        if (i > 0 and std.mem.eql(u8, &copy[i - 1], &id)) continue;
        try out.append(gpa, id);
    }
    return out.toOwnedSlice(gpa);
}

/// sha256 over sorted, deduplicated ids, as the recording script computed it.
fn idSetDigest(ids: []const [32]u8) [32]u8 {
    var h = Sha256.init(.{});
    for (ids) |id| h.update(&id);
    return h.finalResult();
}

const Transcript = struct {
    n: usize,
    spread: u64,
    frame_a: u64,
    frame_b: u64,
    rounds: usize,
    /// sha256 over every message in order, each prefixed by its length as a
    /// little-endian u32.
    transcript: []const u8,
    have: usize,
    need: usize,
    have_digest: []const u8,
    need_digest: []const u8,
    /// The full messages, kept for the smallest case.
    msgs: []const []const u8 = &.{},
};

// Recorded by driving the JavaScript reference (hoytech/negentropy,
// js/Negentropy.js) on the sets above, initiator against responder.
const transcripts = [_]Transcript{
    .{
        .n = 40,
        .spread = 5,
        .frame_a = 0,
        .frame_b = 0,
        .rounds = 1,
        .transcript = "3db366499ac52e94fd04bcbbbf9539a375c5e28dbb513f5c476edb8158650dd3",
        .have = 2,
        .need = 3,
        .have_digest = "5f0749dee001511ffd2fef2c94c0fe36f812edbc45e20b097bce71f7b76682a6",
        .need_digest = "531d475a87f3f54b2929cf0b47734999c0c7fcb0fc09e73ca1a1c9f2f700629b",
        .msgs = &.{
            "6186aacfe20101b101eddce105c245ab558b55c566058fe60e02012701ced9f3487b1bc4c13d5d376df0edea7c01019e01ea716916b6a9badcdb68d200c01652a0020130016270350d49a9c3cf90c2af38ec9603310101cf013b358fe1c6cbdf3a4aca010fe030e5f30101ea01b2ac5442030bcf84a73066be426a896d0200014a2b1777fb62b8ba9850a69cb2ec4ed501017b01b969f6f7213a60d61837529e605835c10101f7014a140444c5793793b87b18b8d753475802011701ebe34141be9b7cfb500a32b25cac372201012c01190a09f5fddc185721441e20e26ae08801013701d6ea4daf04a1d2ea345edf75fb79881101014d01c8ad235b9bf1e8e9f71e459f4544358e01016401310c5e744bdb5be8b43581365dad47fa0101cd01a16192a9509bee621a7c790928793c42000001c7b266574aee54fdb37def7fb06de781",
            "6186aacfe20101b1020403a23a313374a1dd3dbe8d7c300bca6b9de41bae5693158eec0257e18982df2a431c9dceccb6a038b4e432fe58716af2a10f62bd49bf1d48430bc66a1fc4e7826969a5d777ba8d8ea842bc60034eebe54de3cae58077585f053baca19319065779a4428cdba664c81ef6a7072cd6ebea7011cc4a6aa1e9e360cd0ed109e038b70201270001019e02022795395a1ac36d50bac1abeef99e46b65b84b7be1ce76b4769495729d5a534674e2f7cd7b206abd2d9005a255bb4eaee6d7137b862f56c3c2ffda4b5f274a6cb020130000101cf0205308faef443f1e14af98e88b6d0a44cdb7f791742937921952a7cf4abf058cc113b402159f2ea35d8eb6cbd38f99687d0da90901142c11dda773dec60713c189460c4513867e79dc971f05fab3711c77730826007eab0cb339ce4f756337ffe616fd9c3939c65cb11629e421f4561cece064fec0060b127cd1523d481a7b8bff579b8b2d6f4ab034ff47131f788d4f520c2a7d8abac31f15322f4abfa1501e647030164000101cd0201b3ce5d61ff96693daedb716c9ba147187b21e719596aa886b93e32074226113b",
        },
    },
    .{ .n = 300, .spread = 1, .frame_a = 0, .frame_b = 0, .rounds = 1, .transcript = "91dff0c72d0d5f1c10cc08a32ce8e2082eb4e1b14503606900eaf4eb53755a59", .have = 27, .need = 23, .have_digest = "e3569514ce7bcf4faf9ce40b85ef7b1607f956923714d1658d02da3a09b01e34", .need_digest = "7e55a066d801852b5e48291e2e08ea6eb30f8ed35aa7df18b291271275d0d9a3" },
    .{ .n = 3000, .spread = 50, .frame_a = 0, .frame_b = 0, .rounds = 2, .transcript = "a83ce5573db2db23b75e14427132def31a035714f4b556a90682f115d4ee9177", .have = 284, .need = 320, .have_digest = "9278abba4d5e2f6220e4e99e935fa389ba4ee81b09e989db31db573d23bf6a5e", .need_digest = "0adb7ff984d4a7d36a189c67e96934398784bb78eb9e065be65c03399707ff3b" },
    .{ .n = 20000, .spread = 20000, .frame_a = 4096, .frame_b = 4096, .rounds = 205, .transcript = "ae6c70ba1322e8dfbe601f05e6d3af492363793ddef94e6afd4e5f7c9588837e", .have = 1950, .need = 2072, .have_digest = "e805f8a1b811ba08fe85e44d298b865aa1c3d6f3e034b64efa1f724e0d79f984", .need_digest = "8598e8dc27a4486a8e19851545b5f7aed3d57ad16af1fa7ac242dff11c08a688" },
    .{ .n = 20000, .spread = 3, .frame_a = 0, .frame_b = 5000, .rounds = 40, .transcript = "21e9bfc21f9af54ddc4767f9c7f8d829779837853c5cae168aa1e89222d37478", .have = 1950, .need = 2072, .have_digest = "e805f8a1b811ba08fe85e44d298b865aa1c3d6f3e034b64efa1f724e0d79f984", .need_digest = "8598e8dc27a4486a8e19851545b5f7aed3d57ad16af1fa7ac242dff11c08a688" },
};

fn hashMessage(h: *Sha256, msg: []const u8) void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(msg.len), .little);
    h.update(&len);
    h.update(msg);
}

const SyncOutcome = struct {
    rounds: usize,
    /// Sorted and deduplicated.
    have: [][32]u8,
    need: [][32]u8,
    max_query: usize,
    max_reply: usize,
    transcript: [32]u8,

    fn deinit(self: *SyncOutcome, gpa: std.mem.Allocator) void {
        gpa.free(self.have);
        gpa.free(self.need);
    }
};

/// Runs a whole reconciliation in process, initiator on `a`, responder on `b`.
fn syncInProcess(gpa: std.mem.Allocator, a: *const Storage, b: *const Storage, fa: u64, fb: u64, expect_msgs: []const []const u8) !SyncOutcome {
    var client = try Initiator.init(a, .{ .frame_size_limit = fa });
    var server = try Responder.init(b, .{ .frame_size_limit = fb });
    var have: IdList = .empty;
    defer have.deinit(gpa);
    var need: IdList = .empty;
    defer need.deinit(gpa);
    var h = Sha256.init(.{});
    var rounds: usize = 0;
    var max_query: usize = 0;
    var max_reply: usize = 0;
    var msg_index: usize = 0;
    var q = try client.initiate(gpa);
    while (true) {
        // `q` is reassigned below, so free this round's message by its own name.
        const sent = q;
        defer gpa.free(sent);
        max_query = @max(max_query, q.len);
        hashMessage(&h, q);
        try expectMessage(gpa, expect_msgs, msg_index, q);
        msg_index += 1;

        const reply = try server.reconcile(gpa, q);
        defer gpa.free(reply);
        max_reply = @max(max_reply, reply.len);
        hashMessage(&h, reply);
        try expectMessage(gpa, expect_msgs, msg_index, reply);
        msg_index += 1;

        rounds += 1;
        var r = try client.reconcile(gpa, reply);
        defer r.deinit(gpa);
        try have.appendSlice(gpa, r.have);
        try need.appendSlice(gpa, r.need);
        q = r.message orelse break;
        r.message = null;
    }
    const have_out = try dedupSorted(gpa, have.items);
    errdefer gpa.free(have_out);
    return .{
        .rounds = rounds,
        .have = have_out,
        .need = try dedupSorted(gpa, need.items),
        .max_query = max_query,
        .max_reply = max_reply,
        .transcript = h.finalResult(),
    };
}

fn expectMessage(gpa: std.mem.Allocator, msgs: []const []const u8, i: usize, got: []const u8) !void {
    if (i >= msgs.len) return;
    const want = try fromHex(gpa, msgs[i]);
    defer gpa.free(want);
    try testing.expectEqualSlices(u8, want, got);
}

test "nip77: messages match transcripts recorded from the reference implementation" {
    const gpa = testing.allocator;
    for (transcripts) |t| {
        const sets = try transcriptSets(gpa, t.n, t.spread);
        defer gpa.free(sets.a);
        defer gpa.free(sets.b);
        var sa = try Storage.fromSlice(gpa, sets.a);
        defer sa.deinit(gpa);
        var sb = try Storage.fromSlice(gpa, sets.b);
        defer sb.deinit(gpa);

        var out = try syncInProcess(gpa, &sa, &sb, t.frame_a, t.frame_b, t.msgs);
        defer out.deinit(gpa);
        try testing.expectEqual(t.rounds, out.rounds);
        try testing.expectEqual(try hex.decodeFixed(32, t.transcript), out.transcript);
        try testing.expectEqual(t.have, out.have.len);
        try testing.expectEqual(t.need, out.need.len);
        try testing.expectEqual(try hex.decodeFixed(32, t.have_digest), idSetDigest(out.have));
        try testing.expectEqual(try hex.decodeFixed(32, t.need_digest), idSetDigest(out.need));
    }
}

const RandomSets = struct {
    a: []Item,
    b: []Item,
    /// Sorted.
    only_a: [][32]u8,
    only_b: [][32]u8,

    fn deinit(self: *RandomSets, gpa: std.mem.Allocator) void {
        gpa.free(self.a);
        gpa.free(self.b);
        gpa.free(self.only_a);
        gpa.free(self.only_b);
    }
};

/// `n` random items; each is shared with probability `overlap_pct`/100 and
/// otherwise goes to one side or the other.
fn randomSets(gpa: std.mem.Allocator, seed: u64, n: usize, overlap_pct: u64, spread: u64) !RandomSets {
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var a: std.ArrayList(Item) = .empty;
    defer a.deinit(gpa);
    var b: std.ArrayList(Item) = .empty;
    defer b.deinit(gpa);
    var only_a: IdList = .empty;
    defer only_a.deinit(gpa);
    var only_b: IdList = .empty;
    defer only_b.deinit(gpa);
    for (0..n) |_| {
        var item: Item = .{ .created_at = 1_700_000_000 + rand.uintLessThan(u64, spread), .id = undefined };
        rand.bytes(&item.id);
        if (rand.uintLessThan(u64, 100) < overlap_pct) {
            try a.append(gpa, item);
            try b.append(gpa, item);
        } else if (rand.boolean()) {
            try a.append(gpa, item);
            try only_a.append(gpa, item.id);
        } else {
            try b.append(gpa, item);
            try only_b.append(gpa, item.id);
        }
    }
    sortIds(only_a.items);
    sortIds(only_b.items);
    var out: RandomSets = .{ .a = &.{}, .b = &.{}, .only_a = &.{}, .only_b = &.{} };
    errdefer out.deinit(gpa);
    out.a = try a.toOwnedSlice(gpa);
    out.b = try b.toOwnedSlice(gpa);
    out.only_a = try only_a.toOwnedSlice(gpa);
    out.only_b = try only_b.toOwnedSlice(gpa);
    return out;
}

fn expectIdsEqual(want: []const [32]u8, got: []const [32]u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualSlices(u8, &w, &g);
}

test "nip77: randomized sets reconcile to exactly their symmetric difference" {
    const gpa = testing.allocator;
    const sizes = [_]usize{ 0, 1, 2, 31, 32, 33, 500, 5_000, 50_000 };
    const overlaps = [_]u64{ 0, 50, 90, 99, 100 };
    const seeds = [_]u64{ 1, 2, 3 };
    for (sizes) |n| {
        for (overlaps) |ov| {
            for (seeds) |seed| {
                // A narrow spread forces many equal timestamps, and so bounds
                // that need an id prefix.
                const spread: u64 = if (seed == 2) 3 else n + 1;
                var sets = try randomSets(gpa, seed *% 7919 +% n *% 31 +% ov, n, ov, spread);
                defer sets.deinit(gpa);
                var sa = try Storage.fromSlice(gpa, sets.a);
                defer sa.deinit(gpa);
                var sb = try Storage.fromSlice(gpa, sets.b);
                defer sb.deinit(gpa);
                var out = try syncInProcess(gpa, &sa, &sb, 0, 0, &.{});
                defer out.deinit(gpa);
                try expectIdsEqual(sets.only_a, out.have);
                try expectIdsEqual(sets.only_b, out.need);
            }
        }
    }
}

test "nip77: frame size limits are respected and still find the whole difference" {
    const gpa = testing.allocator;
    var sets = try randomSets(gpa, 42, 30_000, 80, 30_000);
    defer sets.deinit(gpa);
    var sa = try Storage.fromSlice(gpa, sets.a);
    defer sa.deinit(gpa);
    var sb = try Storage.fromSlice(gpa, sets.b);
    defer sb.deinit(gpa);
    const limits = [_][2]u64{ .{ 4096, 4096 }, .{ 0, 4096 }, .{ 4096, 0 }, .{ 10_000, 60_000 } };
    for (limits) |l| {
        var out = try syncInProcess(gpa, &sa, &sb, l[0], l[1], &.{});
        defer out.deinit(gpa);
        try expectIdsEqual(sets.only_a, out.have);
        try expectIdsEqual(sets.only_b, out.need);
        if (l[0] != 0) try testing.expect(out.max_query <= l[0]);
        if (l[1] != 0) try testing.expect(out.max_reply <= l[1]);
        try testing.expect(out.rounds > 1);
    }
    try testing.expectError(error.FrameSizeLimitTooSmall, Initiator.init(&sa, .{ .frame_size_limit = 4095 }));
    try testing.expectError(error.FrameSizeLimitTooSmall, Responder.init(&sa, .{ .frame_size_limit = 1 }));
}

test "nip77: malformed messages are rejected, never panic" {
    const gpa = testing.allocator;
    var sets = try randomSets(gpa, 9, 200, 50, 200);
    defer sets.deinit(gpa);
    var sa = try Storage.fromSlice(gpa, sets.a);
    defer sa.deinit(gpa);
    var server = try Responder.init(&sa, .{});

    const long_prefix = [_]u8{ 0x61, 0x00, 0x21 } ++ [_]u8{0} ** 33 ++ [_]u8{0x00};
    const bad = [_]struct { msg: []const u8, err: Error }{
        .{ .msg = "", .err = error.Malformed },
        .{ .msg = &.{0x00}, .err = error.InvalidProtocolVersion },
        .{ .msg = &.{0x70}, .err = error.InvalidProtocolVersion },
        // Bound cut short, mode missing, unknown mode.
        .{ .msg = &.{ 0x61, 0x00 }, .err = error.Malformed },
        .{ .msg = &.{ 0x61, 0x00, 0x00 }, .err = error.Malformed },
        .{ .msg = &.{ 0x61, 0x00, 0x00, 0x03 }, .err = error.Malformed },
        // Id prefix longer than 32 bytes.
        .{ .msg = &long_prefix, .err = error.Malformed },
        // Fingerprint shorter than 16 bytes.
        .{ .msg = &.{ 0x61, 0x00, 0x00, 0x01, 0xaa, 0xbb }, .err = error.Malformed },
        // Id lists claiming more ids than the message holds.
        .{ .msg = &.{ 0x61, 0x00, 0x00, 0x02, 0x8f, 0xff, 0xff, 0xff, 0x7f }, .err = error.Malformed },
        .{ .msg = &.{ 0x61, 0x00, 0x00, 0x02, 0x01, 0xaa }, .err = error.Malformed },
        // An overlong varint.
        .{ .msg = &.{ 0x61, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 }, .err = error.Malformed },
    };
    for (bad) |case| {
        try testing.expectError(case.err, server.reconcile(gpa, case.msg));
        var client = try Initiator.init(&sa, .{});
        gpa.free(try client.initiate(gpa));
        try testing.expectError(case.err, client.reconcile(gpa, case.msg));
    }

    // Another protocol version gets a bare version-1 byte back; the initiator
    // refuses one it cannot speak.
    const reply = try server.reconcile(gpa, &.{0x62});
    defer gpa.free(reply);
    try testing.expectEqualSlices(u8, &.{protocol_version}, reply);
    var client = try Initiator.init(&sa, .{});
    try testing.expectError(error.NotInitiated, client.reconcile(gpa, &.{0x61}));
    gpa.free(try client.initiate(gpa));
    try testing.expectError(error.AlreadyInitiated, client.initiate(gpa));
    try testing.expectError(error.UnsupportedProtocolVersion, client.reconcile(gpa, &.{0x62}));

    // Random bytes after a valid version byte: any outcome but a crash, a
    // leak or a hang. Out-of-order bounds and saturating timestamps land here.
    var prng = std.Random.DefaultPrng.init(77);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    var limited = try Responder.init(&sa, .{ .frame_size_limit = 4096 });
    for (0..20_000) |_| {
        const len = rand.uintLessThan(usize, buf.len);
        rand.bytes(buf[0..len]);
        if (len > 0) buf[0] = protocol_version;
        if (server.reconcile(gpa, buf[0..len])) |out| gpa.free(out) else |_| {}
        if (limited.reconcile(gpa, buf[0..len])) |out| {
            try testing.expect(out.len <= 4096);
            gpa.free(out);
        } else |_| {}
        var c = try Initiator.init(&sa, .{ .frame_size_limit = 4096 });
        gpa.free(try c.initiate(gpa));
        if (c.reconcile(gpa, buf[0..len])) |r| {
            var rr = r;
            rr.deinit(gpa);
        } else |_| {}
    }
}

test "nip77: a peer that never converges hits the round limit" {
    const gpa = testing.allocator;
    var sets = try randomSets(gpa, 5, 10, 0, 10);
    defer sets.deinit(gpa);
    var sa = try Storage.fromSlice(gpa, sets.a);
    defer sa.deinit(gpa);
    var client = try Initiator.init(&sa, .{ .max_rounds = 5 });
    gpa.free(try client.initiate(gpa));
    // A reply that disagrees about the whole space every time.
    const stubborn = [_]u8{ 0x61, 0x00, 0x00, 0x01 } ++ [_]u8{0xee} ** 16;
    for (0..5) |_| {
        var r = try client.reconcile(gpa, &stubborn);
        defer r.deinit(gpa);
        try testing.expect(r.message != null);
    }
    try testing.expectError(error.TooManyRounds, client.reconcile(gpa, &stubborn));
}

test "nip77: 100k against 100k with 1 percent different reconciles in a few rounds" {
    const gpa = testing.allocator;
    // 101,000 items, 98 percent shared: about 100,000 on each side with
    // about 1,000 (1 percent) unique to each.
    var sets = try randomSets(gpa, 100, 101_000, 98, 1_000_000);
    defer sets.deinit(gpa);
    var sa = try Storage.fromSlice(gpa, sets.a);
    defer sa.deinit(gpa);
    var sb = try Storage.fromSlice(gpa, sets.b);
    defer sb.deinit(gpa);
    var out = try syncInProcess(gpa, &sa, &sb, 0, 0, &.{});
    defer out.deinit(gpa);
    try expectIdsEqual(sets.only_a, out.have);
    try expectIdsEqual(sets.only_b, out.need);
    try testing.expect(out.rounds <= 4);
}

test "nip77: storage built from the store reconciles against a slice" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buf);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/nip77.mdb", .{dir_buf[0..dir_len]});
    var s = try store_mod.Store.open(path.ptr, .{});
    defer s.deinit();

    var local: std.ArrayList(Item) = .empty;
    defer local.deinit(gpa);
    for (0..100) |i| {
        var id = [_]u8{0} ** 32;
        id[0] = @intCast(i);
        const ev: @import("event.zig").Event = .{
            .id = id,
            .pubkey = [_]u8{1} ** 32,
            .created_at = @intCast(1000 + i / 3),
            .kind = 1,
            .tags = &.{},
            .content = "",
            .sig = [_]u8{0} ** 64,
        };
        if (i % 10 != 0) _ = try s.putEvent(gpa, ev);
        if (i % 10 != 1) try local.append(gpa, .{ .created_at = @intCast(ev.created_at), .id = id });
    }

    var from_store = try Storage.fromStore(gpa, &s, .{}, .{});
    defer from_store.deinit(gpa);
    try testing.expectEqual(@as(usize, 90), from_store.size());
    var from_slice = try Storage.fromSlice(gpa, local.items);
    defer from_slice.deinit(gpa);

    var out = try syncInProcess(gpa, &from_slice, &from_store, 0, 0, &.{});
    defer out.deinit(gpa);
    try testing.expectEqual(@as(usize, 10), out.have.len);
    try testing.expectEqual(@as(usize, 10), out.need.len);
    for (out.have) |id| try testing.expectEqual(@as(u8, 0), id[0] % 10);
    for (out.need) |id| try testing.expectEqual(@as(u8, 1), id[0] % 10);
}

test "nip77: with default options no message is too large for the wire parser" {
    // The NIP-77 envelope parser refuses a hex payload past
    // `message.max_neg_hex_len`. A peer on default options must never produce
    // one, whichever side holds the large set.
    const gpa = testing.allocator;
    const many = try gpa.alloc(Item, 20_000);
    defer gpa.free(many);
    for (many, 0..) |*it, i| {
        it.* = .{ .created_at = i, .id = undefined };
        Sha256.hash(std.mem.asBytes(&i), &it.id, .{});
    }
    var full = try Storage.fromSlice(gpa, many);
    defer full.deinit(gpa);
    var empty = try Storage.fromSlice(gpa, &.{});
    defer empty.deinit(gpa);

    for ([_][2]*const Storage{ .{ &full, &empty }, .{ &empty, &full } }) |pair| {
        var client = try Initiator.init(pair[0], .{});
        var server = try Responder.init(pair[1], .{});
        var learned: usize = 0;
        var q = try client.initiate(gpa);
        while (true) {
            const sent = q;
            defer gpa.free(sent);
            try testing.expect(2 * sent.len <= message.max_neg_hex_len);
            const reply = try server.reconcile(gpa, sent);
            defer gpa.free(reply);
            try testing.expect(2 * reply.len <= message.max_neg_hex_len);
            var r = try client.reconcile(gpa, reply);
            defer r.deinit(gpa);
            learned += r.have.len + r.need.len;
            q = r.message orelse break;
            r.message = null;
        }
        try testing.expect(learned >= many.len);
    }
}

test "nip77: hex round trip" {
    const gpa = testing.allocator;
    const h = try toHex(gpa, &.{ 0x61, 0x00, 0xab });
    defer gpa.free(h);
    try testing.expectEqualStrings("6100ab", h);
    const b = try fromHex(gpa, h);
    defer gpa.free(b);
    try testing.expectEqualSlices(u8, &.{ 0x61, 0x00, 0xab }, b);
    try testing.expectError(error.InvalidHex, fromHex(gpa, "61z0"));
}
