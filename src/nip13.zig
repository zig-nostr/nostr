//! NIP-13 proof of work for event IDs.
//!
//! `difficulty` counts the leading zero bits of an id, `committedTarget`
//! reads the target an event commits to in its nonce tag, and `mine` searches
//! for a nonce that reaches a target difficulty.
//!
//! The miner puts the nonce tag last, so the canonical serialization is
//! `prefix ++ nonce digits ++ suffix`. The prefix is hashed once into a
//! SHA-256 midstate. Each attempt copies that state and hashes only the
//! partial block left over from the prefix, the digits and the suffix. The
//! nonce is a fixed number of decimal digits for the whole run, so the
//! layout of those bytes never moves.

const std = @import("std");
const event = @import("event.zig");
const hex = @import("hex.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Width of the decimal nonce. Leading zeros are kept so the width is fixed.
const nonce_digits = 10;
const nonce_space: u64 = 10_000_000_000;

/// Number of leading zero bits in `id`.
pub fn difficulty(id: [32]u8) u32 {
    var bits: u32 = 0;
    for (id) |b| {
        if (b == 0) {
            bits += 8;
            continue;
        }
        bits += @clz(b);
        break;
    }
    return bits;
}

/// The target difficulty committed to by a `["nonce", n, target]` tag, or
/// null when there is no such tag or the target is not a number.
pub fn committedTarget(ev: event.Event) ?u32 {
    for (ev.tags) |tag| {
        if (tag.len >= 3 and std.mem.eql(u8, tag[0], "nonce")) {
            return std.fmt.parseInt(u32, tag[2], 10) catch null;
        }
    }
    return null;
}

pub const MineError = error{
    /// The cancel flag was set before a nonce was found.
    Cancelled,
    /// The deadline passed before a nonce was found.
    Timeout,
    /// Every nonce in the space was tried.
    Exhausted,
    /// The target is above 256 bits.
    InvalidTarget,
    ThreadSpawnFailed,
} || std.mem.Allocator.Error;

pub const Options = struct {
    /// Target number of leading zero bits (at most 256).
    target: u32,
    /// Worker threads. 0 is treated as 1.
    threads: u32 = 1,
    /// Set to true from any thread to stop the search.
    cancel: ?*const std.atomic.Value(bool) = null,
    /// Stop with `error.Timeout` once this much time has passed. A value
    /// too large for the clock means no deadline.
    timeout_ms: ?u64 = null,
    /// When set, workers add the hashes they computed (flushed in batches).
    attempts: ?*std.atomic.Value(u64) = null,
};

/// An unsigned event with its proof of work. The `sig` of `event` is zero.
/// Free with `deinit`.
pub const Mined = struct {
    event: event.Event,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Mined) void {
        self.arena.deinit();
    }
};

/// Unsigned event fields to mine.
pub const Template = struct {
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const event.Tag = &.{},
    content: []const u8 = "",
};

const Shared = struct {
    /// Bytes of the canonical serialization before the nonce digits.
    prefix: []const u8,
    /// Bytes after the nonce digits.
    suffix: []const u8,
    target: u32,
    threads: u32,
    cancel: ?*const std.atomic.Value(bool),
    deadline_ms: ?i64,
    io: std.Io,
    attempts: ?*std.atomic.Value(u64),
    stop: std.atomic.Value(bool) = .init(false),
    found: std.atomic.Value(bool) = .init(false),
    timed_out: std.atomic.Value(bool) = .init(false),
    nonce: u64 = 0,
    mutex: std.atomic.Mutex = .unlocked,
};

/// The bytes a worker hashes after the midstate: what is left of the prefix
/// past its last whole block, the nonce digits, and the suffix.
fn tailLen(sh: *const Shared) usize {
    return sh.prefix.len % 64 + nonce_digits + sh.suffix.len;
}

/// Mines nonces `index`, `index + threads`, ... into its own `tail`, which
/// `mine` allocated before any worker started. Nothing in here can fail, so
/// a worker never stops on its own while the others carry on.
fn worker(sh: *Shared, index: u32, tail: []u8) void {
    const full = sh.prefix.len / 64 * 64;
    var mid = Sha256.init(.{});
    mid.update(sh.prefix[0..full]);
    const rem = sh.prefix[full..];

    std.debug.assert(tail.len == tailLen(sh));
    @memcpy(tail[0..rem.len], rem);
    @memcpy(tail[rem.len + nonce_digits ..], sh.suffix);
    const digits = tail[rem.len..][0..nonce_digits];

    var n: u64 = index;
    const stride: u64 = sh.threads;
    var batch: u64 = 0;
    while (n < nonce_space) : (n += stride) {
        if (batch & 1023 == 1023) {
            if (sh.attempts) |c| _ = c.fetchAdd(1024, .monotonic);
            if (sh.stop.load(.monotonic)) return;
            if (sh.cancel) |c| if (c.load(.monotonic)) {
                sh.stop.store(true, .release);
                return;
            };
            if (sh.deadline_ms) |d| {
                if (std.Io.Timestamp.now(sh.io, .awake).toMilliseconds() >= d) {
                    sh.timed_out.store(true, .release);
                    sh.stop.store(true, .release);
                    return;
                }
            }
        }
        batch += 1;

        var v = n;
        var i: usize = nonce_digits;
        while (i > 0) {
            i -= 1;
            digits[i] = '0' + @as(u8, @intCast(v % 10));
            v /= 10;
        }

        var h = mid;
        h.update(tail);
        var id: [32]u8 = undefined;
        h.final(&id);
        if (difficulty(id) >= sh.target) {
            while (!sh.mutex.tryLock()) std.atomic.spinLoopHint();
            if (!sh.found.load(.acquire)) {
                sh.nonce = n;
                sh.found.store(true, .release);
            }
            sh.mutex.unlock();
            sh.stop.store(true, .release);
            return;
        }
    }
}

/// Searches for a nonce so the id of `template` plus a trailing
/// `["nonce", "<n>", "<target>"]` tag has at least `opts.target` leading zero
/// bits. Any nonce tag already in the template is replaced. The nonce tag is
/// the last tag of the result.
pub fn mine(
    allocator: std.mem.Allocator,
    io: std.Io,
    template: Template,
    opts: Options,
) MineError!Mined {
    if (opts.target > 256) return error.InvalidTarget;

    var mined: Mined = .{ .event = undefined, .arena = .init(allocator) };
    errdefer mined.arena.deinit();
    const arena = mined.arena.allocator();

    var target_buf: [8]u8 = undefined;
    const target_str = std.fmt.bufPrint(&target_buf, "{d}", .{opts.target}) catch unreachable;
    const target_copy = try arena.dupe(u8, target_str);

    var tags: std.ArrayList(event.Tag) = .empty;
    for (template.tags) |t| {
        if (t.len > 0 and std.mem.eql(u8, t[0], "nonce")) continue;
        try tags.append(arena, t);
    }
    const nonce_str = try arena.alloc(u8, nonce_digits);
    @memset(nonce_str, '0');
    const nonce_tag = try arena.alloc([]const u8, 3);
    nonce_tag[0] = "nonce";
    nonce_tag[1] = nonce_str;
    nonce_tag[2] = target_copy;
    try tags.append(arena, nonce_tag);
    const all_tags = tags.items;

    // The serialization with a ten digit nonce, and with an empty nonce. They
    // first differ where the digits start.
    const ser = try event.serializeCanonical(allocator, template.pubkey, template.created_at, template.kind, all_tags, template.content);
    defer allocator.free(ser);
    nonce_tag[1] = "";
    const ser_empty = try event.serializeCanonical(allocator, template.pubkey, template.created_at, template.kind, all_tags, template.content);
    defer allocator.free(ser_empty);
    nonce_tag[1] = nonce_str;
    const start = std.mem.indexOfDiff(u8, ser, ser_empty).?;

    const threads: u32 = @max(opts.threads, 1);
    var sh: Shared = .{
        .prefix = ser[0..start],
        .suffix = ser[start + nonce_digits ..],
        .target = opts.target,
        .threads = threads,
        .cancel = opts.cancel,
        // A timeout past what the clock can count is no deadline at all.
        .deadline_ms = if (opts.timeout_ms) |t|
            std.Io.Timestamp.now(io, .awake).toMilliseconds() +| (std.math.cast(i64, t) orelse std.math.maxInt(i64))
        else
            null,
        .io = io,
        .attempts = opts.attempts,
    };

    const handles = try allocator.alloc(std.Thread, threads - 1);
    defer allocator.free(handles);
    // Every worker's buffer, allocated before the first one starts. A worker
    // that allocated its own and ran out stopped alone, and the rest mined on
    // with nobody to tell them.
    const tail_len = tailLen(&sh);
    const tails = try allocator.alloc(u8, tail_len * threads);
    defer allocator.free(tails);
    var spawned: usize = 0;
    var spawn_failed = false;
    while (spawned < threads - 1) : (spawned += 1) {
        const index: u32 = @intCast(spawned + 1);
        handles[spawned] = std.Thread.spawn(.{}, worker, .{ &sh, index, tails[index * tail_len ..][0..tail_len] }) catch {
            spawn_failed = true;
            break;
        };
    }
    if (spawn_failed) sh.stop.store(true, .release) else worker(&sh, 0, tails[0..tail_len]);
    for (handles[0..spawned]) |h| h.join();

    // A nonce found is a result, whatever else happened.
    if (spawn_failed and !sh.found.load(.acquire)) return error.ThreadSpawnFailed;
    if (!sh.found.load(.acquire)) {
        if (sh.timed_out.load(.acquire)) return error.Timeout;
        if (sh.cancel) |c| if (c.load(.acquire)) return error.Cancelled;
        return error.Exhausted;
    }

    var v = sh.nonce;
    var i: usize = nonce_digits;
    while (i > 0) {
        i -= 1;
        nonce_str[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    const id = try event.computeId(allocator, template.pubkey, template.created_at, template.kind, all_tags, template.content);
    mined.event = .{
        .id = id,
        .pubkey = template.pubkey,
        .created_at = template.created_at,
        .kind = template.kind,
        .tags = all_tags,
        .content = try arena.dupe(u8, template.content),
        .sig = @splat(0),
    };
    return mined;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "nip13: difficulty counts leading zero bits" {
    var id: [32]u8 = @splat(0xff);
    try testing.expectEqual(@as(u32, 0), difficulty(id));
    id[0] = 0x7f;
    try testing.expectEqual(@as(u32, 1), difficulty(id));
    id[0] = 0;
    id[1] = 0x01;
    try testing.expectEqual(@as(u32, 15), difficulty(id));
    id = @splat(0);
    try testing.expectEqual(@as(u32, 256), difficulty(id));
}

test "nip13: spec example id has 21 leading zero bits" {
    // 000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358
    const id = try hex.decodeFixed(32, "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358");
    try testing.expectEqual(@as(u32, 21), difficulty(id));
}

test "nip13: committedTarget reads the nonce tag" {
    const nonce_tag: event.Tag = &.{ "nonce", "776797", "20" };
    const e_tag: event.Tag = &.{ "e", "abc" };
    var ev: event.Event = .{
        .id = @splat(0),
        .pubkey = @splat(0),
        .created_at = 0,
        .kind = 1,
        .tags = &.{ e_tag, nonce_tag },
        .content = "",
        .sig = @splat(0),
    };
    try testing.expectEqual(@as(?u32, 20), committedTarget(ev));
    const no_target: event.Tag = &.{ "nonce", "1" };
    ev.tags = &.{no_target};
    try testing.expectEqual(@as(?u32, null), committedTarget(ev));
    ev.tags = &.{e_tag};
    try testing.expectEqual(@as(?u32, null), committedTarget(ev));
}

fn checkMined(m: Mined, target: u32) !void {
    const ev = m.event;
    try testing.expect(difficulty(ev.id) >= target);
    const real = try event.computeId(testing.allocator, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    try testing.expectEqualSlices(u8, &real, &ev.id);
    try testing.expectEqual(@as(?u32, target), committedTarget(ev));
    const last = ev.tags[ev.tags.len - 1];
    try testing.expectEqualStrings("nonce", last[0]);
}

test "nip13: mine reaches difficulty 8 to 12 on one thread" {
    const old: event.Tag = &.{ "nonce", "1", "99" };
    const t_tag: event.Tag = &.{ "t", "pow \"quoted\"" };
    var target: u32 = 8;
    while (target <= 12) : (target += 1) {
        var m = try mine(testing.allocator, testing.io, .{
            .pubkey = @splat(7),
            .created_at = 1700000000,
            .kind = 1,
            .tags = &.{ old, t_tag },
            .content = "hello\nworld \u{1F600}",
        }, .{ .target = target, .threads = 1 });
        defer m.deinit();
        try checkMined(m, target);
        try testing.expectEqual(@as(usize, 2), m.event.tags.len);
    }
}

test "nip13: mine with four threads" {
    var m = try mine(testing.allocator, testing.io, .{
        .pubkey = @splat(9),
        .created_at = 1700000001,
        .kind = 1,
        .content = "x" ** 200,
    }, .{ .target = 14, .threads = 4 });
    defer m.deinit();
    try checkMined(m, 14);
}

test "nip13: mine cancels promptly" {
    var cancel: std.atomic.Value(bool) = .init(false);
    const T = struct {
        fn run(c: *std.atomic.Value(bool)) void {
            testing.io.sleep(.fromMilliseconds(50), .awake) catch {};
            c.store(true, .release);
        }
    };
    const th = try std.Thread.spawn(.{}, T.run, .{&cancel});
    defer th.join();
    const start = std.Io.Timestamp.now(testing.io, .awake).toMilliseconds();
    try testing.expectError(error.Cancelled, mine(testing.allocator, testing.io, .{
        .pubkey = @splat(1),
        .created_at = 1,
        .kind = 1,
    }, .{ .target = 200, .threads = 4, .cancel = &cancel }));
    const took = std.Io.Timestamp.now(testing.io, .awake).toMilliseconds() - start;
    try testing.expect(took < 2000);
}

test "nip13: mine stops at the deadline" {
    try testing.expectError(error.Timeout, mine(testing.allocator, testing.io, .{
        .pubkey = @splat(1),
        .created_at = 1,
        .kind = 1,
    }, .{ .target = 200, .threads = 2, .timeout_ms = 30 }));
}

test "nip13: a timeout too long for the clock is no deadline, not a crash" {
    var m = try mine(testing.allocator, testing.io, .{ .pubkey = @splat(1), .created_at = 1, .kind = 1 }, .{ .target = 1, .timeout_ms = std.math.maxInt(u64) });
    defer m.deinit();
    try checkMined(m, 1);
}

test "nip13: running out of memory anywhere in mine is reported and leaks nothing" {
    // On every thread count: each allocation that can fail fails once, and
    // mine has to come back with OutOfMemory rather than mine on with some of
    // its workers gone.
    const run = struct {
        fn f(a: std.mem.Allocator, threads: u32) !void {
            var m = try mine(a, testing.io, .{ .pubkey = @splat(1), .created_at = 1, .kind = 1, .content = "x" ** 200 }, .{ .target = 1, .threads = threads });
            m.deinit();
        }
    }.f;
    for ([_]u32{ 1, 4 }) |threads| try testing.checkAllAllocationFailures(testing.allocator, run, .{threads});
}

test "nip13: mine rejects a target above 256" {
    try testing.expectError(error.InvalidTarget, mine(testing.allocator, testing.io, .{
        .pubkey = @splat(1),
        .created_at = 1,
        .kind = 1,
    }, .{ .target = 257 }));
}
