//! Store benchmark: ingest throughput and warm-cache query latency.
//!
//! Run with `zig build bench` (default 20_000 events). Set the `BENCH_N`
//! environment variable to change the count, and build in a release mode for
//! representative numbers, e.g. `BENCH_N=100000 zig build bench -Doptimize=ReleaseFast`.
//!
//! It fills a fresh store with `num_events` events spread across a fixed number
//! of authors, times the ingest, then repeatedly runs a 500-note author feed
//! query and reports the best (warm) latency — the acceptance metric for the
//! local-first cache. Results print to stderr; the temporary database is
//! removed on exit.

const std = @import("std");
const nostr = @import("nostr");

const Store = nostr.store.Store;
const Event = nostr.event.Event;
const Filter = nostr.filter.Filter;

const num_authors: u64 = 100;
const feed_limit: u32 = 500;
const query_reps: usize = 50;
const db_path = "zig-nostr-bench.mdb";

/// Builds a distinct, cheap event: id and author derived from `i` so that
/// author `i % num_authors` accumulates a contiguous run of events.
fn makeEvent(i: u64) Event {
    var id = [_]u8{0} ** 32;
    std.mem.writeInt(u64, id[0..8], i +% 1, .little);
    var pubkey = [_]u8{0} ** 32;
    std.mem.writeInt(u64, pubkey[0..8], i % num_authors, .little);
    return .{
        .id = id,
        .pubkey = pubkey,
        .created_at = @intCast(i),
        .kind = 1,
        .tags = &.{},
        .content = "benchmark event content",
        .sig = [_]u8{0} ** 64,
    };
}

fn authorPubkey(index: u64) [32]u8 {
    var pubkey = [_]u8{0} ** 32;
    std.mem.writeInt(u64, pubkey[0..8], index, .little);
    return pubkey;
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var n: u64 = 20_000;
    if (std.c.getenv("BENCH_N")) |s| {
        n = std.fmt.parseInt(u64, std.mem.span(s), 10) catch n;
    }

    // Start from a clean database file (and its lock sidecar).
    _ = std.c.unlink(db_path);
    _ = std.c.unlink(db_path ++ "-lock");
    var store = try Store.open(db_path, .{ .map_size = 8 << 30 });
    defer {
        store.deinit();
        _ = std.c.unlink(db_path);
        _ = std.c.unlink(db_path ++ "-lock");
    }

    // -- Ingest -- (batched, so throughput reflects the store rather than the
    // per-commit fsync latency; events are inserted in chunks of `batch`).
    const batch = 10_000;
    const scratch = try gpa.alloc(Event, @min(batch, n));
    defer gpa.free(scratch);

    const ingest_start = std.Io.Timestamp.now(io, .awake);
    var done: u64 = 0;
    while (done < n) {
        const this_batch = @min(@as(u64, batch), n - done);
        for (0..this_batch) |j| scratch[j] = makeEvent(done + j);
        _ = try store.putEventBatch(gpa, scratch[0..this_batch]);
        done += this_batch;
    }
    const ingest_ns: u64 = @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds - ingest_start.nanoseconds);
    const ingest_per_s = @as(f64, @floatFromInt(n)) * 1e9 / @as(f64, @floatFromInt(ingest_ns));

    // -- Warm-cache query: a `feed_limit`-note author feed --
    const feed = Filter{ .authors = &[_][32]u8{authorPubkey(0)}, .limit = feed_limit };
    {
        var warm = try store.query(gpa, feed); // prime the mmap / page cache
        warm.deinit();
    }
    var best_ns: u64 = std.math.maxInt(u64);
    var feed_len: usize = 0;
    var rep: usize = 0;
    while (rep < query_reps) : (rep += 1) {
        const q_start = std.Io.Timestamp.now(io, .awake);
        var r = try store.query(gpa, feed);
        const dt: u64 = @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds - q_start.nanoseconds);
        feed_len = r.events.len;
        r.deinit();
        if (dt < best_ns) best_ns = dt;
    }
    const best_us = @as(f64, @floatFromInt(best_ns)) / 1e3;

    std.debug.print(
        \\zig-nostr store benchmark
        \\  events ingested : {d}
        \\  authors         : {d}
        \\  ingest          : {d:.0} events/s ({d:.2} ms total)
        \\  warm feed query : {d} notes in {d:.1} us (best of {d})
        \\
    , .{
        n,
        num_authors,
        ingest_per_s,
        @as(f64, @floatFromInt(ingest_ns)) / 1e6,
        feed_len,
        best_us,
        query_reps,
    });
}
