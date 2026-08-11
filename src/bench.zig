//! Store benchmark: ingest throughput and warm-cache query latency.
//!
//! Run with `zig build bench` (default 20_000 events). Set the `BENCH_N`
//! environment variable to change the count, and build in a release mode for
//! representative numbers, e.g. `BENCH_N=100000 zig build bench -Doptimize=ReleaseFast`.
//!
//! It fills a fresh store with `num_events` events spread across a fixed number
//! of authors, each of whom has a profile buried under everything they have
//! posted since, times the ingest, then measures five warm query shapes: a
//! multi-author home feed (`feed_authors` authors, kind 1, 500 notes), the same
//! feed scoped to a whole follow list rather than a handful of authors, a
//! refresh of that feed by naming the ids that arrived since the last one, one
//! author's timeline (500 events, any kind), and one author's profile (kind 0,
//! one event). It reports the best latency of each, plus how many index entries
//! each read to produce its answer.
//!
//! The feed shape is the hottest path of a client and the acceptance metric for
//! the local-first cache. The profile shape is the one a store of a single kind
//! cannot measure at all, because there is nothing of the wrong kind to read
//! past, which is why this fills a mixed store.
//!
//! The wide-feed and by-id shapes are the two halves of one decision. A merged
//! query opens a cursor per author and picks the newest across every live
//! stream once per returned event, so its cost is set by how many people the
//! reader follows, not by how many notes come back. A client that re-runs it to
//! pick up what just arrived pays that in full for a handful of new notes;
//! naming the ids instead is a direct read each. Twenty authors, the shape this
//! measured for its first year, is not a follow list, and it made the query
//! look free at a size nobody has.
//!
//! Results print to stderr; the temporary database is removed on exit.

const std = @import("std");
const nostr = @import("nostr");

const Store = nostr.store.Store;
const Event = nostr.event.Event;
const Filter = nostr.filter.Filter;

/// How many authors the store is spread across. Also the size of the wide-feed
/// follow set, so that shape reads a store where every author it names has
/// posted. Overridable with `BENCH_AUTHORS`; the default is what the first
/// three shapes have always been measured against, so their numbers stay
/// comparable across releases.
var num_authors: u64 = 100;
const feed_authors: usize = 20;
const feed_limit: u32 = 500;
/// A screenful, which is what a client re-queries for on a tick, as opposed to
/// the 500-note backfill the shapes above measure. Overridable with
/// `BENCH_FEED_LIMIT`, because this is the number a reader raises by scrolling
/// and the merge pays the whole author set again for every extra note.
var wide_feed_limit: u32 = 60;
/// How many ids the by-id shape names. Eight is one tick's worth of arrivals;
/// a client refreshing a feed it already holds names the whole screenful it is
/// holding as well, so `BENCH_IDS` raises it to that.
var arrivals: usize = 8;
const max_arrivals = 8192;
const query_reps: usize = 50;
const db_path = "zig-nostr-bench.mdb";

/// Builds a distinct, cheap event: id and author derived from `i` so that
/// author `i % num_authors` accumulates a contiguous run of events.
///
/// The first event of each author is their profile and everything after it is a
/// note, which is the shape a real store has: a `kind:0` written once, buried
/// under everything its author has posted since. A store of one kind cannot
/// tell whether a filter is being answered from an index that suits it, because
/// there is nothing of the wrong kind to read past.
fn makeEvent(i: u64) Event {
    var id = [_]u8{0} ** 32;
    std.mem.writeInt(u64, id[0..8], i +% 1, .little);
    var pubkey = [_]u8{0} ** 32;
    std.mem.writeInt(u64, pubkey[0..8], i % num_authors, .little);
    return .{
        .id = id,
        .pubkey = pubkey,
        .created_at = @intCast(i),
        .kind = if (i < num_authors) 0 else 1,
        .tags = &.{},
        .content = if (i < num_authors) "{\"name\":\"benchmark\"}" else "benchmark event content",
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
    if (std.c.getenv("BENCH_AUTHORS")) |s| {
        num_authors = std.fmt.parseInt(u64, std.mem.span(s), 10) catch num_authors;
    }
    // Every author needs their profile plus at least one note for the shapes
    // below to mean anything, and `makeEvent` gives the first `num_authors`
    // events to the profiles.
    if (num_authors == 0) num_authors = 1;
    if (n < num_authors * 2) n = num_authors * 2;
    if (std.c.getenv("BENCH_FEED_LIMIT")) |s| {
        wide_feed_limit = std.fmt.parseInt(u32, std.mem.span(s), 10) catch wide_feed_limit;
    }
    if (std.c.getenv("BENCH_IDS")) |s| {
        arrivals = @min(std.fmt.parseInt(usize, std.mem.span(s), 10) catch arrivals, max_arrivals);
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

    // -- Warm-cache queries --
    //
    // Home feed: the followed-authors timeline every client renders first.
    var feed_pubkeys: [feed_authors][32]u8 = undefined;
    for (&feed_pubkeys, 0..) |*pk, i| pk.* = authorPubkey(i);
    const feed = Filter{
        .authors = &feed_pubkeys,
        .kinds = &[_]u16{1},
        .limit = feed_limit,
    };
    // Timeline: a single author's recent events, whatever they are.
    const timeline = Filter{ .authors = &[_][32]u8{authorPubkey(0)}, .limit = feed_limit };
    // Profile: one author's `kind:0`. What a client asks for every time it has
    // to put a name on a note, and the shape that has to reach past everything
    // that author has written since they set it.
    const profile = Filter{
        .authors = &[_][32]u8{authorPubkey(0)},
        .kinds = &[_]u16{0},
        .limit = 1,
    };

    // The whole follow list, one screenful deep: what a client re-runs to pick
    // up what arrived a moment ago. Every author named here has posted, so no
    // stream in the merge dies early and the pick pays for all of them.
    const follow_pubkeys = try gpa.alloc([32]u8, num_authors);
    defer gpa.free(follow_pubkeys);
    for (follow_pubkeys, 0..) |*pk, i| pk.* = authorPubkey(i);
    const wide_feed = Filter{
        .authors = follow_pubkeys,
        .kinds = &[_]u16{1},
        .limit = wide_feed_limit,
    };

    const feed_best = try bestQuery(gpa, io, &store, feed);
    const wide_best = try bestQuery(gpa, io, &store, wide_feed);
    const timeline_best = try bestQuery(gpa, io, &store, timeline);
    const profile_best = try bestQuery(gpa, io, &store, profile);

    // The other way to answer the same question: name the ids that arrived and
    // read each directly. Taken from the top of the wide feed, so these are ids
    // the store really holds and the shape is a fair comparison.
    const arrival_ids = try gpa.alloc([32]u8, arrivals);
    defer gpa.free(arrival_ids);
    var arrivals_len: usize = 0;
    {
        // Deep enough to name as many ids as were asked for, whatever the wide
        // feed's own depth is.
        var head_filter = wide_feed;
        head_filter.limit = @intCast(@max(wide_feed_limit, arrivals));
        var head = try store.query(gpa, head_filter);
        defer head.deinit();
        for (head.events) |ev| {
            if (arrivals_len >= arrival_ids.len) break;
            arrival_ids[arrivals_len] = ev.id;
            arrivals_len += 1;
        }
    }
    const by_id = Filter{
        .ids = arrival_ids[0..arrivals_len],
        .authors = follow_pubkeys,
        .kinds = &[_]u16{1},
    };
    const by_id_best = try bestQuery(gpa, io, &store, by_id);

    std.debug.print(
        \\zig-nostr store benchmark
        \\  events ingested    : {d}
        \\  authors            : {d}
        \\  ingest             : {d:.0} events/s ({d:.2} ms total)
        \\  warm feed query    : {d} notes in {d:.1} us (best of {d}; {d} authors, kind 1)
        \\  wide feed query    : {d} notes in {d:.1} us (best of {d}; {d} authors, kind 1, {d} entries examined)
        \\  same feed by id    : {d} notes in {d:.1} us (best of {d}; {d} ids named, {d} entries examined)
        \\  warm timeline query: {d} events in {d:.1} us (best of {d}; 1 author, any kind)
        \\  warm profile query : {d} event in {d:.1} us (best of {d}; 1 author, kind 0, {d} entries examined)
        \\
    , .{
        n,
        num_authors,
        ingest_per_s,
        @as(f64, @floatFromInt(ingest_ns)) / 1e6,
        feed_best.notes,
        @as(f64, @floatFromInt(feed_best.ns)) / 1e3,
        query_reps,
        feed_authors,
        wide_best.notes,
        @as(f64, @floatFromInt(wide_best.ns)) / 1e3,
        query_reps,
        num_authors,
        wide_best.examined,
        by_id_best.notes,
        @as(f64, @floatFromInt(by_id_best.ns)) / 1e3,
        query_reps,
        arrivals_len,
        by_id_best.examined,
        timeline_best.notes,
        @as(f64, @floatFromInt(timeline_best.ns)) / 1e3,
        query_reps,
        profile_best.notes,
        @as(f64, @floatFromInt(profile_best.ns)) / 1e3,
        query_reps,
        profile_best.examined,
    });
}

/// Runs `f` once to warm the mmap/page cache, then `query_reps` times,
/// returning the best latency, the result count, and how many index entries the
/// query read to produce it. The last one is the part a stopwatch cannot show:
/// a query reading far more than it returns is answering from an index that
/// does not suit it, whatever the clock says on the day.
fn bestQuery(
    gpa: std.mem.Allocator,
    io: std.Io,
    store: *Store,
    f: Filter,
) !struct { ns: u64, notes: usize, examined: usize } {
    var notes: usize = 0;
    var examined: usize = 0;
    {
        var warm = try store.query(gpa, f);
        notes = warm.events.len;
        examined = warm.examined;
        warm.deinit();
    }
    var best_ns: u64 = std.math.maxInt(u64);
    var rep: usize = 0;
    while (rep < query_reps) : (rep += 1) {
        const q_start = std.Io.Timestamp.now(io, .awake);
        var r = try store.query(gpa, f);
        const dt: u64 = @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds - q_start.nanoseconds);
        r.deinit();
        if (dt < best_ns) best_ns = dt;
    }
    return .{ .ns = best_ns, .notes = notes, .examined = examined };
}
