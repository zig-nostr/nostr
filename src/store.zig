//! Local-first event store over LMDB.
//!
//! The storage engine for the local-first cache (milestone A4): a zero-copy,
//! memory-mapped key/value database. This module owns the on-disk event record
//! format, the primary store keyed by event id, the secondary indexes, and the
//! filter-driven query API that serves reads entirely from the local database.
//!
//! Events are stored in a compact binary record (see `EventView`) rather than
//! JSON: the fixed-size scalar fields sit at constant offsets so they can be
//! read in O(1) straight out of the memory map, with no JSON re-parse on read.
//!
//! Secondary indexes (by author, kind, created_at, and single-letter tag) are
//! written in the same transaction as the event. A query selects the most
//! selective index as its driving scan, gathers candidate ids, and applies the
//! full `Filter` to each candidate — reusing the exact matching semantics that
//! subscriptions use — returning results newest-first with pagination.

const std = @import("std");
const c = @import("lmdb");
const event = @import("event.zig");
const filter_mod = @import("filter.zig");
const keys = @import("keys.zig");

const Event = event.Event;
const Tag = event.Tag;
const Filter = filter_mod.Filter;

pub const Error = error{
    /// LMDB returned a non-success, non-`NOTFOUND` status code.
    Lmdb,
    /// A stored event record was truncated or malformed.
    CorruptRecord,
    OutOfMemory,
};

/// A handle to an open LMDB environment (a single memory-mapped database file)
/// plus the named sub-databases the store uses.
pub const Store = struct {
    env: *c.MDB_env,
    /// Generic key/value database used by `put`/`get`.
    kv_dbi: c.MDB_dbi,
    /// Primary event store: 32-byte event id -> binary event record.
    events_dbi: c.MDB_dbi,
    /// Index: pubkey ++ time-key ++ id -> (empty).
    idx_author_dbi: c.MDB_dbi,
    /// Index: kind(be u16) ++ time-key ++ id -> (empty).
    idx_kind_dbi: c.MDB_dbi,
    /// Index: time-key ++ id -> (empty). Drives "everything, newest first".
    idx_created_dbi: c.MDB_dbi,
    /// Index: letter ++ value ++ time-key ++ id -> (empty).
    idx_tag_dbi: c.MDB_dbi,
    /// Replaceable coordinate -> current event id. The coordinate is
    /// pubkey ++ kind(be u16) for (parameterized-)replaceable events, with the
    /// `d`-tag value appended for parameterized ones. Lets ingestion find the
    /// event a new replaceable event supersedes.
    repl_dbi: c.MDB_dbi,

    pub const OpenOptions = struct {
        /// Upper bound on the memory map (and thus the on-disk database) size.
        /// LMDB reserves this as virtual address space, not physical memory,
        /// so a generous default is cheap. Defaults to 1 GiB.
        map_size: usize = 1 << 30,
        /// Maximum number of named sub-databases. Defaults to 16.
        max_dbs: u32 = 16,
    };

    /// Opens (creating if necessary) the LMDB environment at `path`. The path
    /// is treated as a single file (`MDB_NOSUBDIR`) rather than a directory.
    /// The named sub-databases are created up front so that read-only
    /// transactions can rely on their existence.
    pub fn open(path: [*:0]const u8, options: OpenOptions) Error!Store {
        var env: ?*c.MDB_env = null;
        try check(c.mdb_env_create(&env));
        errdefer c.mdb_env_close(env);
        try check(c.mdb_env_set_mapsize(env, options.map_size));
        try check(c.mdb_env_set_maxdbs(env, @intCast(options.max_dbs)));
        try check(c.mdb_env_open(env, path, @intCast(c.MDB_NOSUBDIR), 0o644));

        // Create/open the named sub-databases in a single write transaction.
        // The dbi handles remain valid for the life of the environment.
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        const store = Store{
            .env = env.?,
            .kv_dbi = try openDb(txn, "kv"),
            .events_dbi = try openDb(txn, "events"),
            .idx_author_dbi = try openDb(txn, "idx_author"),
            .idx_kind_dbi = try openDb(txn, "idx_kind"),
            .idx_created_dbi = try openDb(txn, "idx_created"),
            .idx_tag_dbi = try openDb(txn, "idx_tag"),
            .repl_dbi = try openDb(txn, "repl"),
        };
        try check(c.mdb_txn_commit(txn));
        return store;
    }

    /// Flushes and closes the environment. The handle is invalid afterwards.
    pub fn deinit(self: *Store) void {
        c.mdb_env_close(self.env);
        self.* = undefined;
    }

    // -- Generic key/value access -------------------------------------------

    /// Stores `value` under `key` in the generic key/value database, committing
    /// the write. An existing value for `key` is overwritten.
    pub fn put(self: *Store, key: []const u8, value: []const u8) Error!void {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        var k = val(key);
        var v = val(value);
        try check(c.mdb_put(txn, self.kv_dbi, &k, &v, 0));
        try check(c.mdb_txn_commit(txn));
    }

    /// Looks up `key` in the generic key/value database. Returns a caller-owned
    /// copy of the value (allocated with `allocator`), or null if absent.
    pub fn get(self: *Store, allocator: std.mem.Allocator, key: []const u8) Error!?[]u8 {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, @intCast(c.MDB_RDONLY), &txn));
        defer c.mdb_txn_abort(txn);
        var k = val(key);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(txn, self.kv_dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try check(rc);
        return try allocator.dupe(u8, valBytes(v));
    }

    // -- Event storage ------------------------------------------------------

    /// Stores `ev` keyed by its 32-byte id and writes its secondary index
    /// entries in the same transaction. Idempotent: because the id is a hash of
    /// the event's own content, an id that already exists denotes the same
    /// event, so a duplicate insert is a no-op. Returns true if the event was
    /// newly inserted, false if it was already present.
    pub fn putEvent(self: *Store, gpa: std.mem.Allocator, ev: Event) Error!bool {
        const record = try encodeEvent(gpa, ev);
        defer gpa.free(record);

        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);

        var k = val(&ev.id);
        var v = val(record);
        const rc = c.mdb_put(txn, self.events_dbi, &k, &v, @intCast(c.MDB_NOOVERWRITE));
        const inserted = rc != c.MDB_KEYEXIST;
        if (inserted) {
            try check(rc);
            try self.applyIndexes(gpa, txn, ev, .put);
        }
        try check(c.mdb_txn_commit(txn));
        return inserted;
    }

    /// Writes or deletes every secondary-index entry for `ev` within `txn`.
    /// Building both directions from one place guarantees an index delete uses
    /// the exact keys its insert did.
    fn applyIndexes(self: *Store, gpa: std.mem.Allocator, txn: ?*c.MDB_txn, ev: Event, op: IndexOp) Error!void {
        const tk = orderKey(ev.created_at);

        var key: std.ArrayList(u8) = .empty;
        defer key.deinit(gpa);

        // created_at index: [time][id]
        key.clearRetainingCapacity();
        try key.appendSlice(gpa, &tk);
        try key.appendSlice(gpa, &ev.id);
        try indexOp(txn, self.idx_created_dbi, key.items, op);

        // author index: [pubkey][time][id]
        key.clearRetainingCapacity();
        try key.appendSlice(gpa, &ev.pubkey);
        try key.appendSlice(gpa, &tk);
        try key.appendSlice(gpa, &ev.id);
        try indexOp(txn, self.idx_author_dbi, key.items, op);

        // kind index: [kind big-endian][time][id]
        var kb: [2]u8 = undefined;
        std.mem.writeInt(u16, &kb, ev.kind, .big);
        key.clearRetainingCapacity();
        try key.appendSlice(gpa, &kb);
        try key.appendSlice(gpa, &tk);
        try key.appendSlice(gpa, &ev.id);
        try indexOp(txn, self.idx_kind_dbi, key.items, op);

        // tag index: [letter][value][time][id] for each single-letter tag.
        for (ev.tags) |tag| {
            if (tag.len < 2 or tag[0].len != 1) continue;
            key.clearRetainingCapacity();
            try key.append(gpa, tag[0][0]);
            try key.appendSlice(gpa, tag[1]);
            try key.appendSlice(gpa, &tk);
            try key.appendSlice(gpa, &ev.id);
            try indexOp(txn, self.idx_tag_dbi, key.items, op);
        }
    }

    /// Encodes and stores `ev`'s record and index entries within `txn`,
    /// overwriting any record already at its id. Used by the ingestion paths,
    /// which have already decided the write should happen.
    fn storeEvent(self: *Store, gpa: std.mem.Allocator, txn: ?*c.MDB_txn, ev: Event) Error!void {
        const record = try encodeEvent(gpa, ev);
        defer gpa.free(record);
        var k = val(&ev.id);
        var v = val(record);
        try check(c.mdb_put(txn, self.events_dbi, &k, &v, 0));
        try self.applyIndexes(gpa, txn, ev, .put);
    }

    /// Removes `ev`'s record and all its index entries within `txn`.
    fn removeEvent(self: *Store, gpa: std.mem.Allocator, txn: ?*c.MDB_txn, ev: Event) Error!void {
        try self.applyIndexes(gpa, txn, ev, .del);
        var k = val(&ev.id);
        const rc = c.mdb_del(txn, self.events_dbi, &k, null);
        if (rc != c.MDB_NOTFOUND) try check(rc);
    }

    /// Returns true if an event with `id` is stored.
    pub fn hasEvent(self: *Store, id: [32]u8) Error!bool {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, @intCast(c.MDB_RDONLY), &txn));
        defer c.mdb_txn_abort(txn);
        var k = val(&id);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(txn, self.events_dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return false;
        try check(rc);
        return true;
    }

    /// Looks up the event with `id` and decodes it into a caller-owned
    /// `StoredEvent` (backed by its own arena), or null if absent. The decode
    /// reads the binary record directly — there is no JSON parsing on this
    /// path. Call `deinit` on the result to free it.
    pub fn getEvent(self: *Store, gpa: std.mem.Allocator, id: [32]u8) Error!?StoredEvent {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, @intCast(c.MDB_RDONLY), &txn));
        defer c.mdb_txn_abort(txn);
        var k = val(&id);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(txn, self.events_dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try check(rc);

        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        errdefer {
            arena.deinit();
            gpa.destroy(arena);
        }
        const ev = try decodeEvent(arena.allocator(), valBytes(v));
        return StoredEvent{ .arena = arena, .event = ev };
    }

    // -- Query --------------------------------------------------------------

    /// Runs `filter` against the local database and returns the matching events
    /// newest-first (ties broken deterministically by id), capped at
    /// `filter.limit` when set. The result owns an arena backing all returned
    /// event data — call `deinit` on it to free.
    ///
    /// The query drives off the most selective available index (ids > authors >
    /// kinds > tags > everything-by-time) to gather candidates, then applies the
    /// full `Filter` to each, so every constraint is enforced exactly as in
    /// subscription matching.
    pub fn query(self: *Store, gpa: std.mem.Allocator, filter: Filter) Error!QueryResult {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, @intCast(c.MDB_RDONLY), &txn));
        defer c.mdb_txn_abort(txn);

        var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        defer seen.deinit(gpa);
        var candidates: std.ArrayList([32]u8) = .empty;
        defer candidates.deinit(gpa);
        try self.collectCandidates(txn, gpa, filter, &candidates, &seen);

        const arena = try gpa.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(gpa);
        errdefer {
            arena.deinit();
            gpa.destroy(arena);
        }
        const aa = arena.allocator();

        var matched: std.ArrayList(Event) = .empty;
        defer matched.deinit(gpa);
        for (candidates.items) |id| {
            var k = val(&id);
            var v: c.MDB_val = undefined;
            const rc = c.mdb_get(txn, self.events_dbi, &k, &v);
            if (rc == c.MDB_NOTFOUND) continue;
            try check(rc);
            const ev = try decodeEvent(aa, valBytes(v));
            if (filter.matches(ev)) try matched.append(gpa, ev);
        }

        std.mem.sort(Event, matched.items, {}, lessByTimeDesc);

        const count = if (filter.limit) |l| @min(@as(usize, l), matched.items.len) else matched.items.len;
        const events = try aa.dupe(Event, matched.items[0..count]);
        return QueryResult{ .arena = arena, .events = events };
    }

    /// Populates `candidates` (deduplicated via `seen`) with event ids to
    /// evaluate, chosen from the most selective index the filter allows.
    fn collectCandidates(
        self: *Store,
        txn: ?*c.MDB_txn,
        gpa: std.mem.Allocator,
        filter: Filter,
        candidates: *std.ArrayList([32]u8),
        seen: *std.AutoHashMapUnmanaged([32]u8, void),
    ) Error!void {
        if (filter.ids) |ids| {
            for (ids) |id| try addCandidate(gpa, candidates, seen, id);
            return;
        }
        if (filter.authors) |authors| {
            for (authors) |a| try scanPrefix(txn, self.idx_author_dbi, gpa, &a, candidates, seen);
            return;
        }
        if (filter.kinds) |kinds| {
            for (kinds) |kd| {
                var kb: [2]u8 = undefined;
                std.mem.writeInt(u16, &kb, kd, .big);
                try scanPrefix(txn, self.idx_kind_dbi, gpa, &kb, candidates, seen);
            }
            return;
        }
        if (filter.tags) |tag_filters| {
            if (tag_filters.len > 0) {
                const tf = tag_filters[0];
                var prefix: std.ArrayList(u8) = .empty;
                defer prefix.deinit(gpa);
                for (tf.values) |value| {
                    prefix.clearRetainingCapacity();
                    try prefix.append(gpa, tf.letter);
                    try prefix.appendSlice(gpa, value);
                    try scanPrefix(txn, self.idx_tag_dbi, gpa, prefix.items, candidates, seen);
                }
                return;
            }
        }
        // No selective constraint: walk every event by the created_at index.
        try scanPrefix(txn, self.idx_created_dbi, gpa, &.{}, candidates, seen);
    }

    // -- Ingestion ----------------------------------------------------------

    /// Ingests `ev`, applying NIP-01 protocol semantics on top of raw storage:
    /// optional signature validation, and replaceable / parameterized-
    /// replaceable "latest wins" upserts. Ephemeral events are not persisted.
    /// See `IngestResult` for the possible outcomes.
    ///
    /// This is the protocol-aware entry point; `putEvent` is the low-level
    /// insert. Callers feeding events from relays should use `ingest`.
    pub fn ingest(self: *Store, gpa: std.mem.Allocator, ev: Event, options: IngestOptions) Error!IngestResult {
        if (options.verify_with) |signer| {
            if (!(try event.verify(gpa, signer, ev))) return .invalid;
        }
        switch (classify(ev.kind)) {
            .ephemeral => return .ephemeral,
            .regular => {
                const inserted = try self.putEvent(gpa, ev);
                return if (inserted) .added else .duplicate;
            },
            .replaceable, .parameterized => |class| return self.ingestReplaceable(gpa, ev, class),
        }
    }

    fn ingestReplaceable(self: *Store, gpa: std.mem.Allocator, ev: Event, class: Class) Error!IngestResult {
        // Build the replaceable coordinate: pubkey ++ kind, plus the d-tag
        // value for parameterized-replaceable events.
        var coord: std.ArrayList(u8) = .empty;
        defer coord.deinit(gpa);
        try coord.appendSlice(gpa, &ev.pubkey);
        var kb: [2]u8 = undefined;
        std.mem.writeInt(u16, &kb, ev.kind, .big);
        try coord.appendSlice(gpa, &kb);
        if (class == .parameterized) try coord.appendSlice(gpa, dTagValue(ev));

        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);

        var ck = val(coord.items);
        var cv: c.MDB_val = undefined;
        const crc = c.mdb_get(txn, self.repl_dbi, &ck, &cv);

        var result: IngestResult = .added;
        if (crc != c.MDB_NOTFOUND) {
            try check(crc);
            const existing_id: [32]u8 = valBytes(cv)[0..32].*;
            if (std.mem.eql(u8, &existing_id, &ev.id)) {
                try check(c.mdb_txn_commit(txn));
                return .duplicate;
            }
            // Compare against the currently stored event for this coordinate.
            var ek = val(&existing_id);
            var evv: c.MDB_val = undefined;
            const erc = c.mdb_get(txn, self.events_dbi, &ek, &evv);
            if (erc != c.MDB_NOTFOUND) {
                try check(erc);
                var scratch = std.heap.ArenaAllocator.init(gpa);
                defer scratch.deinit();
                const existing = try decodeEvent(scratch.allocator(), valBytes(evv));
                if (!replaces(ev, existing)) {
                    try check(c.mdb_txn_commit(txn));
                    return .stale;
                }
                try self.removeEvent(gpa, txn, existing);
                result = .replaced;
            }
        }

        try self.storeEvent(gpa, txn, ev);
        // Point the coordinate at the new event.
        var v = val(&ev.id);
        try check(c.mdb_put(txn, self.repl_dbi, &ck, &v, 0));
        try check(c.mdb_txn_commit(txn));
        return result;
    }
};

/// An owned, decoded event: `event`'s tag/content storage lives in `arena`.
pub const StoredEvent = struct {
    arena: *std.heap.ArenaAllocator,
    event: Event,

    pub fn deinit(self: *StoredEvent) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// The owned result of a `query`: `events` (newest-first) and all their backing
/// storage live in `arena`.
pub const QueryResult = struct {
    arena: *std.heap.ArenaAllocator,
    events: []Event,

    pub fn deinit(self: *QueryResult) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Options controlling `Store.ingest`.
pub const IngestOptions = struct {
    /// When set, the event's signature and id are verified before storing; a
    /// failing event is rejected with `IngestResult.invalid`. When null the
    /// event is trusted (e.g. already verified upstream).
    verify_with: ?keys.Signer = null,
};

/// The outcome of `Store.ingest`.
pub const IngestResult = enum {
    /// Stored as a new event (or the first for its replaceable coordinate).
    added,
    /// A (parameterized-)replaceable event superseded an older stored one.
    replaced,
    /// The same event id was already stored; nothing changed.
    duplicate,
    /// A replaceable event at least as new is already stored; not stored.
    stale,
    /// Rejected: signature/id validation failed.
    invalid,
    /// An ephemeral-kind event, which is not persisted.
    ephemeral,
};

/// NIP-01 event-kind classes that determine storage semantics.
const Class = enum { regular, replaceable, parameterized, ephemeral };

fn classify(kind: u16) Class {
    if (kind == 0 or kind == 3) return .replaceable;
    if (kind >= 10_000 and kind < 20_000) return .replaceable;
    if (kind >= 20_000 and kind < 30_000) return .ephemeral;
    if (kind >= 30_000 and kind < 40_000) return .parameterized;
    return .regular;
}

/// Whether `new` supersedes `old` for the same replaceable coordinate: the
/// higher `created_at` wins, ties broken by the lexicographically lower id
/// (per NIP-01).
fn replaces(new: Event, old: Event) bool {
    if (new.created_at != old.created_at) return new.created_at > old.created_at;
    return std.mem.order(u8, &new.id, &old.id) == .lt;
}

/// The value of the first `d` tag, or "" if absent (an addressable event with
/// no `d` tag is treated as having an empty identifier).
fn dTagValue(ev: Event) []const u8 {
    for (ev.tags) |tag| {
        if (tag.len >= 1 and tag[0].len == 1 and tag[0][0] == 'd') {
            return if (tag.len >= 2) tag[1] else "";
        }
    }
    return "";
}

fn lessByTimeDesc(_: void, a: Event, b: Event) bool {
    if (a.created_at != b.created_at) return a.created_at > b.created_at;
    return std.mem.order(u8, &a.id, &b.id) == .gt;
}

fn addCandidate(
    gpa: std.mem.Allocator,
    candidates: *std.ArrayList([32]u8),
    seen: *std.AutoHashMapUnmanaged([32]u8, void),
    id: [32]u8,
) Error!void {
    const gop = try seen.getOrPut(gpa, id);
    if (gop.found_existing) return;
    try candidates.append(gpa, id);
}

/// Scans an index database for all keys beginning with `prefix` (an empty
/// prefix scans everything), extracts the trailing 32-byte id of each, and adds
/// it to `candidates`. Every index key ends with `[time-key(8)][id(32)]`, so a
/// non-empty prefix match additionally requires the exact length
/// `prefix.len + 40`, which rules out a shorter query value being a prefix of a
/// longer stored value.
fn scanPrefix(
    txn: ?*c.MDB_txn,
    dbi: c.MDB_dbi,
    gpa: std.mem.Allocator,
    prefix: []const u8,
    candidates: *std.ArrayList([32]u8),
    seen: *std.AutoHashMapUnmanaged([32]u8, void),
) Error!void {
    var cursor: ?*c.MDB_cursor = null;
    try check(c.mdb_cursor_open(txn, dbi, &cursor));
    defer c.mdb_cursor_close(cursor);

    var k: c.MDB_val = if (prefix.len == 0) undefined else val(prefix);
    var v: c.MDB_val = undefined;
    var rc = if (prefix.len == 0)
        c.mdb_cursor_get(cursor, &k, &v, c.MDB_FIRST)
    else
        c.mdb_cursor_get(cursor, &k, &v, c.MDB_SET_RANGE);

    while (rc == c.MDB_SUCCESS) : (rc = c.mdb_cursor_get(cursor, &k, &v, c.MDB_NEXT)) {
        const key = valBytes(k);
        if (prefix.len != 0) {
            if (key.len < prefix.len or !std.mem.eql(u8, key[0..prefix.len], prefix)) break;
            if (key.len != prefix.len + 40) continue;
        }
        if (key.len < 32) continue;
        try addCandidate(gpa, candidates, seen, key[key.len - 32 ..][0..32].*);
    }
    if (rc != c.MDB_SUCCESS and rc != c.MDB_NOTFOUND) return error.Lmdb;
}

/// Order-preserving big-endian encoding of an `i64` timestamp: flipping the
/// sign bit maps two's-complement order onto unsigned lexicographic order, so
/// LMDB's byte comparison sorts index keys by time.
fn orderKey(t: i64) [8]u8 {
    const u = @as(u64, @bitCast(t)) ^ (@as(u64, 1) << 63);
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, u, .big);
    return b;
}

// -- Binary event record ----------------------------------------------------
//
// Layout (little-endian):
//   [0..32)    id
//   [32..64)   pubkey
//   [64..128)  sig
//   [128..136) created_at (i64)
//   [136..138) kind (u16)
//   [138..142) content length (u32)
//   [142..146) tag count (u32)
//   [146..146+content_len) content bytes
//   then, tag_count times:
//     field count (u32)
//     then, field_count times: field length (u32) + field bytes
//
// The scalar fields and the content slice are at fixed/computable offsets, so
// `EventView` reads them with no allocation and no parse.

const header_len = 146;
const off_id = 0;
const off_pubkey = 32;
const off_sig = 64;
const off_created_at = 128;
const off_kind = 136;
const off_content_len = 138;
const off_tag_count = 142;

/// A zero-copy view over a stored event record. Accessors return slices into
/// the underlying `bytes`, which for a record read from LMDB point directly
/// into the memory map and are valid only for the life of the read
/// transaction. Callers who need the data to outlive the transaction should
/// use `Store.getEvent`, which copies into an owned arena.
pub const EventView = struct {
    bytes: []const u8,

    pub fn id(self: EventView) *const [32]u8 {
        return self.bytes[off_id..][0..32];
    }
    pub fn pubkey(self: EventView) *const [32]u8 {
        return self.bytes[off_pubkey..][0..32];
    }
    pub fn sig(self: EventView) *const [64]u8 {
        return self.bytes[off_sig..][0..64];
    }
    pub fn createdAt(self: EventView) i64 {
        return std.mem.readInt(i64, self.bytes[off_created_at..][0..8], .little);
    }
    pub fn kind(self: EventView) u16 {
        return std.mem.readInt(u16, self.bytes[off_kind..][0..2], .little);
    }
    pub fn content(self: EventView) []const u8 {
        const len = std.mem.readInt(u32, self.bytes[off_content_len..][0..4], .little);
        return self.bytes[header_len..][0..len];
    }
};

/// Encodes `ev` into a freshly allocated binary record (see the layout above).
fn encodeEvent(gpa: std.mem.Allocator, ev: Event) Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);

    try list.appendSlice(gpa, &ev.id);
    try list.appendSlice(gpa, &ev.pubkey);
    try list.appendSlice(gpa, &ev.sig);
    try appendInt(&list, gpa, i64, ev.created_at);
    try appendInt(&list, gpa, u16, ev.kind);
    try appendInt(&list, gpa, u32, @intCast(ev.content.len));
    try appendInt(&list, gpa, u32, @intCast(ev.tags.len));
    try list.appendSlice(gpa, ev.content);
    for (ev.tags) |tag| {
        try appendInt(&list, gpa, u32, @intCast(tag.len));
        for (tag) |field| {
            try appendInt(&list, gpa, u32, @intCast(field.len));
            try list.appendSlice(gpa, field);
        }
    }
    return list.toOwnedSlice(gpa);
}

/// Decodes a binary record into an `Event` whose tag/content storage is
/// allocated from `arena`. Returns `CorruptRecord` if the record is truncated.
fn decodeEvent(arena: std.mem.Allocator, bytes: []const u8) Error!Event {
    if (bytes.len < header_len) return error.CorruptRecord;
    const content_len = std.mem.readInt(u32, bytes[off_content_len..][0..4], .little);
    const tag_count = std.mem.readInt(u32, bytes[off_tag_count..][0..4], .little);

    var cursor: usize = header_len;
    const content = try readSlice(bytes, &cursor, content_len);

    const tags = try arena.alloc(Tag, tag_count);
    for (tags) |*tag| {
        const field_count = try readU32(bytes, &cursor);
        const fields = try arena.alloc([]const u8, field_count);
        for (fields) |*field| {
            const field_len = try readU32(bytes, &cursor);
            field.* = try arena.dupe(u8, try readSlice(bytes, &cursor, field_len));
        }
        tag.* = fields;
    }

    return Event{
        .id = bytes[off_id..][0..32].*,
        .pubkey = bytes[off_pubkey..][0..32].*,
        .created_at = std.mem.readInt(i64, bytes[off_created_at..][0..8], .little),
        .kind = std.mem.readInt(u16, bytes[off_kind..][0..2], .little),
        .tags = tags,
        .content = try arena.dupe(u8, content),
        .sig = bytes[off_sig..][0..64].*,
    };
}

fn readU32(bytes: []const u8, cursor: *usize) Error!u32 {
    const slice = try readSlice(bytes, cursor, 4);
    return std.mem.readInt(u32, slice[0..4], .little);
}

/// Returns the next `len` bytes at `cursor` and advances it, or `CorruptRecord`
/// if the record does not contain that many more bytes.
fn readSlice(bytes: []const u8, cursor: *usize, len: usize) Error![]const u8 {
    const end = std.math.add(usize, cursor.*, len) catch return error.CorruptRecord;
    if (end > bytes.len) return error.CorruptRecord;
    defer cursor.* = end;
    return bytes[cursor.*..end];
}

fn appendInt(list: *std.ArrayList(u8), gpa: std.mem.Allocator, comptime T: type, v: T) Error!void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, v, .little);
    try list.appendSlice(gpa, &buf);
}

// -- LMDB helpers -----------------------------------------------------------

/// Opens (creating) a named database within `txn` and returns its handle.
fn openDb(txn: ?*c.MDB_txn, name: [*:0]const u8) Error!c.MDB_dbi {
    var dbi: c.MDB_dbi = 0;
    try check(c.mdb_dbi_open(txn, name, @intCast(c.MDB_CREATE), &dbi));
    return dbi;
}

const IndexOp = enum { put, del };

/// Inserts (with an empty value) or deletes an index key, per `op`. A delete of
/// an already-absent key is not an error.
fn indexOp(txn: ?*c.MDB_txn, dbi: c.MDB_dbi, key: []const u8, op: IndexOp) Error!void {
    var k = val(key);
    switch (op) {
        .put => {
            var v = val(&.{});
            try check(c.mdb_put(txn, dbi, &k, &v, 0));
        },
        .del => {
            const rc = c.mdb_del(txn, dbi, &k, null);
            if (rc != c.MDB_NOTFOUND) try check(rc);
        },
    }
}

/// Wraps a byte slice as an `MDB_val` for passing to LMDB. LMDB does not mutate
/// key/value inputs, so casting away const is sound here.
fn val(bytes: []const u8) c.MDB_val {
    return .{ .mv_size = bytes.len, .mv_data = @ptrCast(@constCast(bytes.ptr)) };
}

/// Views an LMDB-returned `MDB_val` as a byte slice.
fn valBytes(v: c.MDB_val) []const u8 {
    if (v.mv_size == 0) return &.{};
    return @as([*]const u8, @ptrCast(v.mv_data.?))[0..v.mv_size];
}

/// Translates an LMDB status code into a Zig error. `MDB_SUCCESS` (0) is Ok.
fn check(rc: c_int) Error!void {
    if (rc == c.MDB_SUCCESS) return;
    return error.Lmdb;
}

// -- tests ------------------------------------------------------------------

fn testStorePath(tmp: *std.testing.TmpDir, name: []const u8, buf: []u8) [:0]const u8 {
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = tmp.dir.realPath(std.testing.io, &dir_buf) catch unreachable;
    return std.fmt.bufPrintZ(buf, "{s}/{s}", .{ dir_buf[0..dir_len], name }) catch unreachable;
}

fn openTempStore(tmp: *std.testing.TmpDir, name: []const u8, buf: []u8) !Store {
    const path = testStorePath(tmp, name, buf);
    return Store.open(path.ptr, .{});
}

fn sampleEvent() Event {
    return Event{
        .id = [_]u8{0x11} ** 32,
        .pubkey = [_]u8{0x22} ** 32,
        .created_at = 1_700_000_000,
        .kind = 1,
        .tags = &[_]Tag{
            &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example" },
            &[_][]const u8{ "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" },
        },
        .content = "hello, nostr \"world\"\n",
        .sig = [_]u8{0x33} ** 64,
    };
}

fn expectEventEqual(a: Event, b: Event) !void {
    try std.testing.expectEqualSlices(u8, &a.id, &b.id);
    try std.testing.expectEqualSlices(u8, &a.pubkey, &b.pubkey);
    try std.testing.expectEqual(a.created_at, b.created_at);
    try std.testing.expectEqual(a.kind, b.kind);
    try std.testing.expectEqualStrings(a.content, b.content);
    try std.testing.expectEqualSlices(u8, &a.sig, &b.sig);
    try std.testing.expectEqual(a.tags.len, b.tags.len);
    for (a.tags, b.tags) |ta, tb| {
        try std.testing.expectEqual(ta.len, tb.len);
        for (ta, tb) |fa, fb| try std.testing.expectEqualStrings(fa, fb);
    }
}

test "store: open, put, and get round-trip through LMDB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "store.mdb", &buf);
    defer store.deinit();

    try store.put("hello", "world");
    const got = try store.get(std.testing.allocator, "hello");
    defer if (got) |g| std.testing.allocator.free(g);
    try std.testing.expectEqualStrings("world", got.?);

    try store.put("hello", "nostr"); // overwrite
    const got2 = try store.get(std.testing.allocator, "hello");
    defer if (got2) |g| std.testing.allocator.free(g);
    try std.testing.expectEqualStrings("nostr", got2.?);

    const missing = try store.get(std.testing.allocator, "absent");
    try std.testing.expect(missing == null);
}

test "store: event record encode/decode round-trip" {
    const ev = sampleEvent();
    const record = try encodeEvent(std.testing.allocator, ev);
    defer std.testing.allocator.free(record);

    const view = EventView{ .bytes = record };
    try std.testing.expectEqualSlices(u8, &ev.id, view.id());
    try std.testing.expectEqualSlices(u8, &ev.pubkey, view.pubkey());
    try std.testing.expectEqualSlices(u8, &ev.sig, view.sig());
    try std.testing.expectEqual(ev.created_at, view.createdAt());
    try std.testing.expectEqual(ev.kind, view.kind());
    try std.testing.expectEqualStrings(ev.content, view.content());

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const decoded = try decodeEvent(arena.allocator(), record);
    try expectEventEqual(ev, decoded);
}

test "store: decodeEvent rejects a truncated record" {
    const ev = sampleEvent();
    const record = try encodeEvent(std.testing.allocator, ev);
    defer std.testing.allocator.free(record);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.CorruptRecord, decodeEvent(arena.allocator(), record[0 .. record.len - 3]));
    try std.testing.expectError(error.CorruptRecord, decodeEvent(arena.allocator(), record[0..10]));
}

test "store: orderKey preserves i64 order as unsigned bytes" {
    const times = [_]i64{ -1_000, -1, 0, 1, 1_700_000_000, std.math.maxInt(i32) };
    var prev: ?[8]u8 = null;
    for (times) |t| {
        const k = orderKey(t);
        if (prev) |p| try std.testing.expect(std.mem.order(u8, &p, &k) == .lt);
        prev = k;
    }
}

test "store: putEvent / getEvent round-trip and idempotent dedup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "events.mdb", &buf);
    defer store.deinit();

    const ev = sampleEvent();
    try std.testing.expect(!(try store.hasEvent(ev.id)));

    try std.testing.expect(try store.putEvent(std.testing.allocator, ev));
    try std.testing.expect(try store.hasEvent(ev.id));
    try std.testing.expect(!(try store.putEvent(std.testing.allocator, ev))); // no-op

    var stored = (try store.getEvent(std.testing.allocator, ev.id)).?;
    defer stored.deinit();
    try expectEventEqual(ev, stored.event);

    const none = try store.getEvent(std.testing.allocator, [_]u8{0xAA} ** 32);
    try std.testing.expect(none == null);
}

test "store: stored events survive reopen (decoded from mmap, no JSON)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = testStorePath(&tmp, "events-persist.mdb", &buf);

    const ev = sampleEvent();
    {
        var store = try Store.open(path.ptr, .{});
        defer store.deinit();
        _ = try store.putEvent(std.testing.allocator, ev);
    }
    {
        var store = try Store.open(path.ptr, .{});
        defer store.deinit();
        var stored = (try store.getEvent(std.testing.allocator, ev.id)).?;
        defer stored.deinit();
        try expectEventEqual(ev, stored.event);
    }
}

// -- query tests ------------------------------------------------------------

const author_a = [_]u8{0xA1} ** 32;
const author_b = [_]u8{0xB2} ** 32;

/// Builds a minimal event with a distinct id derived from `seed`.
fn qEvent(seed: u8, pubkey: [32]u8, kind: u16, created_at: i64, tags: []const Tag) Event {
    return Event{
        .id = [_]u8{seed} ** 32,
        .pubkey = pubkey,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = "",
        .sig = [_]u8{0} ** 64,
    };
}

/// Collects the seeds (first id byte) of the query results in order.
fn resultSeeds(r: QueryResult, out: []u8) []u8 {
    for (r.events, 0..) |e, i| out[i] = e.id[0];
    return out[0..r.events.len];
}

test "store: query drives off indexes and returns newest-first" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "query.mdb", &buf);
    defer store.deinit();

    const gpa = std.testing.allocator;
    const p_tag = [_]Tag{&[_][]const u8{ "p", "cafe" }};
    // seed, author, kind, created_at, tags
    _ = try store.putEvent(gpa, qEvent(1, author_a, 1, 100, &p_tag));
    _ = try store.putEvent(gpa, qEvent(2, author_a, 1, 200, &.{}));
    _ = try store.putEvent(gpa, qEvent(3, author_b, 1, 150, &.{}));
    _ = try store.putEvent(gpa, qEvent(4, author_a, 7, 300, &.{}));

    var seeds: [8]u8 = undefined;

    // Empty filter: all events, newest-first (300, 200, 150, 100).
    {
        var r = try store.query(gpa, .{});
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 2, 3, 1 }, resultSeeds(r, &seeds));
    }
    // By author A (any kind), newest-first: 4(300), 2(200), 1(100).
    {
        var r = try store.query(gpa, .{ .authors = &[_][32]u8{author_a} });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 2, 1 }, resultSeeds(r, &seeds));
    }
    // Author A AND kind 1: 2(200), 1(100).
    {
        var r = try store.query(gpa, .{ .authors = &[_][32]u8{author_a}, .kinds = &[_]u16{1} });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 1 }, resultSeeds(r, &seeds));
    }
    // By kind 7: just event 4.
    {
        var r = try store.query(gpa, .{ .kinds = &[_]u16{7} });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{4}, resultSeeds(r, &seeds));
    }
    // By id.
    {
        var r = try store.query(gpa, .{ .ids = &[_][32]u8{[_]u8{3} ** 32} });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{3}, resultSeeds(r, &seeds));
    }
    // By tag #p = cafe: just event 1.
    {
        const vals = [_][]const u8{"cafe"};
        var r = try store.query(gpa, .{ .tags = &[_]filter_mod.TagFilter{.{ .letter = 'p', .values = &vals }} });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{1}, resultSeeds(r, &seeds));
    }
    // Time window since/until.
    {
        var r = try store.query(gpa, .{ .since = 150, .until = 250 });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 3 }, resultSeeds(r, &seeds));
    }
    // Limit caps the newest N.
    {
        var r = try store.query(gpa, .{ .limit = 2 });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 2 }, resultSeeds(r, &seeds));
    }
    // Duplicate authors do not produce duplicate results.
    {
        var r = try store.query(gpa, .{ .authors = &[_][32]u8{ author_a, author_a } });
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 4, 2, 1 }, resultSeeds(r, &seeds));
    }
    // A tag prefix that is shorter than a stored value must not match it.
    {
        const vals = [_][]const u8{"ca"}; // "ca" is a prefix of "cafe"
        var r = try store.query(gpa, .{ .tags = &[_]filter_mod.TagFilter{.{ .letter = 'p', .values = &vals }} });
        defer r.deinit();
        try std.testing.expectEqual(@as(usize, 0), r.events.len);
    }
}

// -- ingestion tests --------------------------------------------------------

test "store: classify maps kinds to storage semantics" {
    try std.testing.expectEqual(Class.replaceable, classify(0));
    try std.testing.expectEqual(Class.replaceable, classify(3));
    try std.testing.expectEqual(Class.replaceable, classify(10002));
    try std.testing.expectEqual(Class.ephemeral, classify(20001));
    try std.testing.expectEqual(Class.parameterized, classify(30023));
    try std.testing.expectEqual(Class.regular, classify(1));
    try std.testing.expectEqual(Class.regular, classify(5));
    try std.testing.expectEqual(Class.regular, classify(40000));
}

test "store: ingest verifies signatures when a signer is given" {
    const gpa = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "ingest-verify.mdb", &buf);
    defer store.deinit();

    const good = try event.create(gpa, signer, kp, 1000, 1, &[_]Tag{}, "hi", null);
    try std.testing.expectEqual(IngestResult.added, try store.ingest(gpa, good, .{ .verify_with = signer }));
    try std.testing.expect(try store.hasEvent(good.id));

    // A valid id but a zeroed signature must be rejected when verifying.
    var bad = try event.create(gpa, signer, kp, 2000, 1, &[_]Tag{}, "nope", null);
    bad.sig = [_]u8{0} ** 64;
    try std.testing.expectEqual(IngestResult.invalid, try store.ingest(gpa, bad, .{ .verify_with = signer }));
    try std.testing.expect(!(try store.hasEvent(bad.id)));

    // Without a signer the same event is trusted and stored.
    try std.testing.expectEqual(IngestResult.added, try store.ingest(gpa, bad, .{}));
    try std.testing.expect(try store.hasEvent(bad.id));
}

test "store: ingest replaceable keeps the newest" {
    const gpa = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "ingest-repl.mdb", &buf);
    defer store.deinit();

    const older = try event.create(gpa, signer, kp, 1000, 0, &[_]Tag{}, "old profile", null);
    const newer = try event.create(gpa, signer, kp, 2000, 0, &[_]Tag{}, "new profile", null);

    try std.testing.expectEqual(IngestResult.added, try store.ingest(gpa, older, .{}));
    try std.testing.expectEqual(IngestResult.replaced, try store.ingest(gpa, newer, .{}));
    try std.testing.expect(!(try store.hasEvent(older.id)));
    try std.testing.expect(try store.hasEvent(newer.id));

    // Only the newest survives, and its indexes point at it.
    {
        var r = try store.query(gpa, .{ .authors = &[_][32]u8{kp.public_key}, .kinds = &[_]u16{0} });
        defer r.deinit();
        try std.testing.expectEqual(@as(usize, 1), r.events.len);
        try std.testing.expectEqualSlices(u8, &newer.id, &r.events[0].id);
    }

    // An older event for the same coordinate is stale; the same one is a dup.
    try std.testing.expectEqual(IngestResult.stale, try store.ingest(gpa, older, .{}));
    try std.testing.expect(try store.hasEvent(newer.id));
    try std.testing.expectEqual(IngestResult.duplicate, try store.ingest(gpa, newer, .{}));
}

test "store: ingest replaceable tie-break prefers the lower id" {
    const gpa = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "ingest-tiebreak.mdb", &buf);
    defer store.deinit();

    // Same author, kind and created_at, different content -> different ids.
    const e1 = try event.create(gpa, signer, kp, 1000, 0, &[_]Tag{}, "aaa", null);
    const e2 = try event.create(gpa, signer, kp, 1000, 0, &[_]Tag{}, "bbb", null);
    const e1_lower = std.mem.order(u8, &e1.id, &e2.id) == .lt;
    const lower = if (e1_lower) e1 else e2;
    const higher = if (e1_lower) e2 else e1;

    try std.testing.expectEqual(IngestResult.added, try store.ingest(gpa, higher, .{}));
    // The lexicographically lower id wins the tie and replaces the stored one.
    try std.testing.expectEqual(IngestResult.replaced, try store.ingest(gpa, lower, .{}));
    try std.testing.expect(try store.hasEvent(lower.id));
    try std.testing.expect(!(try store.hasEvent(higher.id)));
    // Re-ingesting the higher id now loses the tie.
    try std.testing.expectEqual(IngestResult.stale, try store.ingest(gpa, higher, .{}));
}

test "store: ingest parameterized-replaceable is keyed by the d tag" {
    const gpa = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "ingest-param.mdb", &buf);
    defer store.deinit();

    const d_profile = [_]Tag{&[_][]const u8{ "d", "profile" }};
    const d_other = [_]Tag{&[_][]const u8{ "d", "other" }};
    const a1 = try event.create(gpa, signer, kp, 1000, 30000, &d_profile, "a1", null);
    const a2 = try event.create(gpa, signer, kp, 2000, 30000, &d_profile, "a2", null);
    const b1 = try event.create(gpa, signer, kp, 1500, 30000, &d_other, "b1", null);

    try std.testing.expectEqual(IngestResult.added, try store.ingest(gpa, a1, .{}));
    try std.testing.expectEqual(IngestResult.added, try store.ingest(gpa, b1, .{}));
    // a2 replaces a1 (same d), b1 is a different coordinate and untouched.
    try std.testing.expectEqual(IngestResult.replaced, try store.ingest(gpa, a2, .{}));
    try std.testing.expect(!(try store.hasEvent(a1.id)));
    try std.testing.expect(try store.hasEvent(a2.id));
    try std.testing.expect(try store.hasEvent(b1.id));

    var r = try store.query(gpa, .{ .authors = &[_][32]u8{kp.public_key}, .kinds = &[_]u16{30000} });
    defer r.deinit();
    try std.testing.expectEqual(@as(usize, 2), r.events.len);
}

test "store: ingest does not persist ephemeral events" {
    const gpa = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    var store = try openTempStore(&tmp, "ingest-ephemeral.mdb", &buf);
    defer store.deinit();

    const eph = try event.create(gpa, signer, kp, 1000, 20000, &[_]Tag{}, "ephemeral", null);
    try std.testing.expectEqual(IngestResult.ephemeral, try store.ingest(gpa, eph, .{}));
    try std.testing.expect(!(try store.hasEvent(eph.id)));
}
