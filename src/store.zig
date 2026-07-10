//! Local-first event store over LMDB.
//!
//! This is the storage-engine foundation for the local-first cache described
//! in milestone A4: a zero-copy, memory-mapped key/value engine that later
//! layers build on (event blobs keyed by id, secondary indexes by
//! author/kind/created_at/tags, and a filter-driven query API served entirely
//! from the local database).
//!
//! This module currently exposes the environment lifecycle (`open`/`deinit`)
//! and raw key/value round-trips inside LMDB transactions. Event-aware storage
//! and indexing are added in subsequent changes on top of this surface.

const std = @import("std");
const c = @import("lmdb");

pub const Error = error{
    /// LMDB returned a non-success, non-`NOTFOUND` status code.
    Lmdb,
    OutOfMemory,
};

/// A handle to an open LMDB environment (a single memory-mapped database file).
pub const Store = struct {
    env: *c.MDB_env,

    pub const OpenOptions = struct {
        /// Upper bound on the memory map (and thus the on-disk database) size.
        /// LMDB reserves this as virtual address space, not physical memory,
        /// so a generous default is cheap. Defaults to 1 GiB.
        map_size: usize = 1 << 30,
        /// Maximum number of named sub-databases. Each secondary index added
        /// by later layers lives in its own named database. Defaults to 16.
        max_dbs: u32 = 16,
    };

    /// Opens (creating if necessary) the LMDB environment at `path`. The path
    /// is treated as a single file (`MDB_NOSUBDIR`) rather than a directory.
    pub fn open(path: [*:0]const u8, options: OpenOptions) Error!Store {
        var env: ?*c.MDB_env = null;
        try check(c.mdb_env_create(&env));
        errdefer c.mdb_env_close(env);
        try check(c.mdb_env_set_mapsize(env, options.map_size));
        try check(c.mdb_env_set_maxdbs(env, @intCast(options.max_dbs)));
        try check(c.mdb_env_open(env, path, @intCast(c.MDB_NOSUBDIR), 0o644));
        return .{ .env = env.? };
    }

    /// Flushes and closes the environment. The handle is invalid afterwards.
    pub fn deinit(self: *Store) void {
        c.mdb_env_close(self.env);
        self.* = undefined;
    }

    /// Stores `value` under `key` in the unnamed default database, committing
    /// the write. An existing value for `key` is overwritten.
    pub fn put(self: *Store, key: []const u8, value: []const u8) Error!void {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, 0, &txn));
        errdefer c.mdb_txn_abort(txn);
        var dbi: c.MDB_dbi = 0;
        try check(c.mdb_dbi_open(txn, null, 0, &dbi));
        var k = val(key);
        var v = val(value);
        try check(c.mdb_put(txn, dbi, &k, &v, 0));
        try check(c.mdb_txn_commit(txn));
    }

    /// Looks up `key`. Returns a caller-owned copy of the value (allocated with
    /// `allocator`), or null if the key is absent. Zero-copy views into the
    /// memory map are introduced by a later layer; here we copy the bytes out
    /// so the result outlives the read transaction.
    pub fn get(self: *Store, allocator: std.mem.Allocator, key: []const u8) Error!?[]u8 {
        var txn: ?*c.MDB_txn = null;
        try check(c.mdb_txn_begin(self.env, null, @intCast(c.MDB_RDONLY), &txn));
        defer c.mdb_txn_abort(txn);
        var dbi: c.MDB_dbi = 0;
        try check(c.mdb_dbi_open(txn, null, 0, &dbi));
        var k = val(key);
        var v: c.MDB_val = undefined;
        const rc = c.mdb_get(txn, dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try check(rc);
        if (v.mv_size == 0) return try allocator.dupe(u8, "");
        const bytes = @as([*]const u8, @ptrCast(v.mv_data.?))[0..v.mv_size];
        return try allocator.dupe(u8, bytes);
    }
};

/// Wraps a byte slice as an `MDB_val` for passing to LMDB. LMDB does not mutate
/// key/value inputs, so casting away const is sound here.
fn val(bytes: []const u8) c.MDB_val {
    return .{ .mv_size = bytes.len, .mv_data = @ptrCast(@constCast(bytes.ptr)) };
}

/// Translates an LMDB status code into a Zig error. `MDB_SUCCESS` (0) is Ok.
fn check(rc: c_int) Error!void {
    if (rc == c.MDB_SUCCESS) return;
    return error.Lmdb;
}

test "store: open, put, and get round-trip through LMDB" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buf);
    const dir_path = dir_buf[0..dir_len];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/store.mdb", .{dir_path});

    var store = try Store.open(path.ptr, .{});
    defer store.deinit();

    try store.put("hello", "world");

    const got = try store.get(std.testing.allocator, "hello");
    defer if (got) |g| std.testing.allocator.free(g);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("world", got.?);

    // Overwrite replaces the previous value.
    try store.put("hello", "nostr");
    const got2 = try store.get(std.testing.allocator, "hello");
    defer if (got2) |g| std.testing.allocator.free(g);
    try std.testing.expectEqualStrings("nostr", got2.?);

    // Absent keys return null rather than an error.
    const missing = try store.get(std.testing.allocator, "absent");
    try std.testing.expect(missing == null);
}

test "store: data persists across reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buf);
    const dir_path = dir_buf[0..dir_len];
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/persist.mdb", .{dir_path});

    {
        var store = try Store.open(path.ptr, .{});
        defer store.deinit();
        try store.put("key", "durable");
    }
    {
        var store = try Store.open(path.ptr, .{});
        defer store.deinit();
        const got = try store.get(std.testing.allocator, "key");
        defer if (got) |g| std.testing.allocator.free(g);
        try std.testing.expectEqualStrings("durable", got.?);
    }
}
