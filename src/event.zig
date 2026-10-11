//! NIP-01 event model: the `Event` struct, canonical serialization for id
//! hashing, and wire-format JSON encode/decode.

const std = @import("std");
const hex = @import("hex.zig");
const keys = @import("keys.zig");

pub const Error = error{
    InvalidJson,
    InvalidHex,
    InvalidLength,
} || std.mem.Allocator.Error;

/// A single tag: an array of one or more strings (name + arbitrary fields).
pub const Tag = []const []const u8;

pub const Event = struct {
    id: [32]u8,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
    sig: [64]u8,
};

// -- Serialization ------------------------------------------------------------
//
// Every serializer below writes through a `std.Io.Writer`, so the same code
// fills a caller's buffer (`Writer.fixed`), an exactly sized allocation, or a
// SHA-256 state with a small stack buffer in front of it, which is how
// `computeId` hashes an event without allocating. The `...Len` functions
// return the exact byte count the matching writer produces, so a caller can
// size a buffer before writing into it.

const Writer = std.Io.Writer;

const Lane = @Vector(16, u8);

/// Index of the first byte at or after `from` that a JSON string cannot carry
/// raw: a quote, a backslash or a control byte. `s.len` when there is none.
fn nextSpecial(s: []const u8, from: usize) usize {
    var i = from;
    while (i + 16 <= s.len) : (i += 16) {
        const v: Lane = s[i..][0..16].*;
        const m: u16 = @as(u16, @bitCast(v < @as(Lane, @splat(0x20)))) |
            @as(u16, @bitCast(v == @as(Lane, @splat('"')))) |
            @as(u16, @bitCast(v == @as(Lane, @splat('\\'))));
        if (m != 0) return i + @ctz(m);
    }
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c < 0x20 or c == '"' or c == '\\') return i;
    }
    return s.len;
}

/// The escape for a byte `nextSpecial` stopped at. A six-byte buffer holds
/// the longest, `\u00XX`.
fn escapeFor(c: u8, buf: *[6]u8) []const u8 {
    const short: u8 = switch (c) {
        '\n' => 'n',
        '"' => '"',
        '\\' => '\\',
        '\r' => 'r',
        '\t' => 't',
        0x08 => 'b',
        0x0C => 'f',
        else => 0,
    };
    buf[0] = '\\';
    if (short != 0) {
        buf[1] = short;
        return buf[0..2];
    }
    buf[1..4].* = "u00".*;
    buf[4] = hex_digits[c >> 4];
    buf[5] = hex_digits[c & 0xf];
    return buf[0..6];
}

fn escapedLen(s: []const u8) usize {
    var n: usize = s.len + 2;
    var i = nextSpecial(s, 0);
    while (i < s.len) : (i = nextSpecial(s, i + 1)) {
        n += switch (s[i]) {
            '\n', '"', '\\', '\r', '\t', 0x08, 0x0C => 1,
            else => 5,
        };
    }
    return n;
}

/// Writes `s` as a quoted JSON string, escaped the way the id serialization
/// needs.
///
/// NIP-01 names seven escapes (`\n \" \\ \r \t \b \f`) and says all other
/// characters must be included verbatim. Read literally that leaves a byte
/// below 0x20 sitting raw inside a JSON string, and RFC 8259 forbids exactly
/// that, so the wire form would not be JSON and no relay could parse it.
///
/// The sentence also does not describe what the network does. nostr-tools
/// builds the preimage with `JSON.stringify` and go-nostr writes the same
/// behaviour by hand in `escapeString`, so both escape every remaining
/// control byte as `\u00XX`. Following the sentence instead of the
/// implementations produces an id nothing else reproduces, which turns a
/// correctly signed event from any JS or Go client into a bad signature here
/// and makes our own ids unverifiable everywhere else.
///
/// So the remaining control bytes are escaped as `\u00XX`. Everything from
/// 0x20 up, raw UTF-8 included, is still copied verbatim, which is where the
/// warning against a general-purpose encoder still holds: escaping non-ASCII
/// would change the id. The wire JSON wants the same bytes.
fn writeJsonString(w: *Writer, s: []const u8) Writer.Error!void {
    try w.writeByte('"');
    var start: usize = 0;
    var i = nextSpecial(s, 0);
    var esc: [6]u8 = undefined;
    while (i < s.len) : (i = nextSpecial(s, start)) {
        try w.writeAll(s[start..i]);
        try w.writeAll(escapeFor(s[i], &esc));
        start = i + 1;
    }
    try w.writeAll(s[start..]);
    try w.writeByte('"');
}

const hex_digits = "0123456789abcdef";

fn writeHex(w: *Writer, comptime n: usize, bytes: *const [n]u8) Writer.Error!void {
    var out: [n * 2]u8 = undefined;
    for (bytes, 0..) |b, i| {
        out[2 * i] = hex_digits[b >> 4];
        out[2 * i + 1] = hex_digits[b & 0xf];
    }
    try w.writeAll(&out);
}

/// Decimal digits of `v`, written from the back of `buf`.
fn intDigits(v: i64, buf: *[20]u8) []const u8 {
    var mag: u64 = @abs(v);
    var i: usize = buf.len;
    while (true) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(mag % 10));
        mag /= 10;
        if (mag == 0) break;
    }
    if (v < 0) {
        i -= 1;
        buf[i] = '-';
    }
    return buf[i..];
}

fn intLen(v: i64) usize {
    var buf: [20]u8 = undefined;
    return intDigits(v, &buf).len;
}

fn writeInt(w: *Writer, v: i64) Writer.Error!void {
    var buf: [20]u8 = undefined;
    try w.writeAll(intDigits(v, &buf));
}

fn tagsLen(tags: []const Tag) usize {
    var n: usize = 2;
    for (tags, 0..) |tag, ti| {
        n += @as(usize, @intFromBool(ti != 0)) + 2;
        for (tag, 0..) |field, fi| n += @as(usize, @intFromBool(fi != 0)) + escapedLen(field);
    }
    return n;
}

fn writeTags(w: *Writer, tags: []const Tag) Writer.Error!void {
    try w.writeByte('[');
    for (tags, 0..) |tag, ti| {
        if (ti != 0) try w.writeByte(',');
        try w.writeByte('[');
        for (tag, 0..) |field, fi| {
            if (fi != 0) try w.writeByte(',');
            try writeJsonString(w, field);
        }
        try w.writeByte(']');
    }
    try w.writeByte(']');
}

/// The exact length of the canonical serialization `writeCanonical` writes.
pub fn canonicalLen(created_at: i64, kind: u16, tags: []const Tag, content: []const u8) usize {
    // `[0,"` + 64 hex + `",` + created_at + `,` + kind + `,` + tags + `,` + content + `]`
    return 4 + 64 + 2 + intLen(created_at) + 1 + intLen(kind) + 1 + tagsLen(tags) + 1 + escapedLen(content) + 1;
}

/// Writes the canonical `[0,pubkey,created_at,kind,tags,content]`
/// serialization (used only for id hashing, per NIP-01) to `w`. With
/// `Writer.fixed` over a buffer of `canonicalLen` bytes it allocates nothing.
pub fn writeCanonical(
    w: *Writer,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) Writer.Error!void {
    try w.writeAll("[0,\"");
    try writeHex(w, 32, &pubkey);
    try w.writeAll("\",");
    try writeInt(w, created_at);
    try w.writeByte(',');
    try writeInt(w, kind);
    try w.writeByte(',');
    try writeTags(w, tags);
    try w.writeByte(',');
    try writeJsonString(w, content);
    try w.writeByte(']');
}

/// Appends the canonical `[0,pubkey,created_at,kind,tags,content]`
/// serialization (used only for id hashing, per NIP-01) to `list`.
pub fn appendCanonical(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error!void {
    const len = canonicalLen(created_at, kind, tags, content);
    try list.ensureUnusedCapacity(allocator, len);
    var w: Writer = .fixed(list.unusedCapacitySlice()[0..len]);
    writeCanonical(&w, pubkey, created_at, kind, tags, content) catch unreachable;
    list.items.len += len;
}

/// Returns the owned canonical serialization bytes (for inspection/testing).
pub fn serializeCanonical(
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, canonicalLen(created_at, kind, tags, content));
    var w: Writer = .fixed(out);
    writeCanonical(&w, pubkey, created_at, kind, tags, content) catch unreachable;
    return out;
}

/// Computes the NIP-01 event id: sha256 of the canonical serialization.
///
/// The serialization streams through a stack buffer into the hash, so this
/// allocates nothing; `allocator` is kept for the signature callers already
/// use, and the error set with it.
pub fn computeId(
    allocator: std.mem.Allocator,
    pubkey: [32]u8,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
) std.mem.Allocator.Error![32]u8 {
    _ = allocator;
    return idOf(pubkey, created_at, kind, tags, content);
}

fn idOf(pubkey: [32]u8, created_at: i64, kind: u16, tags: []const Tag, content: []const u8) [32]u8 {
    var buf: [1024]u8 = undefined;
    var hashing: Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buf);
    // The hashing writer's drain cannot fail.
    writeCanonical(&hashing.writer, pubkey, created_at, kind, tags, content) catch unreachable;
    hashing.writer.flush() catch unreachable;
    var id: [32]u8 = undefined;
    hashing.hasher.final(&id);
    return id;
}

/// Builds and signs an event: computes the canonical id from `keypair`'s
/// public key and the given fields, then signs that id with `keypair`'s
/// secret key. `aux_rand`, when provided, is 32 bytes of fresh randomness
/// (recommended — see `keys.Signer.sign`).
pub fn create(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    created_at: i64,
    kind: u16,
    tags: []const Tag,
    content: []const u8,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error)!Event {
    const id = try computeId(allocator, keypair.public_key, created_at, kind, tags, content);
    const sig = try signer.signId(id, keypair, aux_rand);
    return Event{
        .id = id,
        .pubkey = keypair.public_key,
        .created_at = created_at,
        .kind = kind,
        .tags = tags,
        .content = content,
        .sig = sig,
    };
}

/// Verifies an event: recomputes the canonical id from its fields (rejecting
/// any event whose `id` doesn't match its own content — a forged or
/// corrupted id), then verifies `sig` against that id and `pubkey`.
pub fn verify(allocator: std.mem.Allocator, signer: keys.Signer, ev: Event) std.mem.Allocator.Error!bool {
    const computed_id = try computeId(allocator, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    if (!std.mem.eql(u8, &computed_id, &ev.id)) return false;
    return signer.verifyId(ev.sig, ev.id, ev.pubkey);
}

const json_id = "{\"id\":\"";
const json_pubkey = "\",\"pubkey\":\"";
const json_created_at = "\",\"created_at\":";
const json_kind = ",\"kind\":";
const json_tags = ",\"tags\":";
const json_content = ",\"content\":";
const json_sig = ",\"sig\":\"";
const json_end = "\"}";

/// The exact length of the wire JSON `writeJson` writes.
pub fn jsonLen(event: Event) usize {
    return json_id.len + 64 + json_pubkey.len + 64 + json_created_at.len + intLen(event.created_at) +
        json_kind.len + intLen(event.kind) + json_tags.len + tagsLen(event.tags) +
        json_content.len + escapedLen(event.content) + json_sig.len + 128 + json_end.len;
}

/// Writes a full `Event` as wire-format JSON (`{"id":...,...}`) to `w`. With
/// `Writer.fixed` over a buffer of `jsonLen` bytes it allocates nothing.
pub fn writeJson(w: *Writer, event: Event) Writer.Error!void {
    try w.writeAll(json_id);
    try writeHex(w, 32, &event.id);
    try w.writeAll(json_pubkey);
    try writeHex(w, 32, &event.pubkey);
    try w.writeAll(json_created_at);
    try writeInt(w, event.created_at);
    try w.writeAll(json_kind);
    try writeInt(w, event.kind);
    try w.writeAll(json_tags);
    try writeTags(w, event.tags);
    try w.writeAll(json_content);
    try writeJsonString(w, event.content);
    try w.writeAll(json_sig);
    try writeHex(w, 64, &event.sig);
    try w.writeAll(json_end);
}

/// Serializes a full `Event` to wire-format JSON (`{"id":...,...}`), in one
/// allocation of exactly the right size.
pub fn toJson(allocator: std.mem.Allocator, event: Event) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, jsonLen(event));
    var w: Writer = .fixed(out);
    writeJson(&w, event) catch unreachable;
    return out;
}

/// The seven fields NIP-01 names. An event object may carry other keys beside
/// them (some relays and clients add their own), and they are skipped rather
/// than refused: the id and the signature cover these seven and nothing else,
/// so an extra key cannot change what was signed. A key named twice is still
/// refused, because then it is ambiguous which value the signature covers.
const WireEvent = struct {
    id: []const u8,
    pubkey: []const u8,
    created_at: i64,
    kind: u16,
    tags: []const []const []const u8,
    content: []const u8,
    sig: []const u8,
};

const wire_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };

pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    value: Event,

    pub fn deinit(self: *Parsed) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Parses wire-format event JSON. The returned `Parsed` owns every byte the
/// Parses wire-format event JSON. The returned `Parsed` owns every byte the
/// event points at, in one arena, so `json_text` may be freed or reused as soon
/// as this returns. Call `deinit` to free it.
///
/// The text is copied into the arena once and read by `scanEvent`, which
/// decodes each string in place in that copy and builds the event without a
/// JSON tree. Anything it does not take on the first pass (a missing or
/// repeated field, a number written as `1e3`, bad hex, malformed JSON) is
/// parsed again by `std.json`, so what is accepted and every error returned
/// are exactly what the `std.json` path alone gives.
pub fn fromJson(gpa: std.mem.Allocator, json_text: []const u8) !Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const allocator = arena.allocator();

    const owned_text = try allocator.dupe(u8, json_text);
    if (scanEvent(allocator, owned_text)) |ev| {
        return .{ .arena = arena, .value = ev };
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Unsupported => {},
    }

    // The scan decoded strings in place, so the copy is no longer the text.
    _ = arena.reset(.retain_capacity);
    const fresh = try allocator.dupe(u8, json_text);
    const wire = try std.json.parseFromSliceLeaky(WireEvent, allocator, fresh, wire_options);
    return .{ .arena = arena, .value = try fromWire(wire) };
}

/// `Unsupported` means only "not on the fast path": the caller parses the
/// same text with `std.json`, which decides whether it is an event.
const ScanError = error{Unsupported} || std.mem.Allocator.Error;

/// Reads one NIP-01 event object out of `buf`, which it owns and may write.
///
/// Strings are decoded in place: an escape is never shorter than what it
/// decodes to, so the decoded bytes always fit behind the read position. Every
/// slice in the returned event points into `buf` or into `allocator`.
///
/// The contract that matters is one way: whatever this accepts, `std.json`
/// accepts too, with the same result. It holds itself to the same grammar
/// (whitespace, number syntax, escapes, surrogate pairs, UTF-8, nothing after
/// the object) and hands everything else back as `Unsupported`, including
/// forms `std.json` would take but that no event in practice uses: a
/// number in a string or with a fraction, a
/// string spelled as an array of bytes. The differential tests in this file
/// and in `fuzz.zig` hold it to that.
fn scanEvent(allocator: std.mem.Allocator, buf: []u8) ScanError!Event {
    var s: Scanner = .{ .buf = buf };
    var ev: Event = undefined;
    var seen: u7 = 0;

    s.skipWs();
    try s.expect('{');
    s.skipWs();
    if (s.peek() != '"') return error.Unsupported;
    while (true) {
        if (s.peek() != '"') return error.Unsupported;
        const key = try s.string();
        s.skipWs();
        try s.expect(':');
        s.skipWs();
        const field: u7 = fieldBit(key);
        if (field != 0) {
            if (seen & field != 0) return error.Unsupported;
            seen |= field;
        }
        switch (field) {
            0 => try s.skipValue(0),
            bit_id => ev.id = try s.hexString(32),
            bit_pubkey => ev.pubkey = try s.hexString(32),
            bit_sig => ev.sig = try s.hexString(64),
            bit_created_at => ev.created_at = try s.int(i64),
            bit_kind => ev.kind = try s.int(u16),
            bit_content => {
                if (s.peek() != '"') return error.Unsupported;
                ev.content = try s.string();
            },
            bit_tags => ev.tags = try s.tags(allocator),
            else => unreachable,
        }
        s.skipWs();
        switch (s.peek()) {
            ',' => {
                s.i += 1;
                s.skipWs();
            },
            '}' => {
                s.i += 1;
                break;
            },
            else => return error.Unsupported,
        }
    }
    s.skipWs();
    if (s.i != buf.len) return error.Unsupported;
    if (seen != all_fields) return error.Unsupported;
    return ev;
}

const bit_id: u7 = 1;
const bit_pubkey: u7 = 2;
const bit_created_at: u7 = 4;
const bit_kind: u7 = 8;
const bit_tags: u7 = 16;
const bit_content: u7 = 32;
const bit_sig: u7 = 64;
const all_fields: u7 = 127;

fn fieldBit(key: []const u8) u7 {
    const eql = std.mem.eql;
    return switch (key.len) {
        2 => if (eql(u8, key, "id")) bit_id else 0,
        3 => if (eql(u8, key, "sig")) bit_sig else 0,
        4 => if (eql(u8, key, "kind")) bit_kind else if (eql(u8, key, "tags")) bit_tags else 0,
        6 => if (eql(u8, key, "pubkey")) bit_pubkey else 0,
        7 => if (eql(u8, key, "content")) bit_content else 0,
        10 => if (eql(u8, key, "created_at")) bit_created_at else 0,
        else => 0,
    };
}

/// How deep a skipped value may nest before the fast path gives it to
/// `std.json`, which has no limit of its own beyond memory.
const max_skip_depth = 64;

const Scanner = struct {
    buf: []u8,
    i: usize = 0,

    /// The byte at the cursor, or 0 at the end, which no branch takes.
    inline fn peek(s: *const Scanner) u8 {
        return if (s.i < s.buf.len) s.buf[s.i] else 0;
    }

    inline fn expect(s: *Scanner, c: u8) error{Unsupported}!void {
        if (s.peek() != c) return error.Unsupported;
        s.i += 1;
    }

    /// JSON whitespace is these four bytes and nothing else.
    inline fn skipWs(s: *Scanner) void {
        while (s.i < s.buf.len) : (s.i += 1) {
            switch (s.buf[s.i]) {
                ' ', '\t', '\n', '\r' => {},
                else => return,
            }
        }
    }

    /// Reads the string whose opening quote is at the cursor and returns it
    /// decoded, in place.
    fn string(s: *Scanner) error{Unsupported}![]u8 {
        const buf = s.buf;
        const start = s.i + 1;
        var i = start;
        var high: u8 = 0;
        var lanes: Lane = @splat(0);

        // The common case: a run with no escape, ended by its quote, which is
        // a slice of the text as it stands.
        while (i + 16 <= buf.len) {
            const v: Lane = buf[i..][0..16].*;
            const m = specialMask(v);
            lanes |= v;
            if (m != 0) {
                i += @ctz(m);
                break;
            }
            i += 16;
        } else {
            while (i < buf.len) : (i += 1) {
                const c = buf[i];
                if (c < 0x20 or c == '"' or c == '\\') break;
                high |= c;
            }
        }
        if (i >= buf.len) return error.Unsupported;
        high |= @reduce(.Or, lanes);

        var end = i;
        switch (buf[i]) {
            '"' => {},
            '\\' => {
                // From the first escape on, bytes move down to `w` as they are
                // decoded.
                var w = i;
                while (true) {
                    if (i >= buf.len) return error.Unsupported;
                    switch (buf[i]) {
                        '"' => break,
                        '\\' => {
                            if (i + 1 >= buf.len) return error.Unsupported;
                            const e = buf[i + 1];
                            i += 2;
                            switch (e) {
                                '"', '\\', '/' => {
                                    buf[w] = e;
                                    w += 1;
                                },
                                'b' => {
                                    buf[w] = 0x08;
                                    w += 1;
                                },
                                'f' => {
                                    buf[w] = 0x0C;
                                    w += 1;
                                },
                                'n' => {
                                    buf[w] = '\n';
                                    w += 1;
                                },
                                'r' => {
                                    buf[w] = '\r';
                                    w += 1;
                                },
                                't' => {
                                    buf[w] = '\t';
                                    w += 1;
                                },
                                'u' => {
                                    var cp: u21 = try hex4(buf, i);
                                    i += 4;
                                    if (cp >= 0xD800 and cp <= 0xDBFF) {
                                        // A high surrogate must be followed at
                                        // once by an escaped low one.
                                        if (i + 2 > buf.len or buf[i] != '\\' or buf[i + 1] != 'u') return error.Unsupported;
                                        const lo = try hex4(buf, i + 2);
                                        if (lo < 0xDC00 or lo > 0xDFFF) return error.Unsupported;
                                        i += 6;
                                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    } else if (cp >= 0xDC00 and cp <= 0xDFFF) {
                                        return error.Unsupported;
                                    }
                                    w += encodeUtf8(cp, buf[w..]);
                                },
                                else => return error.Unsupported,
                            }
                        },
                        else => {
                            const run_end = nextSpecial(buf, i);
                            if (run_end >= buf.len or buf[run_end] < 0x20) return error.Unsupported;
                            for (buf[i..run_end]) |c| high |= c;
                            std.mem.copyForwards(u8, buf[w..], buf[i..run_end]);
                            w += run_end - i;
                            i = run_end;
                        },
                    }
                }
                end = w;
            },
            else => return error.Unsupported,
        }
        const out = buf[start..end];
        // Raw bytes from 0x80 up have to be well formed UTF-8, as `std.json`
        // requires. A decoded `\u` escape is always well formed and never
        // completes or continues a raw sequence, so checking the decoded bytes
        // checks the raw ones.
        if (high >= 0x80 and !std.unicode.utf8ValidateSlice(out)) return error.Unsupported;
        s.i = i + 1;
        return out;
    }

    /// A string of exactly `n * 2` hex digits, decoded. Upper case is
    /// accepted, as `hex.decodeFixed` accepts it.
    fn hexString(s: *Scanner, comptime n: usize) error{Unsupported}![n]u8 {
        const buf = s.buf;
        if (s.peek() != '"') return error.Unsupported;
        const start = s.i + 1;
        if (start + n * 2 >= buf.len or buf[start + n * 2] != '"') return error.Unsupported;
        var out: [n]u8 = undefined;
        var bad: u8 = 0;
        for (&out, 0..) |*b, k| {
            const hi = hex_values[buf[start + 2 * k]];
            const lo = hex_values[buf[start + 2 * k + 1]];
            bad |= hi | lo;
            b.* = (hi << 4) | (lo & 0xf);
        }
        if (bad & 0x80 != 0) return error.Unsupported;
        s.i = start + n * 2 + 1;
        return out;
    }

    /// A number written as a plain integer, in range for `T`. A fraction or
    /// an exponent, even one that comes out whole, is left to `std.json`.
    fn int(s: *Scanner, comptime T: type) error{Unsupported}!T {
        const buf = s.buf;
        var i = s.i;
        const neg = i < buf.len and buf[i] == '-';
        if (neg) {
            if (@typeInfo(T).int.signedness == .unsigned) return error.Unsupported;
            i += 1;
        }
        if (i >= buf.len or buf[i] < '0' or buf[i] > '9') return error.Unsupported;
        var mag: u64 = 0;
        if (buf[i] == '0') {
            i += 1;
        } else {
            while (i < buf.len and buf[i] >= '0' and buf[i] <= '9') : (i += 1) {
                const m = @mulWithOverflow(mag, 10);
                const a = @addWithOverflow(m[0], buf[i] - '0');
                if (m[1] != 0 or a[1] != 0) return error.Unsupported;
                mag = a[0];
            }
        }
        if (i < buf.len) switch (buf[i]) {
            '.', 'e', 'E', '0'...'9' => return error.Unsupported,
            else => {},
        };
        s.i = i;
        if (neg) {
            if (mag > @as(u64, std.math.maxInt(T)) + 1) return error.Unsupported;
            return @intCast(-@as(i128, mag));
        }
        if (mag > std.math.maxInt(T)) return error.Unsupported;
        return @intCast(mag);
    }

    /// `[[string, ...], ...]`, into one array of tags over one array of
    /// strings, both in `allocator`. Most events have few enough that the
    /// work lists stay on the stack.
    fn tags(s: *Scanner, allocator: std.mem.Allocator) ScanError![]const Tag {
        try s.expect('[');
        s.skipWs();
        if (s.peek() == ']') {
            s.i += 1;
            return &.{};
        }
        var field_stack: [64][]const u8 = undefined;
        var end_stack: [32]u32 = undefined;
        var fields: std.ArrayList([]const u8) = .initBuffer(&field_stack);
        var ends: std.ArrayList(u32) = .initBuffer(&end_stack);
        while (true) {
            try s.expect('[');
            s.skipWs();
            if (s.peek() == ']') {
                s.i += 1;
            } else while (true) {
                if (s.peek() != '"') return error.Unsupported;
                const str = try s.string();
                if (fields.items.len == fields.capacity) try spill([]const u8, allocator, &fields);
                fields.appendAssumeCapacity(str);
                s.skipWs();
                switch (s.peek()) {
                    ',' => {
                        s.i += 1;
                        s.skipWs();
                    },
                    ']' => {
                        s.i += 1;
                        break;
                    },
                    else => return error.Unsupported,
                }
            }
            if (ends.items.len == ends.capacity) try spill(u32, allocator, &ends);
            ends.appendAssumeCapacity(@intCast(fields.items.len));
            s.skipWs();
            switch (s.peek()) {
                ',' => {
                    s.i += 1;
                    s.skipWs();
                },
                ']' => {
                    s.i += 1;
                    break;
                },
                else => return error.Unsupported,
            }
        }
        const flat = try allocator.dupe([]const u8, fields.items);
        const out = try allocator.alloc(Tag, ends.items.len);
        var from: usize = 0;
        for (out, ends.items) |*tag, to| {
            tag.* = flat[from..to];
            from = to;
        }
        return out;
    }

    /// Steps over any JSON value, checking it the way `std.json` would.
    fn skipValue(s: *Scanner, depth: usize) error{Unsupported}!void {
        if (depth > max_skip_depth) return error.Unsupported;
        switch (s.peek()) {
            '"' => _ = try s.string(),
            '{' => {
                s.i += 1;
                s.skipWs();
                if (s.peek() == '}') {
                    s.i += 1;
                    return;
                }
                while (true) {
                    if (s.peek() != '"') return error.Unsupported;
                    _ = try s.string();
                    s.skipWs();
                    try s.expect(':');
                    s.skipWs();
                    try s.skipValue(depth + 1);
                    s.skipWs();
                    switch (s.peek()) {
                        ',' => {
                            s.i += 1;
                            s.skipWs();
                        },
                        '}' => {
                            s.i += 1;
                            return;
                        },
                        else => return error.Unsupported,
                    }
                }
            },
            '[' => {
                s.i += 1;
                s.skipWs();
                if (s.peek() == ']') {
                    s.i += 1;
                    return;
                }
                while (true) {
                    try s.skipValue(depth + 1);
                    s.skipWs();
                    switch (s.peek()) {
                        ',' => {
                            s.i += 1;
                            s.skipWs();
                        },
                        ']' => {
                            s.i += 1;
                            return;
                        },
                        else => return error.Unsupported,
                    }
                }
            },
            't' => try s.literal("true"),
            'f' => try s.literal("false"),
            'n' => try s.literal("null"),
            '-', '0'...'9' => try s.number(),
            else => return error.Unsupported,
        }
    }

    fn literal(s: *Scanner, comptime word: []const u8) error{Unsupported}!void {
        if (!std.mem.startsWith(u8, s.buf[s.i..], word)) return error.Unsupported;
        s.i += word.len;
    }

    /// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`
    fn number(s: *Scanner) error{Unsupported}!void {
        if (s.peek() == '-') s.i += 1;
        switch (s.peek()) {
            '0' => s.i += 1,
            '1'...'9' => s.digits(),
            else => return error.Unsupported,
        }
        if (s.peek() == '.') {
            s.i += 1;
            if (!isDigit(s.peek())) return error.Unsupported;
            s.digits();
        }
        if (s.peek() == 'e' or s.peek() == 'E') {
            s.i += 1;
            if (s.peek() == '+' or s.peek() == '-') s.i += 1;
            if (!isDigit(s.peek())) return error.Unsupported;
            s.digits();
        }
    }

    fn digits(s: *Scanner) void {
        while (isDigit(s.peek())) s.i += 1;
    }
};

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

/// Moves a full work list off the stack, or doubles one already moved.
fn spill(comptime T: type, allocator: std.mem.Allocator, list: *std.ArrayList(T)) std.mem.Allocator.Error!void {
    const bigger = try allocator.alloc(T, list.capacity * 2);
    @memcpy(bigger[0..list.items.len], list.items);
    list.* = .{ .items = bigger[0..list.items.len], .capacity = bigger.len };
}

fn specialMask(v: Lane) u16 {
    return @as(u16, @bitCast(v < @as(Lane, @splat(0x20)))) |
        @as(u16, @bitCast(v == @as(Lane, @splat('"')))) |
        @as(u16, @bitCast(v == @as(Lane, @splat('\\'))));
}

/// Hex digit values, with the top bit set for anything that is not one.
const hex_values: [256]u8 = blk: {
    var t = [_]u8{0x80} ** 256;
    for ('0'..'9' + 1) |c| t[c] = c - '0';
    for ('a'..'f' + 1) |c| t[c] = c - 'a' + 10;
    for ('A'..'F' + 1) |c| t[c] = c - 'A' + 10;
    break :blk t;
};

fn hex4(buf: []const u8, at: usize) error{Unsupported}!u21 {
    if (at + 4 > buf.len) return error.Unsupported;
    var v: u21 = 0;
    for (buf[at..][0..4]) |c| {
        const d = hex_values[c];
        if (d & 0x80 != 0) return error.Unsupported;
        v = (v << 4) | d;
    }
    return v;
}

/// UTF-8 for a code point that is not a surrogate. Returns the byte count.
fn encodeUtf8(cp: u21, out: []u8) usize {
    if (cp < 0x80) {
        out[0] = @intCast(cp);
        return 1;
    }
    if (cp < 0x800) {
        out[0] = @intCast(0xC0 | (cp >> 6));
        out[1] = @intCast(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = @intCast(0xE0 | (cp >> 12));
        out[1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        out[2] = @intCast(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = @intCast(0xF0 | (cp >> 18));
    out[1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
    out[2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
    out[3] = @intCast(0x80 | (cp & 0x3F));
    return 4;
}

/// Builds an `Event` from an already-parsed `std.json.Value` (which must be a
/// JSON object) into `allocator`. The returned event borrows string/tag
/// storage from `allocator`, so it must be arena-like and outlive the event.
///
/// This is the entry point the relay-message parser uses: a relay `EVENT`
/// message is a JSON array whose third element is the event object, and the
/// whole message shares one arena, so re-serializing just to call `fromJson`
/// would be wasteful.
pub fn fromValueLeaky(allocator: std.mem.Allocator, value: std.json.Value) !Event {
    const wire = try std.json.parseFromValueLeaky(WireEvent, allocator, value, wire_options);
    return fromWire(wire);
}

/// Converts the parsed wire representation into an `Event`, decoding the hex
/// id/pubkey/sig fields. Shared by `fromJson` and `fromValueLeaky`.
fn fromWire(wire: WireEvent) hex.Error!Event {
    return Event{
        .id = try hex.decodeFixed(32, wire.id),
        .pubkey = try hex.decodeFixed(32, wire.pubkey),
        .created_at = wire.created_at,
        .kind = wire.kind,
        .tags = wire.tags,
        .content = wire.content,
        .sig = try hex.decodeFixed(64, wire.sig),
    };
}

fn hexToBytes32(h: []const u8) ![32]u8 {
    return hex.decodeFixed(32, h);
}

test "canonical serialization matches a hand-computed vector" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca");
    const tags = [_]Tag{&[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://nostr.example.com" }};
    const content = "Hello, \"world\"!\n";

    const serialized = try serializeCanonical(allocator, pubkey, 1700000000, 1, &tags, content);
    defer allocator.free(serialized);

    const expected = "[0,\"f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca\",1700000000,1,[[\"e\",\"5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36\",\"wss://nostr.example.com\"]],\"Hello, \\\"world\\\"!\\n\"]";
    try std.testing.expectEqualStrings(expected, serialized);

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const expected_id = try hexToBytes32("d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40");
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}

test "canonical serialization: empty tags, mixed escapes" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const tags = [_]Tag{};
    const content = "line1\\nline2\ttab\r\n";

    const id = try computeId(allocator, pubkey, 0, 0, &tags, content);
    const expected_id = try hexToBytes32("06e17cd2f072210550eba01397803e32f3b035cb01b5400665fa282f09060106");
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}

test "control bytes escape the way the rest of the network escapes them" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const tags = [_]Tag{&[_][]const u8{ "e", "a\x02b" }};
    const content = "a\x01b\x1bc";

    // These bytes are what `JSON.stringify` produces, which is how nostr-tools
    // builds the preimage and what go-nostr's `escapeString` writes by hand.
    // Derived from an independent implementation rather than from this code, so
    // it fails if this file ever drifts back to the spec's literal wording.
    const serialized = try serializeCanonical(allocator, pubkey, 1700000000, 1, &tags, content);
    defer allocator.free(serialized);
    const expected = "[0,\"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d\",1700000000,1,[[\"e\",\"a\\u0002b\"]],\"a\\u0001b\\u001bc\"]";
    try std.testing.expectEqualStrings(expected, serialized);

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const expected_id = try hexToBytes32("d70263901ff294ef8559ce5626d7c3b216877255385fb23ba00c4b60d583fd00");
    try std.testing.expectEqualSlices(u8, &expected_id, &id);
}

test "an event carrying control bytes survives its own wire format" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d");
    const tags = [_]Tag{&[_][]const u8{ "e", "a\x02b" }};
    const content = "a\x01b\x1bc";

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const event = Event{
        .id = id,
        .pubkey = pubkey,
        .created_at = 1700000000,
        .kind = 1,
        .tags = &tags,
        .content = content,
        .sig = [_]u8{0xab} ** 64,
    };

    const json_text = try toJson(allocator, event);
    defer allocator.free(json_text);

    // The point of the test: the wire form used to carry the control bytes raw,
    // which is not JSON, so this parse failed on our own output.
    try std.testing.expect(std.mem.indexOfScalar(u8, json_text, 0x01) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, json_text, 0x1b) == null);

    var parsed = try fromJson(allocator, json_text);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(content, parsed.value.content);
    try std.testing.expectEqualStrings("a\x02b", parsed.value.tags[0][1]);
    try std.testing.expectEqualSlices(u8, &event.id, &parsed.value.id);
}

test "toJson / fromJson round trip" {
    const allocator = std.testing.allocator;
    const pubkey = try hexToBytes32("f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca");
    const tags = [_]Tag{&[_][]const u8{ "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" }};
    const content = "hello";

    const id = try computeId(allocator, pubkey, 1700000000, 1, &tags, content);
    const event = Event{
        .id = id,
        .pubkey = pubkey,
        .created_at = 1700000000,
        .kind = 1,
        .tags = &tags,
        .content = content,
        .sig = [_]u8{0xab} ** 64,
    };

    const json_text = try toJson(allocator, event);
    defer allocator.free(json_text);

    var parsed = try fromJson(allocator, json_text);
    defer parsed.deinit();

    try std.testing.expectEqualSlices(u8, &event.id, &parsed.value.id);
    try std.testing.expectEqualSlices(u8, &event.pubkey, &parsed.value.pubkey);
    try std.testing.expectEqual(event.created_at, parsed.value.created_at);
    try std.testing.expectEqual(event.kind, parsed.value.kind);
    try std.testing.expectEqualStrings(event.content, parsed.value.content);
    try std.testing.expectEqualSlices(u8, &event.sig, &parsed.value.sig);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.tags.len);
    try std.testing.expectEqualStrings("p", parsed.value.tags[0][0]);
}

test "fromJson rejects malformed hex id" {
    const allocator = std.testing.allocator;
    const bad = "{\"id\":\"zz\",\"pubkey\":\"" ++ "00" ** 32 ++ "\",\"created_at\":0,\"kind\":0,\"tags\":[],\"content\":\"\",\"sig\":\"" ++ "00" ** 64 ++ "\"}";
    try std.testing.expectError(hex.Error.InvalidHex, fromJson(allocator, bad));
}

test "an event carrying a field NIP-01 does not name still parses and verifies" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    const tags = [_]Tag{&[_][]const u8{ "t", "zig" }};
    const ev = try create(allocator, signer, kp, 1700000000, 1, &tags, "hello", null);
    const wire = try toJson(allocator, ev);
    defer allocator.free(wire);

    // The id and signature cover the seven named fields and nothing else, so
    // a key beside them, of any shape, changes nothing about the event.
    const extra = try std.mem.concat(allocator, u8, &.{
        "{\"relays\":[\"wss://relay.example\"],\"meta\":{\"n\":[1,{\"x\":null}]},",
        wire[1..],
    });
    defer allocator.free(extra);

    var parsed = try fromJson(allocator, extra);
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, &ev.id, &parsed.value.id);
    try std.testing.expectEqualStrings("hello", parsed.value.content);
    try std.testing.expect(try verify(allocator, signer, parsed.value));

    // Written back out, it is the event that was signed, without the extra key.
    const again = try toJson(allocator, parsed.value);
    defer allocator.free(again);
    try std.testing.expectEqualStrings(wire, again);
}

test "a parsed event outlives the text it was parsed from" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    // Unescaped strings are the ones a parser can hand back as slices of its
    // input, and the escaped content is the one it cannot, so both kinds are
    // here.
    const tags = [_]Tag{
        &[_][]const u8{ "e", "5c83da77af1dec6d7289834998ad7aafbd9e2191396d75ec3cc27f5a77226f36", "wss://relay.example" },
        &[_][]const u8{ "t", "zig" },
    };
    const ev = try create(allocator, signer, kp, 1700000000, 1, &tags, "plain words", null);
    const wire = try toJson(allocator, ev);
    defer allocator.free(wire);

    const text = try allocator.dupe(u8, wire);
    var parsed = parsed: {
        // Overwrite the text before freeing it as well, so the test does not
        // depend on what the allocator does with freed memory.
        defer {
            @memset(text, 'x');
            allocator.free(text);
        }
        break :parsed try fromJson(allocator, text);
    };
    defer parsed.deinit();

    try std.testing.expectEqualStrings("plain words", parsed.value.content);
    try std.testing.expectEqualStrings("zig", parsed.value.tags[1][1]);
    try std.testing.expect(try verify(allocator, signer, parsed.value));
    const again = try toJson(allocator, parsed.value);
    defer allocator.free(again);
    try std.testing.expectEqualStrings(wire, again);
}

test "an event naming the same field twice is still refused" {
    const allocator = std.testing.allocator;
    // Two contents make it ambiguous which one the signature covers.
    const twice = "{\"id\":\"" ++ "00" ** 32 ++ "\",\"pubkey\":\"" ++ "00" ** 32 ++ "\",\"created_at\":0,\"kind\":1,\"tags\":[],\"content\":\"a\",\"content\":\"b\",\"sig\":\"" ++ "00" ** 64 ++ "\"}";
    try std.testing.expectError(error.DuplicateField, fromJson(allocator, twice));
}

test "create produces a valid, self-consistent, verifiable event" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    const tags = [_]Tag{&[_][]const u8{ "p", "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" }};
    const ev = try create(allocator, signer, kp, 1700000000, 1, &tags, "hello nostr", null);

    // The id really is the canonical hash of the event's own fields.
    const expected_id = try computeId(allocator, kp.public_key, 1700000000, 1, &tags, "hello nostr");
    try std.testing.expectEqualSlices(u8, &expected_id, &ev.id);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &ev.pubkey);

    try std.testing.expect(try verify(allocator, signer, ev));
}

test "verify rejects a tampered content field" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp = try signer.generateKeyPair(std.testing.io);

    var ev = try create(allocator, signer, kp, 1700000000, 1, &[_]Tag{}, "original", null);
    ev.content = "tampered"; // id no longer matches its own content
    try std.testing.expect(!(try verify(allocator, signer, ev)));
}

test "verify rejects a signature from the wrong key" {
    const allocator = std.testing.allocator;
    var signer = try keys.Signer.initRandomized(std.testing.io);
    defer signer.deinit();
    const kp_a = try signer.generateKeyPair(std.testing.io);
    const kp_b = try signer.generateKeyPair(std.testing.io);

    var ev = try create(allocator, signer, kp_a, 1700000000, 1, &[_]Tag{}, "hello", null);
    ev.sig = try signer.signId(ev.id, kp_b, null); // sign the same id, wrong key
    try std.testing.expect(!(try verify(allocator, signer, ev)));
}

// -- The scanner and the serializers against the code they replaced ----------

const reference = @import("event_reference.zig");

/// Random events, written out with every spelling JSON allows for them, then
/// broken in small ways, for the differential test below.
const Generator = struct {
    rand: std.Random,
    arena: std.mem.Allocator,

    /// A code point, weighted towards the ones that need care: the escaped
    /// ASCII bytes, other control bytes, and multi-byte UTF-8 of every length.
    fn codePoint(g: Generator) u21 {
        const r = g.rand;
        return switch (r.uintLessThan(u8, 12)) {
            0, 1, 2, 3 => r.intRangeAtMost(u21, 0x20, 0x7e),
            4 => "\"\\/\n\r\t\x08\x0c"[r.uintLessThan(usize, 8)],
            5 => r.uintLessThan(u21, 0x20),
            6 => 0x7f,
            7 => r.intRangeAtMost(u21, 0x80, 0x7ff),
            8 => r.intRangeAtMost(u21, 0x800, 0xd7ff),
            9 => r.intRangeAtMost(u21, 0xe000, 0xffff),
            else => r.intRangeAtMost(u21, 0x10000, 0x10ffff),
        };
    }

    fn string(g: Generator) ![]const u8 {
        const r = g.rand;
        const n: usize = switch (r.uintLessThan(u8, 8)) {
            0 => 0,
            1, 2, 3 => r.uintLessThan(usize, 8),
            4, 5 => r.uintLessThan(usize, 40),
            6 => r.uintLessThan(usize, 300),
            else => 64,
        };
        var out: std.ArrayList(u8) = .empty;
        const plain = r.boolean();
        for (0..n) |_| {
            const cp: u21 = if (plain) r.intRangeAtMost(u21, 'a', 'z') else g.codePoint();
            var buf: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(cp, &buf) catch unreachable;
            try out.appendSlice(g.arena, buf[0..len]);
        }
        return out.items;
    }

    fn event(g: Generator) !Event {
        const r = g.rand;
        const tag_count: usize = switch (r.uintLessThan(u8, 6)) {
            0 => 0,
            1, 2, 3 => r.uintLessThan(usize, 6),
            4 => r.uintLessThan(usize, 40),
            else => r.uintLessThan(usize, 400),
        };
        const tags = try g.arena.alloc(Tag, tag_count);
        for (tags) |*tag| {
            const fields = try g.arena.alloc([]const u8, r.uintLessThan(usize, 6));
            for (fields) |*f| f.* = try g.string();
            tag.* = fields;
        }
        var ev: Event = .{
            .id = undefined,
            .pubkey = undefined,
            .created_at = switch (r.uintLessThan(u8, 6)) {
                0 => 0,
                1 => std.math.maxInt(i64),
                2 => std.math.minInt(i64),
                3 => -r.intRangeAtMost(i64, 1, 1000),
                else => r.int(i64),
            },
            .kind = switch (r.uintLessThan(u8, 4)) {
                0 => 0,
                1 => std.math.maxInt(u16),
                else => r.int(u16),
            },
            .tags = tags,
            .content = try g.string(),
            .sig = undefined,
        };
        r.bytes(&ev.id);
        r.bytes(&ev.pubkey);
        r.bytes(&ev.sig);
        return ev;
    }

    fn ws(g: Generator, out: *std.ArrayList(u8)) !void {
        if (g.rand.uintLessThan(u8, 4) != 0) return;
        for (0..g.rand.intRangeAtMost(usize, 1, 3)) |_| try out.append(g.arena, " \t\n\r"[g.rand.uintLessThan(usize, 4)]);
    }

    /// `s` as a JSON string, each code point spelled raw, with its short
    /// escape, or as `\u` (a surrogate pair above the BMP), at random.
    fn writeString(g: Generator, out: *std.ArrayList(u8), s: []const u8) !void {
        const r = g.rand;
        try out.append(g.arena, '"');
        var it = std.unicode.Utf8View.initUnchecked(s).iterator();
        while (it.nextCodepointSlice()) |slice| {
            const cp = std.unicode.utf8Decode(slice) catch unreachable;
            const must = cp < 0x20 or cp == '"' or cp == '\\';
            const choice = r.uintLessThan(u8, 4);
            if (choice == 0 or (must and choice == 1)) {
                if (cp >= 0x10000) {
                    const v = cp - 0x10000;
                    try out.print(g.arena, "\\u{X:0>4}\\u{x:0>4}", .{ 0xD800 + (v >> 10), 0xDC00 + (v & 0x3ff) });
                } else {
                    try out.print(g.arena, "\\u{x:0>4}", .{cp});
                }
            } else if (must or (cp == '/' and choice == 1)) {
                var esc: [6]u8 = undefined;
                try out.appendSlice(g.arena, if (cp == '/') "\\/" else escapeFor(@intCast(cp), &esc));
            } else {
                try out.appendSlice(g.arena, slice);
            }
        }
        try out.append(g.arena, '"');
    }

    fn writeHexString(g: Generator, out: *std.ArrayList(u8), bytes: []const u8) !void {
        const digits = if (g.rand.uintLessThan(u8, 8) == 0) "0123456789ABCDEF" else hex_digits;
        try out.append(g.arena, '"');
        for (bytes) |b| try out.appendSlice(g.arena, &.{ digits[b >> 4], digits[b & 0xf] });
        try out.append(g.arena, '"');
    }

    /// An event object with its fields in a random order, random whitespace,
    /// sometimes an extra key, and numbers sometimes in a form only `std.json`
    /// takes.
    fn text(g: Generator, ev: Event) ![]u8 {
        const r = g.rand;
        var out: std.ArrayList(u8) = .empty;
        var order = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
        r.shuffle(u8, &order);
        const with_extra = r.uintLessThan(u8, 4) == 0;
        try g.ws(&out);
        try out.append(g.arena, '{');
        var first = true;
        for (order) |field| {
            if (field == 7 and !with_extra) continue;
            if (!first) try out.append(g.arena, ',');
            first = false;
            try g.ws(&out);
            const name = switch (field) {
                0 => "id",
                1 => "pubkey",
                2 => "created_at",
                3 => "kind",
                4 => "tags",
                5 => "content",
                6 => "sig",
                else => "extra",
            };
            try g.writeString(&out, name);
            try g.ws(&out);
            try out.append(g.arena, ':');
            try g.ws(&out);
            switch (field) {
                0 => try g.writeHexString(&out, &ev.id),
                1 => try g.writeHexString(&out, &ev.pubkey),
                2 => try g.writeNumber(&out, ev.created_at),
                3 => try g.writeNumber(&out, ev.kind),
                4 => {
                    try out.append(g.arena, '[');
                    for (ev.tags, 0..) |tag, ti| {
                        if (ti != 0) try out.append(g.arena, ',');
                        try g.ws(&out);
                        try out.append(g.arena, '[');
                        for (tag, 0..) |f, fi| {
                            if (fi != 0) try out.append(g.arena, ',');
                            try g.ws(&out);
                            try g.writeString(&out, f);
                            try g.ws(&out);
                        }
                        try out.append(g.arena, ']');
                        try g.ws(&out);
                    }
                    try out.append(g.arena, ']');
                },
                5 => try g.writeString(&out, ev.content),
                6 => try g.writeHexString(&out, &ev.sig),
                else => try out.appendSlice(g.arena, switch (r.uintLessThan(u8, 6)) {
                    0 => "null",
                    1 => "[true,false,{\"a\":[1.5e-3,-0,0.25E+2]}]",
                    2 => "{\"nested\":{\"deeper\":[[[]]]}}",
                    3 => "\"\\u00e9\\ud83d\\ude00\"",
                    4 => "-12.5e10",
                    else => "{}",
                }),
            }
            try g.ws(&out);
        }
        try out.append(g.arena, '}');
        try g.ws(&out);
        return out.items;
    }

    fn writeNumber(g: Generator, out: *std.ArrayList(u8), v: i64) !void {
        switch (g.rand.uintLessThan(u8, 16)) {
            0 => try out.print(g.arena, "{d}.0", .{v}),
            1 => try out.print(g.arena, "\"{d}\"", .{v}),
            2 => try out.print(g.arena, "{d}e0", .{v}),
            3 => if (v == 0) try out.appendSlice(g.arena, "-0") else try out.print(g.arena, "{d}", .{v}),
            else => try out.print(g.arena, "{d}", .{v}),
        }
    }

    /// Breaks `text` the way a bad sender would: a byte changed, dropped,
    /// duplicated, or a slice of the text repeated or cut off.
    fn mutate(g: Generator, text_in: []u8) ![]u8 {
        const touchy = "\"\\{}[],:0-9eu \x00\x80\xc3\xed\xf4";
        const r = g.rand;
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(g.arena, text_in);
        for (0..r.intRangeAtMost(usize, 1, 3)) |_| {
            if (out.items.len == 0) break;
            const at = r.uintLessThan(usize, out.items.len);
            switch (r.uintLessThan(u8, 6)) {
                0 => out.items[at] = r.int(u8),
                1 => out.items[at] = touchy[r.uintLessThan(usize, touchy.len)],
                2 => _ = out.orderedRemove(at),
                3 => try out.insert(g.arena, at, out.items[at]),
                4 => out.items.len = at,
                else => {
                    const len = @min(out.items.len - at, r.uintLessThan(usize, 80));
                    try out.insertSlice(g.arena, at, try g.arena.dupe(u8, out.items[at..][0..len]));
                },
            }
        }
        return out.items;
    }
};

test "fromJson and the serializers agree with std.json on generated events" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var prng = std.Random.DefaultPrng.init(0x6576_656e_7473);
    const g: Generator = .{ .rand = prng.random(), .arena = arena_state.allocator() };

    for (0..4000) |_| {
        const ev = try g.event();
        try reference.expectSameSerialization(ev);
        const wire = try toJson(g.arena, ev);
        try reference.expectSameAsReference(wire);
        const spelled = try g.text(ev);
        try reference.expectSameAsReference(spelled);
        try reference.expectSameAsReference(try g.mutate(spelled));
        try reference.expectSameAsReference(try g.mutate(try g.arena.dupe(u8, wire)));
        _ = arena_state.reset(.retain_capacity);
    }
}

test "fromJson agrees with std.json at the edges" {
    const z32 = "\"" ++ "00" ** 32 ++ "\"";
    const z64 = "\"" ++ "00" ** 64 ++ "\"";
    const head = "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[]";
    const cases = [_][]const u8{
        head ++ ",\"created_at\":0,\"kind\":0,\"content\":\"\"}",
        head ++ ",\"created_at\":-0,\"kind\":-0,\"content\":\"\"}",
        head ++ ",\"created_at\":9223372036854775807,\"kind\":65535,\"content\":\"\"}",
        head ++ ",\"created_at\":-9223372036854775808,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":9223372036854775808,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":-9223372036854775809,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1,\"kind\":65536,\"content\":\"\"}",
        head ++ ",\"created_at\":1,\"kind\":-1,\"content\":\"\"}",
        head ++ ",\"created_at\":01,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1.5,\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1e3,\"kind\":1E0,\"content\":\"\"}",
        head ++ ",\"created_at\":\"12\",\"kind\":1,\"content\":\"\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":[104,105]}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":null}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ud83d\\ude00\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ud83d\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ude00\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\ud83d\\u0041\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\x\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\\u12\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xed\xa0\x80\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xc0\xaf\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xf4\x90\x80\x80\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xc3\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\xc3\\u00a9\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"a\tb\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\x7f\"}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\"} x",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\"}\x00",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",}",
        head ++ ",\"created_at\":1,\"kind\":1}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"kind\":2}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":1,\"x\":2}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":[1,]}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":tru}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":1.}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":.5}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":1e}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":+1}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"x\":" ++ "[" ** 100 ++ "]" ** 100 ++ "}",
        head ++ ",\"created_at\":1,\"kind\":1,\"content\":\"\",\"\\u0069d\":1}",
        "{\"\\u0069d\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"" ++ "0" ** 63 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"" ++ "AB" ** 32 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"" ++ "0g" ** 32 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":\"\\u0030" ++ "0" ** 63 ++ "\",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[[]],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[[1]],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":[\"e\"],\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{\"id\":" ++ z32 ++ ",\"pubkey\":" ++ z32 ++ ",\"sig\":" ++ z64 ++ ",\"tags\":null,\"created_at\":1,\"kind\":1,\"content\":\"\"}",
        "{}",
        "[]",
        "",
        " ",
        "{",
        "\"x\"",
    };
    for (cases) |c| try reference.expectSameAsReference(c);
}
