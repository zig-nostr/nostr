//! A single-pass reader for the JSON that carries events: an event object on
//! its own (`event.fromJson`) or inside a relay message (`message.zig`).
//!
//! Internal: `root.zig` does not export it. Every function here answers
//! `Unsupported` for anything it does not take, and the caller then parses
//! the same text with `std.json`, so what is accepted and every error
//! returned stay exactly what the `std.json` path gives.

const std = @import("std");
const event_mod = @import("event.zig");

const Event = event_mod.Event;
const Tag = event_mod.Tag;

pub const Lane = @Vector(16, u8);

/// Index of the first byte at or after `from` that a JSON string cannot carry
/// raw: a quote, a backslash or a control byte. `s.len` when there is none.
pub fn nextSpecial(s: []const u8, from: usize) usize {
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

/// `Unsupported` means only "not on the fast path": the caller parses the
/// same text with `std.json`, which decides whether it is an event.
pub const ScanError = error{Unsupported} || std.mem.Allocator.Error;

/// What to do with a key NIP-01 does not name.
pub const UnknownKeys = enum {
    /// Step over its value. Right for `std.json` into a typed struct, which
    /// skips unknown fields without looking for repeats inside them.
    skip,
    /// Answer `Unsupported`. Right where the reference is `std.json.Value`,
    /// which refuses a key repeated in any object, however deeply nested:
    /// rather than track every key of every skipped object, leave the rare
    /// event with an extra key to the reference.
    refuse,
};

/// Reads one NIP-01 event object out of `buf`, which it owns and may write,
/// with nothing but whitespace around it.
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
/// string spelled as an array of bytes. The differential tests in `event.zig`
/// and `message.zig` and the targets in `fuzz.zig` hold it to that.
pub fn event(allocator: std.mem.Allocator, buf: []u8) ScanError!Event {
    var s: Scanner = .{ .buf = buf };
    s.skipWs();
    const ev = try eventObject(allocator, &s, .skip);
    s.skipWs();
    if (s.i != buf.len) return error.Unsupported;
    return ev;
}

/// Reads the event object whose `{` is at the cursor and leaves the cursor
/// just past its `}`.
pub fn eventObject(allocator: std.mem.Allocator, s: *Scanner, comptime unknown: UnknownKeys) ScanError!Event {
    var ev: Event = undefined;
    var seen: u7 = 0;

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
            0 => switch (unknown) {
                .skip => try s.skipValue(0),
                .refuse => return error.Unsupported,
            },
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

pub const Scanner = struct {
    buf: []u8,
    i: usize = 0,

    /// The byte at the cursor, or 0 at the end, which no branch takes.
    pub inline fn peek(s: *const Scanner) u8 {
        return if (s.i < s.buf.len) s.buf[s.i] else 0;
    }

    pub inline fn expect(s: *Scanner, c: u8) error{Unsupported}!void {
        if (s.peek() != c) return error.Unsupported;
        s.i += 1;
    }

    /// JSON whitespace is these four bytes and nothing else.
    pub inline fn skipWs(s: *Scanner) void {
        while (s.i < s.buf.len) : (s.i += 1) {
            switch (s.buf[s.i]) {
                ' ', '\t', '\n', '\r' => {},
                else => return,
            }
        }
    }

    /// Reads the string whose opening quote is at the cursor and returns it
    /// decoded, in place.
    pub fn string(s: *Scanner) error{Unsupported}![]u8 {
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
    pub fn hexString(s: *Scanner, comptime n: usize) error{Unsupported}![n]u8 {
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
    pub fn int(s: *Scanner, comptime T: type) error{Unsupported}!T {
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
        if (@typeInfo(T).int.signedness == .signed and neg) {
            if (mag > @as(u64, std.math.maxInt(T)) + 1) return error.Unsupported;
            return @intCast(-@as(i128, mag));
        }
        if (mag > std.math.maxInt(T)) return error.Unsupported;
        return @intCast(mag);
    }

    /// `[[string, ...], ...]`, into one array of tags over one array of
    /// strings, both in `allocator`. Most events have few enough that the
    /// work lists stay on the stack.
    pub fn tags(s: *Scanner, allocator: std.mem.Allocator) ScanError![]const Tag {
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
    pub fn skipValue(s: *Scanner, depth: usize) error{Unsupported}!void {
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

    pub fn literal(s: *Scanner, comptime word: []const u8) error{Unsupported}!void {
        if (!std.mem.startsWith(u8, s.buf[s.i..], word)) return error.Unsupported;
        s.i += word.len;
    }

    /// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`
    pub fn number(s: *Scanner) error{Unsupported}!void {
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

    pub fn digits(s: *Scanner) void {
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
