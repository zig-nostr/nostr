//! bech32 codec (BIP-173, "bech32", not the bech32m variant from BIP-350).
//!
//! NIP-19 explicitly specifies bech32-(not-m) encoding, so this module
//! implements exactly that checksum constant. Values throughout are 5-bit
//! groups stored as `u8` in the 0..31 range.

const std = @import("std");

pub const Error = error{
    InvalidChar,
    InvalidChecksum,
    InvalidLength,
    MixedCase,
    NoSeparator,
} || std.mem.Allocator.Error;

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const charset_rev = blk: {
    var table = [_]i8{-1} ** 128;
    for (charset, 0..) |c, i| table[c] = @intCast(i);
    break :blk table;
};

fn charsetIndex(c: u8) ?u5 {
    if (c >= 128) return null;
    const v = charset_rev[c];
    if (v < 0) return null;
    return @intCast(v);
}

const generator = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

/// bech32 (not bech32m) checksum constant.
const checksum_const: u32 = 1;

fn polymodStep(chk: u32, v: u5) u32 {
    var c = chk;
    const b = c >> 25;
    c = (c & 0x1ffffff) << 5 ^ @as(u32, v);
    inline for (0..5) |i| {
        if ((b >> i) & 1 != 0) c ^= generator[i];
    }
    return c;
}

fn polymodHrp(hrp: []const u8) u32 {
    var chk: u32 = 1;
    for (hrp) |c| chk = polymodStep(chk, @intCast(c >> 5));
    chk = polymodStep(chk, 0);
    for (hrp) |c| chk = polymodStep(chk, @intCast(c & 31));
    return chk;
}

/// Regroups bits between `frombits`-wide and `tobits`-wide values. Used to
/// convert between raw bytes (8-bit) and bech32 data values (5-bit).
pub fn convertBits(
    allocator: std.mem.Allocator,
    data: []const u8,
    frombits: u5,
    tobits: u5,
    pad: bool,
) Error![]u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const maxv: u32 = (@as(u32, 1) << tobits) - 1;

    for (data) |value| {
        if ((@as(u32, value) >> frombits) != 0) return Error.InvalidChar;
        acc = (acc << frombits) | value;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            try out.append(allocator, @intCast((acc >> bits) & maxv));
        }
    }

    if (pad) {
        if (bits > 0) {
            try out.append(allocator, @intCast((acc << (tobits - bits)) & maxv));
        }
    } else if (bits >= frombits or ((acc << (tobits - bits)) & maxv) != 0) {
        return Error.InvalidLength;
    }

    return out.toOwnedSlice(allocator);
}

/// Encodes `hrp` + `data` (5-bit values) as a bech32 string, e.g. `npub1...`.
/// Caller owns the returned slice.
pub fn encode(allocator: std.mem.Allocator, hrp: []const u8, data: []const u8) Error![]u8 {
    var chk = polymodHrp(hrp);
    for (data) |v| chk = polymodStep(chk, @intCast(v));
    for (0..6) |_| chk = polymodStep(chk, 0);
    chk ^= checksum_const;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, hrp);
    try out.append(allocator, '1');
    for (data) |v| try out.append(allocator, charset[v]);
    for (0..6) |i| {
        const shift: u5 = @intCast(5 * (5 - i));
        try out.append(allocator, charset[(chk >> shift) & 31]);
    }
    return out.toOwnedSlice(allocator);
}

pub const Decoded = struct {
    hrp: []u8,
    data: []u8,

    pub fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        allocator.free(self.hrp);
        allocator.free(self.data);
    }
};

/// Decodes a bech32 string into its human-readable part and 5-bit data
/// values (checksum stripped, but verified). Caller owns the returned slices
/// (see `Decoded.deinit`).
pub fn decode(allocator: std.mem.Allocator, s: []const u8) Error!Decoded {
    if (s.len < 8) return Error.InvalidLength;

    var has_lower = false;
    var has_upper = false;
    for (s) |c| {
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;
    }
    if (has_lower and has_upper) return Error.MixedCase;

    const lower = try allocator.alloc(u8, s.len);
    defer allocator.free(lower);
    for (s, 0..) |c, i| lower[i] = std.ascii.toLower(c);

    const sep_pos = std.mem.lastIndexOfScalar(u8, lower, '1') orelse return Error.NoSeparator;
    if (sep_pos == 0) return Error.InvalidLength;
    const value_len = lower.len - sep_pos - 1;
    if (value_len < 6) return Error.InvalidLength;

    const hrp = try allocator.dupe(u8, lower[0..sep_pos]);
    errdefer allocator.free(hrp);

    const values = try allocator.alloc(u5, value_len);
    defer allocator.free(values);
    for (lower[sep_pos + 1 ..], 0..) |c, i| {
        values[i] = charsetIndex(c) orelse return Error.InvalidChar;
    }

    var chk = polymodHrp(hrp);
    for (values) |v| chk = polymodStep(chk, v);
    if (chk != checksum_const) return Error.InvalidChecksum;

    const data = try allocator.alloc(u8, value_len - 6);
    errdefer allocator.free(data);
    for (values[0 .. value_len - 6], 0..) |v, i| data[i] = v;

    return Decoded{ .hrp = hrp, .data = data };
}

test "encode/decode round trip" {
    const allocator = std.testing.allocator;
    const payload = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 };
    const data5 = try convertBits(allocator, &payload, 8, 5, true);
    defer allocator.free(data5);

    const encoded = try encode(allocator, "test", data5);
    defer allocator.free(encoded);

    var decoded = try decode(allocator, encoded);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("test", decoded.hrp);

    const back = try convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(back);
    try std.testing.expectEqualSlices(u8, &payload, back);
}

test "decode rejects mixed case" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.MixedCase, decode(allocator, "Npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9"));
}

test "decode rejects bad checksum" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidChecksum, decode(allocator, "npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdvx"));
}
