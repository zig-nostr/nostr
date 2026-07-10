//! Minimal lowercase hex encode/decode helpers shared across NIP
//! implementations that need hex ids/keys/signatures (NIP-01, NIP-06,
//! NIP-49, ...).

const std = @import("std");

pub const Error = error{InvalidHex} || std.mem.Allocator.Error;

fn digitValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Appends the lowercase hex encoding of `bytes` to `list`.
pub fn appendHex(list: *std.ArrayList(u8), allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error!void {
    const digits = "0123456789abcdef";
    for (bytes) |b| {
        try list.append(allocator, digits[b >> 4]);
        try list.append(allocator, digits[b & 0xf]);
    }
}

/// Returns an owned lowercase hex string for `bytes`.
pub fn encode(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try appendHex(&list, allocator, bytes);
    return list.toOwnedSlice(allocator);
}

/// Decodes a hex string of exactly `N * 2` characters into `[N]u8`.
pub fn decodeFixed(comptime N: usize, hex: []const u8) Error![N]u8 {
    if (hex.len != N * 2) return Error.InvalidHex;
    var out: [N]u8 = undefined;
    for (0..N) |i| {
        const hi = digitValue(hex[i * 2]) orelse return Error.InvalidHex;
        const lo = digitValue(hex[i * 2 + 1]) orelse return Error.InvalidHex;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

/// Decodes a hex string of even length into an owned byte slice.
pub fn decode(allocator: std.mem.Allocator, hex: []const u8) Error![]u8 {
    if (hex.len % 2 != 0) return Error.InvalidHex;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    for (0..out.len) |i| {
        const hi = digitValue(hex[i * 2]) orelse return Error.InvalidHex;
        const lo = digitValue(hex[i * 2 + 1]) orelse return Error.InvalidHex;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

test "encode/decodeFixed round trip" {
    const bytes = [_]u8{ 0x00, 0x01, 0xff, 0xab, 0xcd };
    const allocator = std.testing.allocator;
    const hex = try encode(allocator, &bytes);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("0001ffabcd", hex);

    const back = try decodeFixed(5, hex);
    try std.testing.expectEqualSlices(u8, &bytes, &back);
}

test "decodeFixed rejects wrong length" {
    try std.testing.expectError(Error.InvalidHex, decodeFixed(32, "abcd"));
}

test "decode rejects invalid characters" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(Error.InvalidHex, decode(allocator, "zz"));
}
