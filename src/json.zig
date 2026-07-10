//! Minimal RFC 8259 JSON string escaping, shared by the relay-protocol
//! encoders (subscription filters, client messages).
//!
//! This is deliberately separate from the escaper in `event.zig`: that one
//! implements NIP-01's *stricter* id-serialization rule (only a fixed set of
//! escapes, everything else verbatim) so the event id hashes identically
//! across implementations. Here we are building ordinary wire JSON, so we
//! must produce valid JSON for any input — including emitting control
//! characters below 0x20 as `\u00XX`.

const std = @import("std");

/// Appends `s` as a quoted, RFC 8259-escaped JSON string to `list`.
pub fn appendString(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    s: []const u8,
) std.mem.Allocator.Error!void {
    try list.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            0x08 => try list.appendSlice(allocator, "\\b"),
            0x0C => try list.appendSlice(allocator, "\\f"),
            else => |b| {
                if (b < 0x20) {
                    var buf: [6]u8 = undefined;
                    const esc = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{b}) catch unreachable;
                    try list.appendSlice(allocator, esc);
                } else {
                    try list.append(allocator, b);
                }
            },
        }
    }
    try list.append(allocator, '"');
}

fn expectEncoded(expected: []const u8, input: []const u8) !void {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try appendString(&list, allocator, input);
    try std.testing.expectEqualStrings(expected, list.items);
}

test "escapes the mandatory characters" {
    try expectEncoded("\"plain\"", "plain");
    try expectEncoded("\"a\\\"b\"", "a\"b");
    try expectEncoded("\"a\\\\b\"", "a\\b");
    try expectEncoded("\"line1\\nline2\"", "line1\nline2");
    try expectEncoded("\"\\r\\t\\b\\f\"", "\r\t\x08\x0c");
}

test "escapes other control characters as \\u00XX" {
    try expectEncoded("\"\\u0000\\u001f\"", "\x00\x1f");
    // 0x7f (DEL) and normal bytes are emitted verbatim (valid JSON).
    try expectEncoded("\"\x7f!~\"", "\x7f!~");
}

test "passes UTF-8 through unchanged" {
    try expectEncoded("\"héllo — 🎉\"", "héllo — 🎉");
}
