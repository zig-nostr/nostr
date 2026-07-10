//! zig-nostr/nostr — a Nostr protocol library for Zig.

const std = @import("std");

pub const version = "0.0.0";

pub const bech32 = @import("bech32.zig");
pub const nip19 = @import("nip19.zig");

test "module compiles and version is set" {
    try std.testing.expect(version.len > 0);
}

test {
    std.testing.refAllDecls(@This());
}
