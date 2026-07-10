//! zig-nostr/nostr — a Nostr protocol library for Zig.

const std = @import("std");

pub const version = "0.0.0";

pub const bech32 = @import("bech32.zig");
pub const nip19 = @import("nip19.zig");
pub const nip49 = @import("nip49.zig");
pub const hex = @import("hex.zig");
pub const event = @import("event.zig");
pub const keys = @import("keys.zig");

test "module compiles and version is set" {
    try std.testing.expect(version.len > 0);
}

test {
    std.testing.refAllDecls(@This());
}
