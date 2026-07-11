//! zig-nostr/nostr — a Nostr protocol library for Zig.

const std = @import("std");

pub const version = "0.3.0";

pub const bech32 = @import("bech32.zig");
pub const nip19 = @import("nip19.zig");
pub const nip49 = @import("nip49.zig");
pub const nip44 = @import("nip44.zig");
pub const nip46 = @import("nip46.zig");
pub const hex = @import("hex.zig");
pub const event = @import("event.zig");
pub const keys = @import("keys.zig");
pub const bip39 = @import("bip39.zig");
pub const nip06 = @import("nip06.zig");
pub const filter = @import("filter.zig");
pub const message = @import("message.zig");
pub const websocket = @import("websocket.zig");
pub const relay = @import("relay.zig");
pub const nip65 = @import("nip65.zig");
pub const store = @import("store.zig");

test "module compiles and version is set" {
    try std.testing.expect(version.len > 0);
}

test {
    std.testing.refAllDecls(@This());
}
