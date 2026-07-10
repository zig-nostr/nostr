//! zig-nostr/nostr — a Nostr protocol library for Zig.
//!
//! This is Milestone A1 (repo & workflow scaffolding): the module compiles
//! and its test suite runs in CI, but no protocol functionality exists yet.
//! Keys, encoding, events, and signatures land in Milestone A2.

const std = @import("std");

pub const version = "0.0.0";

test "module compiles and version is set" {
    try std.testing.expect(version.len > 0);
}
