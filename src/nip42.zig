//! NIP-42 authentication of clients to relays.
//!
//! A relay may challenge a client with `["AUTH", <challenge>]` (see
//! `message.parseRelayMessage`). The client proves control of a key by signing
//! an ephemeral `kind:22242` event that names the relay and echoes the
//! challenge, then sends it back as `["AUTH", <event>]` (see
//! `message.encodeAuth`). Relays that require auth gate reads and/or writes
//! behind it — e.g. to protect direct messages or to deliver ephemeral events
//! like NIP-46 requests — so a remote signer authenticates to serve over them.
//!
//! This module builds the client's authentication event. The relay side
//! (issuing challenges, verifying events) is not implemented; verification, if
//! ever needed, is `event.verify` plus checking the `relay`/`challenge` tags and
//! a recent `created_at`.

const std = @import("std");
const event = @import("event.zig");
const keys = @import("keys.zig");

/// The NIP-42 authentication event kind (ephemeral, 20000–29999).
pub const kind: u16 = 22242;

/// Builds and signs the NIP-42 `kind:22242` authentication event answering a
/// relay's challenge: it carries a `["relay", <relay_url>]` tag and a
/// `["challenge", <challenge>]` tag, empty content, signed by `keypair`.
///
/// The returned event borrows `relay_url` and `challenge` (they must outlive
/// it) and owns its tag slices, allocated from `allocator`. Encode it with
/// `message.encodeAuth`; the simplest cleanup is to build it in an arena and
/// free the arena after sending.
pub fn authEvent(
    allocator: std.mem.Allocator,
    signer: keys.Signer,
    keypair: keys.KeyPair,
    relay_url: []const u8,
    challenge: []const u8,
    created_at: i64,
    aux_rand: ?[32]u8,
) (std.mem.Allocator.Error || keys.Error)!event.Event {
    const relay_tag = try allocator.alloc([]const u8, 2);
    relay_tag[0] = "relay";
    relay_tag[1] = relay_url;

    const challenge_tag = try allocator.alloc([]const u8, 2);
    challenge_tag[0] = "challenge";
    challenge_tag[1] = challenge;

    const tags = try allocator.alloc(event.Tag, 2);
    tags[0] = relay_tag;
    tags[1] = challenge_tag;

    return event.create(allocator, signer, keypair, created_at, kind, tags, "", aux_rand);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "authEvent signs a well-formed kind:22242 event" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var signer = keys.Signer.init();
    defer signer.deinit();
    // BIP-340 test-vector secret → a valid x-only pubkey.
    const secret = try @import("hex.zig").decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    const ev = try authEvent(arena, signer, kp, "wss://relay.example.com", "challenge-123", 1_700_000_000, null);

    try testing.expectEqual(@as(u16, 22242), ev.kind);
    try testing.expectEqualStrings("", ev.content);
    try testing.expectEqualSlices(u8, &kp.public_key, &ev.pubkey);

    // Tags: ["relay", <url>] then ["challenge", <challenge>].
    try testing.expectEqual(@as(usize, 2), ev.tags.len);
    try testing.expectEqualStrings("relay", ev.tags[0][0]);
    try testing.expectEqualStrings("wss://relay.example.com", ev.tags[0][1]);
    try testing.expectEqualStrings("challenge", ev.tags[1][0]);
    try testing.expectEqualStrings("challenge-123", ev.tags[1][1]);

    // The signature verifies against the recomputed id.
    try testing.expect(try event.verify(arena, signer, ev));
}
