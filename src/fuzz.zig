//! Fuzz targets for the parsers a stranger controls.
//!
//! Everything here takes bytes that arrive from somewhere else: a relay's
//! frames, an event's JSON, a NIP-44 payload, a bech32 string lifted out of
//! somebody's note. None of it is input this library gets to assume anything
//! about, which is exactly the input a hand-written test is worst at inventing.
//!
//! These are ordinary tests. `zig build test` runs each one against a handful of
//! generated inputs and against its corpus, so CI gets them with no new job and
//! no new tool. `zig build test --fuzz` turns the same functions into a real
//! fuzzing loop that runs until stopped.
//!
//! Two rules for anything added here:
//!
//! 1. **Never assert on the RESULT.** These functions are supposed to reject
//!    nonsense, so "it returned an error" is the healthy case and asserting
//!    otherwise would just encode whatever the parser does today. What is being
//!    tested is that no input reaches a bad index, a bad cast, or a leak. The
//!    allocator is `std.testing.allocator`, so a leak fails the test, and a
//!    safety build turns an out-of-range index into a failure rather than into
//!    silence.
//! 2. **`@disableInstrumentation()` at the top of the target function**, so the
//!    fuzzer measures coverage of the code under test rather than of the harness
//!    generating the input.
//!
//! What this already paid for, before a single target below was written: the
//! survey that chose them found `bip39.mnemonicToSeed` writing a caller's
//! passphrase past a 264-byte stack buffer whenever it exceeded 256, in the
//! build that ships, silently. See the test beside it in bip39.zig.

const std = @import("std");
const testing = std.testing;

const bech32 = @import("bech32.zig");
const event = @import("event.zig");
const filter = @import("filter.zig");
const hex = @import("hex.zig");
const keys = @import("keys.zig");
const message = @import("message.zig");
const nip44 = @import("nip44.zig");
const websocket = @import("websocket.zig");

// -- The bytes under the bytes ------------------------------------------------

test "fuzz: a websocket frame" {
    try testing.fuzz({}, fuzzFrame, .{ .corpus = &.{
        // A tiny unmasked text frame, "hi".
        &.{ 0x81, 0x02, 'h', 'i' },
        // 16-bit length prefix claiming more than it carries.
        &.{ 0x81, 0x7e, 0xff, 0xff, 'x' },
        // 64-bit length prefix, absurd.
        &.{ 0x81, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        // Masked, which a server should never send but the decoder accepts.
        &.{ 0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h', 'i' },
    } });
}

/// The length arithmetic every other parser stands on.
///
/// A frame header carries its own payload length, in one of three widths, and
/// the decoder walks an offset forward past whichever prefixes are present
/// before slicing the payload out. Every one of those numbers is chosen by
/// whoever is on the other end of the socket, and the slice that follows is
/// what the message parser is then handed.
fn fuzzFrame(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    // Mutable: the decoder unmasks in place.
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    _ = websocket.decodeFrame(buf[0..n]) catch return;
}

// -- What a relay says --------------------------------------------------------

test "fuzz: a relay message" {
    try testing.fuzz({}, fuzzRelayMessage, .{ .corpus = &.{
        \\["EVENT","sub",{"id":"00","pubkey":"00","created_at":0,"kind":1,"tags":[],"content":"","sig":"00"}]
        ,
        \\["OK","0000000000000000000000000000000000000000000000000000000000000000",true,""]
        ,
        \\["EOSE","sub"]
        ,
        \\["CLOSED","sub","auth-required: pay up"]
        ,
        \\["NOTICE","hello"]
        ,
        \\["AUTH","challenge"]
        ,
    } });
}

/// The front door. Every byte a relay sends arrives here first, and this is the
/// one target that covers the whole chain behind it: the JSON scanner, event
/// deserialisation, the hex decoder for ids/pubkeys/signatures, and the
/// narrowing of `kind` and `created_at` out of arbitrary JSON numbers.
fn fuzzRelayMessage(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);
    var parsed = message.parseRelayMessage(testing.allocator, buf[0..n]) catch return;
    parsed.deinit();
}

// -- What a relay says, shaped like something it might mean -------------------

test "fuzz: a relay message with a plausible envelope" {
    try testing.fuzz({}, fuzzEnvelope, .{});
}

/// The same parser, reached past the first `if`.
///
/// Raw bytes almost never look like `["EVENT",...]`, so a fuzzer spends its
/// whole budget failing at the first character and the interesting code behind
/// it is never entered. This builds a real envelope around fuzzed contents so
/// the generator's effort lands on the fields rather than on the brackets.
fn fuzzEnvelope(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    const verb = switch (smith.value(enum(u3) { event, ok, eose, closed, notice, auth })) {
        .event => "EVENT",
        .ok => "OK",
        .eose => "EOSE",
        .closed => "CLOSED",
        .notice => "NOTICE",
        .auth => "AUTH",
    };
    var body: [1024]u8 = undefined;
    const n = smith.slice(&body);

    var text: [1200]u8 = undefined;
    const built = std.fmt.bufPrint(&text, "[\"{s}\",{s}]", .{ verb, body[0..n] }) catch return;
    var parsed = message.parseRelayMessage(testing.allocator, built) catch return;
    parsed.deinit();
}

// -- An event on its own ------------------------------------------------------

test "fuzz: an event, and then everything that reads one" {
    try testing.fuzz({}, fuzzEvent, .{ .corpus = &.{
        \\{"id":"0000000000000000000000000000000000000000000000000000000000000000","pubkey":"0000000000000000000000000000000000000000000000000000000000000000","created_at":1700000000,"kind":1,"tags":[["e","00"],["p"]],"content":"hi","sig":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
        ,
    } });
}

/// Deserialise an event, then put it through the two things that walk it
/// afterwards: id computation, which re-serialises every tag and escapes the
/// content, and filter matching, whose tag loop indexes `tag[0]`, `tag[0][0]`
/// and `tag[1]` on arrays whose lengths the sender chose.
///
/// Matching against a filter is where a zero-length tag or a zero-length tag
/// NAME would be felt, and neither is illegal on the wire.
fn fuzzEvent(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);

    var parsed = event.fromJson(testing.allocator, buf[0..n]) catch return;
    defer parsed.deinit();
    const ev = parsed.value;

    // Re-serialising it walks every tag and escapes the content, on lengths the
    // sender chose. Its own allocation is freed, so a leak here is a finding.
    if (event.computeId(testing.allocator, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content)) |_| {} else |_| {}

    const kinds = [_]u16{ 0, 1, 3, 7 };
    const f = filter.Filter{ .kinds = &kinds, .limit = 10 };
    _ = f.matches(ev);
}

// -- A payload somebody encrypted to you --------------------------------------

test "fuzz: a NIP-44 payload" {
    try testing.fuzz({}, fuzzNip44, .{ .corpus = &.{
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "#not-a-version",
        "",
    } });
}

/// Everything before the MAC is checked.
///
/// A payload arrives base64-encoded from a stranger, and the version byte, the
/// nonce, the ciphertext span and the padding length are all read out of it
/// before anything has been authenticated. Whatever this does with a malformed
/// one, it has to do without reading outside the buffer.
fn fuzzNip44(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);

    // A fixed key: the point is the payload, and deriving one per iteration
    // would spend the whole budget in secp256k1 instead of in the parser.
    const key: nip44.ConversationKey = [_]u8{0x42} ** 32;
    const out = nip44.decryptWithConversationKey(testing.allocator, key, buf[0..n]) catch return;
    testing.allocator.free(out);
}

// -- A string out of somebody's note ------------------------------------------

test "fuzz: a bech32 string" {
    try testing.fuzz({}, fuzzBech32, .{ .corpus = &.{
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg",
        "note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "1",
        "a1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    } });
}

/// Reached from a note, not only from a paste. Plaza renders `nostr:` mentions
/// that strangers wrote, so a decoder that trusts its input length is reachable
/// by anyone who can get a note in front of you.
fn fuzzBech32(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    var decoded = bech32.decode(testing.allocator, buf[0..n]) catch return;
    decoded.deinit(testing.allocator);
}

// -- The smallest one, and the one everything else leans on -------------------

test "fuzz: fixed-width hex" {
    try testing.fuzz({}, fuzzHex, .{});
}

/// `decodeFixed` is what stands between a relay's id/pubkey/signature strings
/// and a fixed-size array, and its loop indexes `hex[i*2 + 1]`. The only thing
/// keeping that in range is one length check, so the length check is the test.
fn fuzzHex(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [256]u8 = undefined;
    const n = smith.slice(&buf);
    _ = hex.decodeFixed(32, buf[0..n]) catch {};
    _ = hex.decodeFixed(64, buf[0..n]) catch {};
}

// -- A signature check on bytes nobody vetted ---------------------------------

test "fuzz: verifying a signature over arbitrary bytes" {
    try testing.fuzz({}, fuzzVerify, .{});
}

/// Every event Plaza stores has its signature checked, and all three arguments
/// come off the wire: a 64-byte signature, a 32-byte pubkey and a message of any
/// length, including zero, where a Zig empty slice carries a sentinel address
/// rather than real memory. `verify` returns false rather than erroring for
/// anything malformed, so the only thing to assert is that it returns at all.
fn fuzzVerify(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var signer = keys.Signer.init();
    defer signer.deinit();

    var sig: [64]u8 = undefined;
    smith.bytes(&sig);
    var pk: [32]u8 = undefined;
    smith.bytes(&pk);
    var msg: [512]u8 = undefined;
    const n = smith.slice(&msg);

    _ = signer.verify(sig, msg[0..n], pk);
}
