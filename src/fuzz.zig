//! Fuzz targets for the parsers a stranger controls.
//!
//! Everything here takes bytes that arrive from somewhere else: a relay's
//! frames, an event's JSON, a NIP-44 payload, a bech32 string lifted out of
//! somebody's note, a connection URI somebody pasted. None of it is input this
//! library gets to assume anything about, which is exactly the input a
//! hand-written test is worst at inventing.
//!
//! These are ordinary tests. `zig build test` runs each target once per entry
//! of its corpus, plus once on empty input, so CI gets them with no new job and
//! no new tool. `zig build test --fuzz` turns the same functions into a real
//! fuzzing loop that runs until stopped, starting from that corpus. With Zig
//! 0.16.0 pass `-Doptimize=ReleaseSafe`: the standard test runner does not
//! compile in fuzz mode in Debug (it hands an error return trace to a function
//! that wants a different type), and ReleaseSafe keeps the integer and bounds
//! checks the fuzzer is looking for. A failing run prints its stack trace; to
//! keep the case, build the input that triggers it with `seed` and add it to the
//! target's corpus, which makes it part of every plain `zig build test`.
//!
//! Two kinds of assertion, and a target should have the first at least:
//!
//! 1. **Nothing crashes, nothing leaks.** These functions are supposed to reject
//!    nonsense, so "it returned an error" is the healthy case and is never a
//!    failure. What is being tested is that no input reaches a bad index, a bad
//!    cast, a stack overflow or a leak. The allocator is `std.testing.allocator`,
//!    so a leak fails the test, and a safety build turns an out-of-range index
//!    into a failure rather than into silence.
//! 2. **The invariant that matters, when there is one.** A parse that succeeds
//!    has to mean something: re-serialising what was parsed and parsing that
//!    again must give the same thing back, and a frame that decoded must lie
//!    inside the buffer it was decoded from. These are asserted only on the
//!    success path, so they never encode what a parser happens to reject today.
//!
//! Rules for anything added here:
//!
//! * **`@disableInstrumentation()` at the top of the target function**, so the
//!   fuzzer measures coverage of the code under test rather than of the harness
//!   generating the input.
//! * **A corpus is written in the smith's encoding, not as raw bytes.** A
//!   `smith.slice` reads a four byte length before the bytes, and a
//!   `smith.value` reads eight, so a raw string used as a corpus entry has its
//!   first characters eaten as a length and the target sees something else.
//!   `seed` builds the real encoding. The corpus is also the only input a plain
//!   `zig build test` ever sees, so a target without one is a smoke test of the
//!   empty string.
//! * **Reach past the first check.** Random bytes almost never carry a valid
//!   checksum or a well formed envelope, and the code behind those checks is
//!   never entered. Build the outer layer around fuzzed contents (see
//!   `fuzzEnvelope` and `fuzzNip19Entity`) so the effort lands on the fields.
//!
//! What fuzzing has paid for: `bip39.mnemonicToSeed` wrote a caller's passphrase
//! past a 264-byte stack buffer whenever it exceeded 256, in the build that
//! ships, silently (see the test beside it in bip39.zig). `nip49.decrypt` cast
//! the scrypt cost out of a hostile `ncryptsec` straight into a six bit integer,
//! so a payload with a cost above 63 was an illegal cast and a crash rather than
//! an error (see the test beside it in nip49.zig). The NIP-19 TLV decoders
//! stepped past an entry with a byte-wide sum, which overflowed on an entry of
//! 254 or 255 bytes, and `decodeNaddr` leaked its identifier when an naddr
//! carried two (see the tests beside them in nip19.zig).

const std = @import("std");
const testing = std.testing;

const bech32 = @import("bech32.zig");
const bip39 = @import("bip39.zig");
const event = @import("event.zig");
const filter = @import("filter.zig");
const hex = @import("hex.zig");
const json = @import("json.zig");
const keys = @import("keys.zig");
const message = @import("message.zig");
const nip19 = @import("nip19.zig");
const nip44 = @import("nip44.zig");
const nip46 = @import("nip46.zig");
const nip49 = @import("nip49.zig");
const nip65 = @import("nip65.zig");
const relay = @import("relay.zig");
const signer_ipc = @import("signer_ipc.zig");
const websocket = @import("websocket.zig");

// -- Corpus encoding ----------------------------------------------------------

/// One value a target reads from the smith, in the order it reads them.
const Part = union(enum) {
    /// `smith.value` and friends: eight bytes, little endian, whatever the type.
    int: u64,
    /// `smith.bytes`: the bytes as they are.
    bytes: []const u8,
    /// `smith.slice`: a four byte little endian length, then the bytes.
    slice: []const u8,
};

/// The input a smith would have consumed to produce `parts`.
fn seed(comptime parts: []const Part) []const u8 {
    const out = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        var len: usize = 0;
        for (parts) |p| len += switch (p) {
            .int => 8,
            .bytes => |b| b.len,
            .slice => |s| 4 + s.len,
        };
        var buf: [len]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        for (parts) |p| switch (p) {
            .int => |i| w.writeInt(u64, i, .little) catch unreachable,
            .bytes => |b| w.writeAll(b) catch unreachable,
            .slice => |s| {
                w.writeInt(u32, @intCast(s.len), .little) catch unreachable;
                w.writeAll(s) catch unreachable;
            },
        };
        break :blk buf;
    };
    return &out;
}

/// The common case: a target that reads one slice.
fn one(comptime bytes: []const u8) []const u8 {
    return seed(&.{.{ .slice = bytes }});
}

const zeros32 = "0" ** 64;
const zeros64 = "0" ** 128;

/// A valid event object on the wire, with an id and a signature that do not
/// match anything: parsing does not check them, `verify` does.
const sample_event =
    "{\"id\":\"" ++ zeros32 ++ "\",\"pubkey\":\"" ++ zeros32 ++ "\",\"created_at\":1700000000,\"kind\":1," ++
    "\"tags\":[[\"e\",\"" ++ zeros32 ++ "\",\"wss://r.example\"],[\"p\"],[]],\"content\":\"hi \\\"there\\\"\\n\"," ++
    "\"sig\":\"" ++ zeros64 ++ "\"}";

fn eventsEqual(a: event.Event, b: event.Event) bool {
    if (!std.mem.eql(u8, &a.id, &b.id)) return false;
    if (!std.mem.eql(u8, &a.pubkey, &b.pubkey)) return false;
    if (a.created_at != b.created_at or a.kind != b.kind) return false;
    if (!std.mem.eql(u8, a.content, b.content)) return false;
    if (!std.mem.eql(u8, &a.sig, &b.sig)) return false;
    if (a.tags.len != b.tags.len) return false;
    for (a.tags, b.tags) |ta, tb| {
        if (ta.len != tb.len) return false;
        for (ta, tb) |sa, sb| if (!std.mem.eql(u8, sa, sb)) return false;
    }
    return true;
}

fn stringsEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

// -- The bytes under the bytes ------------------------------------------------

test "fuzz: a websocket frame" {
    try testing.fuzz({}, fuzzFrame, .{
        .corpus = &.{
            // A tiny unmasked text frame, "hi".
            one(&.{ 0x81, 0x02, 'h', 'i' }),
            // 16-bit length prefix claiming more than it carries.
            one(&.{ 0x81, 0x7e, 0xff, 0xff, 'x' }),
            // 64-bit length prefix, absurd.
            one(&.{ 0x81, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }),
            // 64-bit length prefix with the reserved top bit set.
            one(&.{ 0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0 }),
            // Masked, which a server should never send but the decoder accepts.
            one(&.{ 0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h', 'i' }),
            // A header with nothing after it.
            one(&.{0x81}),
        },
    });
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
    const decoded = websocket.decodeFrame(buf[0..n]) catch return;
    if (decoded) |frame| {
        // The frame is the front of the buffer, and nothing past its end.
        try testing.expect(frame.frame_len <= n);
        try testing.expect(frame.payload.len <= frame.frame_len);
    }
}

test "fuzz: a client frame decodes to what was sent" {
    try testing.fuzz({}, fuzzClientFrame, .{ .corpus = &.{
        seed(&.{ .{ .int = 1 }, .{ .bytes = &.{ 1, 2, 3, 4 } }, .{ .slice = "hello" } }),
        seed(&.{ .{ .int = 4 }, .{ .bytes = &.{ 0, 0, 0, 0 } }, .{ .slice = &(.{'a'} ** 200) } }),
        seed(&.{ .{ .int = 3 }, .{ .bytes = &.{ 9, 9, 9, 9 } }, .{ .slice = "" } }),
    } });
}

/// The encoder and the decoder agree, across the 7-bit and 16-bit length forms.
///
/// The decoder is the one fed by strangers, but it is also the only thing that
/// can say the encoder wrote a frame a server would read back as sent.
fn fuzzClientFrame(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    const opcodes = [_]websocket.Opcode{ .text, .binary, .ping, .pong, .close };
    const opcode = opcodes[smith.valueRangeLessThan(u8, 0, opcodes.len)];
    var mask: [4]u8 = undefined;
    smith.bytes(&mask);
    var payload: [1024]u8 = undefined;
    const n = smith.slice(&payload);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try websocket.appendClientFrame(&list, testing.allocator, opcode, payload[0..n], mask);

    const frame = (try websocket.decodeFrame(list.items)) orelse return error.TestUnexpectedResult;
    try testing.expect(frame.fin);
    try testing.expectEqual(opcode, frame.opcode);
    try testing.expectEqual(list.items.len, frame.frame_len);
    try testing.expectEqualSlices(u8, payload[0..n], frame.payload);
}

test "fuzz: a handshake response" {
    // The RFC 6455 worked example: the accept value for key "dGhlIHNhbXBsZSBub25jZQ==".
    const accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
    try testing.fuzz({}, fuzzHandshake, .{ .corpus = &.{
        seed(&.{
            .{ .slice = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " ++ accept ++ "\r\n\r\n" },
            .{ .slice = accept },
        }),
        seed(&.{
            .{ .slice = "HTTP/1.1 200 OK\r\n\r\n" },
            .{ .slice = accept },
        }),
        seed(&.{
            .{ .slice = "HTTP/1.1 101 x\r\nsec-websocket-accept:  nope \r\n\r\n" },
            .{ .slice = accept },
        }),
    } });
}

/// The relay's reply to the upgrade request, read before anything else.
///
/// A header block is a few lines of text a stranger wrote. The invariant is the
/// one the handshake exists for: it is accepted only when the status said 101
/// and the accept value the relay sent is the one we derived from our own key.
fn fuzzHandshake(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var response: [512]u8 = undefined;
    const rn = smith.slice(&response);
    var expected: [64]u8 = undefined;
    const en = smith.slice(&expected);

    websocket.checkHandshakeResponse(response[0..rn], expected[0..en]) catch return;
    // Not `startsWith`: the status line is split on spaces, so leading ones are
    // tolerated and the 101 is not necessarily at the front.
    try testing.expect(std.mem.indexOf(u8, response[0..rn], "HTTP/1.") != null);
    try testing.expect(std.mem.indexOf(u8, response[0..rn], " 101") != null);
    try testing.expect(std.mem.indexOf(u8, response[0..rn], expected[0..en]) != null);
}

// -- What a relay says --------------------------------------------------------

test "fuzz: a relay message" {
    try testing.fuzz({}, fuzzRelayMessage, .{ .corpus = &.{
        one("[\"EVENT\",\"sub\"," ++ sample_event ++ "]"),
        one("[\"OK\",\"" ++ zeros32 ++ "\",true,\"\"]"),
        one("[\"OK\",\"" ++ zeros32 ++ "\",false,\"blocked: no\"]"),
        one("[\"EOSE\",\"sub\"]"),
        one("[\"CLOSED\",\"sub\",\"auth-required: pay up\"]"),
        one("[\"NOTICE\",\"hello\"]"),
        one("[\"AUTH\",\"challenge\"]"),
        one("[\"EVENT\",\"sub\",{\"kind\":70000}]"),
        one("[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["),
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
    defer parsed.deinit();
    switch (parsed.value) {
        .event => |e| try expectEventRoundTrips(e.event),
        else => {},
    }
}

test "fuzz: a relay message with a plausible envelope" {
    try testing.fuzz({}, fuzzEnvelope, .{ .corpus = &.{
        seed(&.{ .{ .int = 0 }, .{ .slice = "\"sub\"," ++ sample_event } }),
        seed(&.{ .{ .int = 1 }, .{ .slice = "\"" ++ zeros32 ++ "\",true,\"saved\"" } }),
        seed(&.{ .{ .int = 2 }, .{ .slice = "\"sub\"" } }),
        seed(&.{ .{ .int = 3 }, .{ .slice = "\"sub\",\"closed\"" } }),
        seed(&.{ .{ .int = 4 }, .{ .slice = "\"hello\"" } }),
        seed(&.{ .{ .int = 5 }, .{ .slice = "\"challenge\"" } }),
    } });
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
    defer parsed.deinit();
    switch (parsed.value) {
        .event => |e| try expectEventRoundTrips(e.event),
        else => {},
    }
}

// -- An event on its own ------------------------------------------------------

test "fuzz: an event, and then everything that reads one" {
    try testing.fuzz({}, fuzzEvent, .{
        .corpus = &.{
            one(sample_event),
            // Reordered, with a key the parser has to skip.
            one("{\"kind\":7,\"extra\":{\"a\":[1,2]},\"content\":\"\",\"tags\":[],\"created_at\":-5,\"pubkey\":\"" ++ zeros32 ++ "\",\"id\":\"" ++ zeros32 ++ "\",\"sig\":\"" ++ zeros64 ++ "\"}"),
            // Every control character and a multi-byte sequence in the content.
            one("{\"id\":\"" ++ zeros32 ++ "\",\"pubkey\":\"" ++ zeros32 ++ "\",\"created_at\":1,\"kind\":1,\"tags\":[[\"\\u0001\",\"\\u00e9\\ud83d\\ude00\"]],\"content\":\"\\u0000\\u001f\\b\\f\\/\",\"sig\":\"" ++ zeros64 ++ "\"}"),
            // A number past the range of the field it lands in.
            one("{\"id\":\"" ++ zeros32 ++ "\",\"pubkey\":\"" ++ zeros32 ++ "\",\"created_at\":99999999999999999999,\"kind\":1,\"tags\":[],\"content\":\"\",\"sig\":\"" ++ zeros64 ++ "\"}"),
        },
    });
}

/// Deserialise an event, then put it through the things that walk it afterwards:
/// serialising it back, id computation, which re-serialises every tag and
/// escapes the content, and filter matching, whose tag loop indexes `tag[0]`,
/// `tag[0][0]` and `tag[1]` on arrays whose lengths the sender chose.
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

    try expectEventRoundTrips(ev);

    // Re-serialising it walks every tag and escapes the content, on lengths the
    // sender chose. Its own allocation is freed, so a leak here is a finding.
    if (event.computeId(testing.allocator, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content)) |_| {} else |_| {}

    const kinds = [_]u16{ 0, 1, 3, 7 };
    const tag_values = [_][]const u8{ "", "a" };
    const tag_filters = [_]filter.TagFilter{ .{ .letter = 'e', .values = &tag_values }, .{ .letter = 'p', .values = &.{} } };
    const f = filter.Filter{ .kinds = &kinds, .tags = &tag_filters, .limit = 10 };
    _ = f.matches(ev);
}

/// The wire form of an event, parsed again, is the same event.
///
/// The id is a hash of the canonical form and the signature covers the id, so a
/// parse that loses or rewrites a byte of a tag or of the content produces an
/// event that no longer verifies, which is silent data corruption on a path
/// every stored event takes.
fn expectEventRoundTrips(ev: event.Event) !void {
    const text = try event.toJson(testing.allocator, ev);
    defer testing.allocator.free(text);
    var again = try event.fromJson(testing.allocator, text);
    defer again.deinit();
    try testing.expect(eventsEqual(ev, again.value));

    // The canonical form is what gets hashed, and it has to be a function of the
    // fields alone.
    const a = try event.computeId(testing.allocator, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content);
    const b = try event.computeId(testing.allocator, again.value.pubkey, again.value.created_at, again.value.kind, again.value.tags, again.value.content);
    try testing.expectEqualSlices(u8, &a, &b);
}

// -- A payload somebody encrypted to you --------------------------------------

test "fuzz: a NIP-44 payload" {
    try testing.fuzz({}, fuzzNip44, .{ .corpus = &.{
        one("AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        one("#not-a-version"),
        one("AQ=="),
        one(""),
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

test "fuzz: a NIP-44 message decrypts to what was sealed" {
    try testing.fuzz({}, fuzzNip44RoundTrip, .{ .corpus = &.{
        seed(&.{ .{ .bytes = &(.{7} ** 32) }, .{ .slice = "a" } }),
        seed(&.{ .{ .bytes = &(.{9} ** 32) }, .{ .slice = "hello, \u{e9}\u{1f600}" } }),
        seed(&.{ .{ .bytes = &(.{1} ** 32) }, .{ .slice = &(.{'x'} ** 1500) } }),
        seed(&.{ .{ .bytes = &(.{3} ** 32) }, .{ .slice = "" } }),
    } });
}

/// Seal then open, over every length the padding scheme rounds differently.
///
/// The padded length is computed from the plaintext length and read back by
/// `unpad` from a prefix inside the ciphertext, so an off-by-one in either
/// shows up as a message that comes back short, long, or not at all.
fn fuzzNip44RoundTrip(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var nonce: [32]u8 = undefined;
    smith.bytes(&nonce);
    var plain: [2048]u8 = undefined;
    const n = smith.slice(&plain);

    const key: nip44.ConversationKey = [_]u8{0x42} ** 32;
    const payload = nip44.encryptWithConversationKey(testing.allocator, key, plain[0..n], nonce) catch |err| switch (err) {
        error.MessageEmpty => {
            try testing.expectEqual(@as(usize, 0), n);
            return;
        },
        else => return err,
    };
    defer testing.allocator.free(payload);
    const back = try nip44.decryptWithConversationKey(testing.allocator, key, payload);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, plain[0..n], back);
}

// -- A string out of somebody's note ------------------------------------------

test "fuzz: a bech32 string" {
    try testing.fuzz({}, fuzzBech32, .{ .corpus = &.{
        one("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"),
        one("NPUB10ELFCS4FR0L0R8AF98JLMGDH9C8TCXJVZ9QKW038JS35MP4DMA8QZVJPTG"),
        one("note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc"),
        one("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        one("1"),
        one("a1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j"),
    } });
}

/// Reached from a note, not only from a paste. Plaza renders `nostr:` mentions
/// that strangers wrote, so a decoder that trusts its input length is reachable
/// by anyone who can get a note in front of you.
///
/// A string that decodes is the one string that encodes back to it, ignoring
/// case. Two strings for one payload would mean a mention that compares unequal
/// to itself.
fn fuzzBech32(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    var decoded = bech32.decode(testing.allocator, buf[0..n]) catch return;
    defer decoded.deinit(testing.allocator);

    const again = try bech32.encode(testing.allocator, decoded.hrp, decoded.data);
    defer testing.allocator.free(again);
    try testing.expect(std.ascii.eqlIgnoreCase(again, buf[0..n]));
}

test "fuzz: a NIP-19 string" {
    try testing.fuzz({}, fuzzNip19String, .{ .corpus = &.{
        one("npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"),
        one("note1fntxtkcy9pjwucqwa9mddn7v03wwwsu9j330jj350nvhpky2tuaspk6nqc"),
        one("nostr:npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"),
        one("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"),
        one("nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p"),
        one("nevent1qqs"),
    } });
}

/// Every NIP-19 decoder on the same string, as a mention renderer would try them.
///
/// For the three bare entities the rule is the same as for bech32 itself: what
/// decodes encodes back to the same string. Padding bits that are not zero would
/// break it, and they are exactly what a hand written five-to-eight regrouping
/// forgets to check.
fn fuzzNip19String(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    const s = nip19.fromNostrUri(buf[0..n]);
    const a = testing.allocator;

    if (nip19.decodeNpub(a, s)) |pk| {
        const again = try nip19.encodeNpub(a, pk);
        defer a.free(again);
        try testing.expect(std.ascii.eqlIgnoreCase(again, s));
    } else |_| {}
    if (nip19.decodeNsec(a, s)) |sk| {
        const again = try nip19.encodeNsec(a, sk);
        defer a.free(again);
        try testing.expect(std.ascii.eqlIgnoreCase(again, s));
    } else |_| {}
    if (nip19.decodeNote(a, s)) |id| {
        const again = try nip19.encodeNote(a, id);
        defer a.free(again);
        try testing.expect(std.ascii.eqlIgnoreCase(again, s));
    } else |_| {}
    try checkNprofile(a, s);
    try checkNevent(a, s);
    try checkNaddr(a, s);
    try checkNrelay(a, s);
}

test "fuzz: a NIP-19 entity built around fuzzed contents" {
    const pk = "\x00\x20" ++ "\x11" ** 32;
    const relay_a = "\x01\x0dwss://a.b/c/d";
    const author = "\x02\x20" ++ "\x22" ** 32;
    const kind = "\x03\x04\x00\x00\x00\x01";
    try testing.fuzz({}, fuzzNip19Entity, .{
        .corpus = &.{
            seed(&.{ .{ .int = 0 }, .{ .slice = "\x33" ** 32 } }),
            seed(&.{ .{ .int = 3 }, .{ .slice = pk ++ relay_a ++ relay_a } }),
            seed(&.{ .{ .int = 4 }, .{ .slice = pk ++ relay_a ++ author ++ kind } }),
            seed(&.{ .{ .int = 5 }, .{ .slice = "\x00\x03abc" ++ relay_a ++ author ++ kind } }),
            seed(&.{ .{ .int = 6 }, .{ .slice = "\x00\x0dwss://a.b/c/d" } }),
            // A TLV whose length runs past the end, a type nobody defined, and a
            // wrong-sized pubkey.
            seed(&.{ .{ .int = 3 }, .{ .slice = "\x00\xff\x01" } }),
            seed(&.{ .{ .int = 3 }, .{ .slice = "\x09\x01x" ++ pk } }),
            seed(&.{ .{ .int = 3 }, .{ .slice = "\x00\x03abc" } }),
            // An naddr with its identifier twice.
            seed(&.{ .{ .int = 5 }, .{ .slice = "\x00\x03abc\x00\x03xyz" ++ author ++ kind } }),
        },
    });
}

/// NIP-19 past the checksum.
///
/// A random string carries a valid bech32 checksum about one time in a billion,
/// so the TLV parsers behind it are never entered by `fuzzNip19String`. This
/// encodes fuzzed bytes under a real prefix instead, so every input arrives at
/// the TLV loop with its length bytes, its types and its truncations intact.
///
/// Pointers (nprofile, nevent, naddr) ignore TLV types they do not know, so the
/// string is not expected to survive being decoded and encoded. The pointer is:
/// decode, encode, decode must give the first pointer again.
fn fuzzNip19Entity(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    const a = testing.allocator;
    const Kind = enum { npub, nsec, note, nprofile, nevent, naddr, nrelay };
    const which = smith.value(Kind);
    var raw: [320]u8 = undefined;
    const n = smith.slice(&raw);

    switch (which) {
        .npub, .nsec, .note => {
            // These carry exactly 32 bytes and nothing else.
            var bytes: [32]u8 = @splat(0);
            @memcpy(bytes[0..@min(n, 32)], raw[0..@min(n, 32)]);
            const s = switch (which) {
                .npub => try nip19.encodeNpub(a, bytes),
                .nsec => try nip19.encodeNsec(a, bytes),
                else => try nip19.encodeNote(a, bytes),
            };
            defer a.free(s);
            const back = switch (which) {
                .npub => try nip19.decodeNpub(a, s),
                .nsec => try nip19.decodeNsec(a, s),
                else => try nip19.decodeNote(a, s),
            };
            try testing.expectEqualSlices(u8, &bytes, &back);
        },
        .nprofile, .nevent, .naddr, .nrelay => {
            const data5 = try bech32.convertBits(a, raw[0..n], 8, 5, true);
            defer a.free(data5);
            const s = try bech32.encode(a, @tagName(which), data5);
            defer a.free(s);
            switch (which) {
                .nprofile => try checkNprofile(a, s),
                .nevent => try checkNevent(a, s),
                .naddr => try checkNaddr(a, s),
                else => try checkNrelay(a, s),
            }
        },
    }
}

fn checkNprofile(a: std.mem.Allocator, s: []const u8) !void {
    var first = nip19.decodeNprofile(a, s) catch return;
    defer first.deinit(a);
    const text = try nip19.encodeNprofile(a, first.pubkey, @ptrCast(first.relays));
    defer a.free(text);
    var second = try nip19.decodeNprofile(a, text);
    defer second.deinit(a);
    try testing.expectEqualSlices(u8, &first.pubkey, &second.pubkey);
    try testing.expect(stringsEqual(@ptrCast(first.relays), @ptrCast(second.relays)));
}

fn checkNevent(a: std.mem.Allocator, s: []const u8) !void {
    var first = nip19.decodeNevent(a, s) catch return;
    defer first.deinit(a);
    const text = try nip19.encodeNevent(a, first.id, @ptrCast(first.relays), first.author, first.kind);
    defer a.free(text);
    var second = try nip19.decodeNevent(a, text);
    defer second.deinit(a);
    try testing.expectEqualSlices(u8, &first.id, &second.id);
    try testing.expect(stringsEqual(@ptrCast(first.relays), @ptrCast(second.relays)));
    try testing.expectEqual(first.author != null, second.author != null);
    if (first.author) |x| try testing.expectEqualSlices(u8, &x, &second.author.?);
    try testing.expectEqual(first.kind, second.kind);
}

fn checkNaddr(a: std.mem.Allocator, s: []const u8) !void {
    var first = nip19.decodeNaddr(a, s) catch return;
    defer first.deinit(a);
    const text = try nip19.encodeNaddr(a, first.identifier, first.pubkey, first.kind, @ptrCast(first.relays));
    defer a.free(text);
    var second = try nip19.decodeNaddr(a, text);
    defer second.deinit(a);
    try testing.expectEqualStrings(first.identifier, second.identifier);
    try testing.expectEqualSlices(u8, &first.pubkey, &second.pubkey);
    try testing.expectEqual(first.kind, second.kind);
    try testing.expect(stringsEqual(@ptrCast(first.relays), @ptrCast(second.relays)));
}

fn checkNrelay(a: std.mem.Allocator, s: []const u8) !void {
    const first = nip19.decodeNrelay(a, s) catch return;
    defer a.free(first);
    const text = try nip19.encodeNrelay(a, first);
    defer a.free(text);
    const second = try nip19.decodeNrelay(a, text);
    defer a.free(second);
    try testing.expectEqualStrings(first, second);
}

// -- The smallest one, and the one everything else leans on -------------------

test "fuzz: fixed-width hex" {
    try testing.fuzz({}, fuzzHex, .{ .corpus = &.{
        one(zeros32),
        one("ABCDEFabcdef" ++ "0" ** 52),
        one(zeros64),
        one("zz"),
        one("abc"),
    } });
}

/// `decodeFixed` is what stands between a relay's id/pubkey/signature strings
/// and a fixed-size array, and its loop indexes `hex[i*2 + 1]`. The only thing
/// keeping that in range is one length check, so the length check is the test.
///
/// What decodes, encodes back to the same digits ignoring case.
fn fuzzHex(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [256]u8 = undefined;
    const n = smith.slice(&buf);
    if (hex.decodeFixed(32, buf[0..n])) |bytes| {
        const text = try hex.encode(testing.allocator, &bytes);
        defer testing.allocator.free(text);
        try testing.expect(std.ascii.eqlIgnoreCase(text, buf[0..n]));
    } else |_| {}
    _ = hex.decodeFixed(64, buf[0..n]) catch {};
    if (hex.decode(testing.allocator, buf[0..n])) |bytes| {
        defer testing.allocator.free(bytes);
        try testing.expectEqual(n, bytes.len * 2);
    } else |_| {}
}

// -- A signature check on bytes nobody vetted ---------------------------------

test "fuzz: verifying a signature over arbitrary bytes" {
    try testing.fuzz({}, fuzzVerify, .{ .corpus = &.{
        seed(&.{ .{ .bytes = &(.{0} ** 96) }, .{ .slice = "hi" } }),
        seed(&.{ .{ .bytes = &(.{0xff} ** 96) }, .{ .slice = "" } }),
    } });
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

// -- Remote signing -----------------------------------------------------------

test "fuzz: a NIP-46 request or response" {
    try testing.fuzz({}, fuzzNip46Message, .{ .corpus = &.{
        one("{\"id\":\"1\",\"method\":\"sign_event\",\"params\":[\"{}\",\"x\"]}"),
        one("{\"id\":\"1\",\"result\":\"ack\"}"),
        one("{\"id\":\"1\",\"result\":\"\",\"error\":\"denied\"}"),
        one("{\"id\":\"1\",\"method\":\"ping\",\"params\":[1]}"),
        one("[]"),
    } });
}

/// What a signer is sent, after it has been decrypted but before it has been
/// believed. These are the first bytes the daemon reads from a client it does
/// not yet trust, so the parse has to hold up against any of them. A request or
/// response that parses serialises to something that parses to the same fields.
fn fuzzNip46Message(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [2048]u8 = undefined;
    const n = smith.slice(&buf);
    const a = testing.allocator;

    if (nip46.parseRequest(a, buf[0..n])) |parsed| {
        var p = parsed;
        defer p.deinit();
        const text = try p.value.toJson(a);
        defer a.free(text);
        var again = try nip46.parseRequest(a, text);
        defer again.deinit();
        try testing.expectEqualStrings(p.value.id, again.value.id);
        try testing.expectEqualStrings(p.value.method, again.value.method);
        try testing.expect(stringsEqual(p.value.params, again.value.params));
        // Whether to sign is decided from the template inside a sign_event, which
        // is one more document a stranger wrote.
        _ = nip46.signEventKind(a, &p.value);
    } else |_| {}

    if (nip46.parseResponse(a, buf[0..n])) |parsed| {
        var p = parsed;
        defer p.deinit();
        const text = try p.value.toJson(a);
        defer a.free(text);
        var again = try nip46.parseResponse(a, text);
        defer again.deinit();
        try testing.expectEqualStrings(p.value.id, again.value.id);
        try testing.expectEqualStrings(p.value.result, again.value.result);
        try testing.expectEqualStrings(p.value.err, again.value.err);
    } else |_| {}
}

test "fuzz: a NIP-46 connection URI" {
    try testing.fuzz({}, fuzzNip46Uri, .{ .corpus = &.{
        one("bunker://" ++ zeros32 ++ "?relay=wss%3A%2F%2Frelay.example&secret=abc"),
        one("bunker://" ++ zeros32 ++ "?relay=wss://a&relay=wss://b&secret=%zz"),
        one("nostrconnect://" ++ zeros32 ++ "?relay=wss%3A%2F%2Fr&secret=s&perms=sign_event%3A1&name=App&url=https%3A%2F%2Fx&image=y"),
        one("bunker://" ++ zeros32),
        one("bunker://" ++ zeros32 ++ "?&&=&relay"),
        one("nostrconnect://" ++ zeros32 ++ "?%"),
    } });
}

/// The token somebody pastes into a client, or scans, to connect it to a signer.
/// The query is percent-decoded by hand, which is where a short escape at the
/// end of the string would read past it.
///
/// A bunker token that parses, built again from its parts and parsed again, is
/// the same token: that is the property a client relies on when it stores the
/// connection and reads it back after a restart.
fn fuzzNip46Uri(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    const a = testing.allocator;

    if (nip46.parseBunkerUri(a, buf[0..n])) |parsed| {
        var p = parsed;
        defer p.deinit();
        const text = try nip46.buildBunkerUri(a, p.value.remote_signer_pubkey, p.value.relays, p.value.secret);
        defer a.free(text);
        var again = try nip46.parseBunkerUri(a, text);
        defer again.deinit();
        try testing.expectEqualSlices(u8, &p.value.remote_signer_pubkey, &again.value.remote_signer_pubkey);
        try testing.expect(stringsEqual(p.value.relays, again.value.relays));
        try testing.expectEqual(p.value.secret != null, again.value.secret != null);
        if (p.value.secret) |s| try testing.expectEqualStrings(s, again.value.secret.?);
    } else |_| {}

    if (nip46.parseNostrConnectUri(a, buf[0..n])) |parsed| {
        var p = parsed;
        p.deinit();
    } else |_| {}
}

test "fuzz: the signer's local wire types" {
    try testing.fuzz({}, fuzzSignerIpc, .{ .corpus = &.{
        one("{\"state\":\"ready\",\"pubkey\":\"ab\"}"),
        one("{\"method\":\"create\",\"secret\":\"s\",\"passphrase\":\"p\"}"),
        one("{\"event\":\"{}\"}"),
        one("{\"peer\":\"" ++ zeros32 ++ "\",\"items\":[\"a\",\"b\"]}"),
        one("{\"items\":[]}"),
        one("{\"error\":\"nope\"}"),
    } });
}

/// The bodies the signer daemon and its clients send each other over the local
/// socket. Both ends parse a body the other end wrote, and one of them runs in a
/// process that holds a key.
fn fuzzSignerIpc(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [1024]u8 = undefined;
    const n = smith.slice(&buf);
    inline for (.{ signer_ipc.Pubkey, signer_ipc.Setup, signer_ipc.SignEvent, signer_ipc.Cipher, signer_ipc.CipherResult, signer_ipc.Failure }) |T| {
        if (signer_ipc.parse(T, testing.allocator, buf[0..n])) |parsed| {
            var p = parsed;
            defer p.deinit();
            const text = try p.value.toJson(testing.allocator);
            testing.allocator.free(text);
        } else |_| {}
    }
}

// -- A relay list from somebody else's event ----------------------------------

test "fuzz: a relay list event" {
    try testing.fuzz({}, fuzzRelayList, .{ .corpus = &.{
        one("{\"id\":\"" ++ zeros32 ++ "\",\"pubkey\":\"" ++ zeros32 ++ "\",\"created_at\":1,\"kind\":10002,\"tags\":[[\"r\",\"wss://a\"],[\"r\",\"wss://a\",\"read\"],[\"r\",\"wss://b\",\"write\"],[\"r\",\"\"],[\"r\"],[\"x\",\"y\"],[]],\"content\":\"\",\"sig\":\"" ++ zeros64 ++ "\"}"),
    } });
}

/// Where a stranger says they read and write. Routing decisions are made from
/// this, so a list that parses has to be a set: no empty url, no url twice.
fn fuzzRelayList(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);
    var ev = event.fromJson(testing.allocator, buf[0..n]) catch return;
    defer ev.deinit();

    var list = nip65.parseRelayList(testing.allocator, ev.value) catch return;
    defer list.deinit();
    const entries = list.list.entries;
    for (entries, 0..) |entry, i| {
        try testing.expect(entry.url.len != 0);
        for (entries[0..i]) |earlier| try testing.expect(!std.mem.eql(u8, entry.url, earlier.url));
    }
}

// -- A relay URL --------------------------------------------------------------

test "fuzz: a relay url" {
    try testing.fuzz({}, fuzzRelayUrl, .{ .corpus = &.{
        one("wss://relay.example"),
        one("ws://relay.example:7777/path?q=1"),
        one("wss://[::1]:8080/x"),
        one("wss://[::1"),
        one("wss://:80"),
        one("wss://h:99999"),
        one("https://relay.example"),
        one("ws://"),
    } });
}

/// The address a user typed into a relay list, or a stranger put in one.
///
/// What parses has a host, a path that starts at the root, and a host header
/// that can be built from it, and the host and path are slices of the input
/// rather than anything the parser made up.
fn fuzzRelayUrl(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [512]u8 = undefined;
    const n = smith.slice(&buf);
    const url = relay.parseUrl(buf[0..n]) catch return;
    try testing.expect(url.host.len != 0);
    try testing.expect(url.path.len != 0 and url.path[0] == '/');
    const input_start = @intFromPtr(&buf[0]);
    const input_end = input_start + n;
    try testing.expect(@intFromPtr(url.host.ptr) >= input_start and @intFromPtr(url.host.ptr) + url.host.len <= input_end);
    var host_buf: [600]u8 = undefined;
    _ = url.hostHeader(&host_buf);
}

// -- Words --------------------------------------------------------------------

test "fuzz: a mnemonic" {
    try testing.fuzz({}, fuzzMnemonic, .{ .corpus = &.{
        seed(&.{ .{ .slice = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" }, .{ .slice = "" } }),
        seed(&.{ .{ .slice = "abandon  abandon" }, .{ .slice = &(.{'p'} ** 300) } }),
        seed(&.{ .{ .slice = "zzzz" }, .{ .slice = "TREZOR" } }),
    } });
}

/// What a person types into a recovery box. A mnemonic that decodes is a
/// mnemonic: turned back into words it decodes to the same entropy. A
/// passphrase of any length is either used or refused, never written past.
fn fuzzMnemonic(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var words: [512]u8 = undefined;
    const wn = smith.slice(&words);
    var pass: [400]u8 = undefined;
    const pn = smith.slice(&pass);

    if (bip39.mnemonicToEntropy(testing.allocator, words[0..wn])) |entropy| {
        defer testing.allocator.free(entropy);
        const text = try bip39.entropyToMnemonic(testing.allocator, entropy);
        defer testing.allocator.free(text);
        const back = try bip39.mnemonicToEntropy(testing.allocator, text);
        defer testing.allocator.free(back);
        try testing.expectEqualSlices(u8, entropy, back);
    } else |_| {}

    if (pn > bip39.max_passphrase_len) {
        try testing.expectError(error.PassphraseTooLong, bip39.mnemonicToSeed(words[0..wn], pass[0..pn]));
    } else {
        _ = try bip39.mnemonicToSeed(words[0..wn], pass[0..pn]);
    }
}

// -- A key file somebody handed you -------------------------------------------

test "fuzz: an ncryptsec" {
    try testing.fuzz({}, fuzzNcryptsec, .{
        .corpus = &.{
            seed(&.{ .{ .int = 0 }, .{ .slice = &(.{2} ++ .{4} ++ .{0} ** 89) } }),
            // A cost that does not fit in the six bits scrypt takes.
            seed(&.{ .{ .int = 1 }, .{ .slice = &(.{2} ++ .{200} ++ .{0} ** 89) } }),
            seed(&.{ .{ .int = 0 }, .{ .slice = "short" } }),
        },
    });
}

/// An `ncryptsec` is a file the user was given or found, and unlocking it runs
/// scrypt with a cost the file chooses.
///
/// The payload is built around the fuzzed bytes so it reaches the cost field:
/// version 2, a cost from the input, then the rest. A cost the key derivation
/// cannot take has to be an error. Costs that a machine can actually run are
/// kept small so each input takes microseconds; a cost between 5 and 63 is a
/// legal request for time and memory and is deliberately not exercised.
fn fuzzNcryptsec(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    const a = testing.allocator;
    const wide = smith.value(bool);
    var raw: [96]u8 = undefined;
    const n = smith.slice(&raw);

    var payload: [91]u8 = @splat(0);
    @memcpy(payload[0..@min(n, 91)], raw[0..@min(n, 91)]);
    payload[0] = 2;
    if (wide) {
        if (payload[1] <= 63) payload[1] = 64 + payload[1] % 64;
    } else {
        payload[1] %= 5;
    }

    const data5 = try bech32.convertBits(a, &payload, 8, 5, true);
    defer a.free(data5);
    const s = try bech32.encode(a, "ncryptsec", data5);
    defer a.free(s);

    if (nip49.decrypt(a, s, "password")) |key| {
        // The ciphertext is zeros and the tag is whatever the input said; a
        // decryption that succeeds is a forgery of the tag, not a finding.
        _ = key;
    } else |err| {
        if (wide) try testing.expectEqual(error.WeakParameters, err);
    }

    // And the same bytes as a plain string.
    _ = nip49.decrypt(a, raw[0..n], "password") catch {};
}

// -- Strings in and out of JSON -----------------------------------------------

test "fuzz: a filter serialises to JSON" {
    try testing.fuzz({}, fuzzFilter, .{ .corpus = &.{
        seed(&.{ .{ .int = 1 }, .{ .int = 'e' }, .{ .slice = "a\"b\\c" }, .{ .bytes = &(.{1} ** 32) } }),
        seed(&.{ .{ .int = 0 }, .{ .int = '\n' }, .{ .slice = "\x00\x1f" }, .{ .bytes = &(.{2} ** 32) } }),
    } });
}

/// A subscription is built from values the user and other people supplied: a
/// hashtag, an id out of a mention, a search term. Whatever goes in, what goes
/// on the wire has to be JSON, because a relay will not read a request that is
/// not, and the one that breaks is silently never answered.
fn fuzzFilter(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    const with_tags = smith.value(bool);
    // A tag name on the wire is one ASCII letter. A byte above 127 is not a
    // letter, and as a key it would be a lone UTF-8 continuation byte.
    const letter = smith.value(u8) & 0x7f;
    var value: [64]u8 = undefined;
    const vn = smith.slice(&value);
    var id: [32]u8 = undefined;
    smith.bytes(&id);
    // JSON is Unicode. Bytes that are not UTF-8 cannot be put in a string.
    if (!std.unicode.utf8ValidateSlice(value[0..vn])) return;

    const values = [_][]const u8{value[0..vn]};
    const tag_filters = [_]filter.TagFilter{.{ .letter = letter, .values = &values }};
    const ids = [_][32]u8{id};
    const kinds = [_]u16{ 0, 65535 };
    const f = filter.Filter{
        .ids = &ids,
        .authors = &ids,
        .kinds = &kinds,
        .tags = if (with_tags) &tag_filters else null,
        .since = -1,
        .until = std.math.maxInt(i64),
        .limit = std.math.maxInt(u32),
    };

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try f.appendJson(&list, testing.allocator);
    try testing.expect(try std.json.validate(testing.allocator, list.items));

    const req = try message.encodeReq(testing.allocator, value[0..vn], &.{f});
    defer testing.allocator.free(req);
    try testing.expect(try std.json.validate(testing.allocator, req));
}

test "fuzz: a string escapes to JSON and back" {
    try testing.fuzz({}, fuzzJsonString, .{ .corpus = &.{
        one("plain"),
        one("a\"b\\c\n\r\t\x08\x0c\x00\x1f"),
        one("\u{e9}\u{1f600}"),
    } });
}

/// Every string this library puts in a message goes through one escaper. It has
/// to produce a document, and that document has to say the string it was given.
fn fuzzJsonString(_: void, smith: *testing.Smith) anyerror!void {
    @disableInstrumentation();
    var buf: [512]u8 = undefined;
    const n = smith.slice(&buf);
    if (!std.unicode.utf8ValidateSlice(buf[0..n])) return;

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(testing.allocator);
    try json.appendString(&list, testing.allocator, buf[0..n]);

    const parsed = try std.json.parseFromSlice([]const u8, testing.allocator, list.items, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(buf[0..n], parsed.value);
}
