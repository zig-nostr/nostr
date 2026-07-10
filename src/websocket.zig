//! RFC 6455 WebSocket protocol: the opening-handshake helpers and the frame
//! codec. This is the transport layer under a Nostr relay connection (relays
//! speak JSON text frames over `ws://` / `wss://`).
//!
//! This module is deliberately I/O-free: it turns bytes into frames and frames
//! into bytes, and computes/checks the handshake fields. The actual socket —
//! TCP, TLS, the read/write loop and control-frame semantics — lives in the
//! relay client that drives this codec, so everything here is exercised by
//! pure unit tests (including the RFC 6455 worked examples).

const std = @import("std");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    /// Reserved / unknown opcodes decode here so the caller can reject them.
    _,
};

// ---------------------------------------------------------------------------
// Frame encoding (client -> server: RFC 6455 requires every client frame to
// be masked with a fresh 4-byte key).
// ---------------------------------------------------------------------------

/// Appends a single final (FIN=1) masked client frame to `list`: the 1-byte
/// FIN+opcode, the payload-length field (7-bit, or 16-/64-bit extended), the
/// 4-byte masking key, and the masked payload. `mask_key` should be fresh
/// random bytes per frame; the codec never invents one so it stays pure.
pub fn appendClientFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    opcode: Opcode,
    payload: []const u8,
    mask_key: [4]u8,
) std.mem.Allocator.Error!void {
    try list.append(allocator, 0x80 | @as(u8, @intFromEnum(opcode)));

    const len = payload.len;
    if (len <= 125) {
        try list.append(allocator, 0x80 | @as(u8, @intCast(len)));
    } else if (len <= 0xffff) {
        try list.append(allocator, 0x80 | 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext, @intCast(len), .big);
        try list.appendSlice(allocator, &ext);
    } else {
        try list.append(allocator, 0x80 | 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, &ext, len, .big);
        try list.appendSlice(allocator, &ext);
    }

    try list.appendSlice(allocator, &mask_key);
    for (payload, 0..) |byte, i| {
        try list.append(allocator, byte ^ mask_key[i % 4]);
    }
}

// ---------------------------------------------------------------------------
// Frame decoding.
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    /// The 64-bit length has its reserved most-significant bit set, which
    /// RFC 6455 forbids.
    InvalidFrame,
};

pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    /// Borrows from the decoded buffer (unmasked in place if the frame was
    /// masked). Valid until the buffer is reused.
    payload: []const u8,
    /// Total bytes this frame occupied — advance the read buffer by this much.
    frame_len: usize,
};

/// Decodes one frame from the front of `buf`, unmasking the payload in place
/// if the frame was masked. Returns `null` when `buf` does not yet hold a
/// complete frame (the caller should read more bytes and retry). Server frames
/// are never masked, but masked frames are handled for symmetry/testing.
pub fn decodeFrame(buf: []u8) DecodeError!?Frame {
    if (buf.len < 2) return null;

    const b0 = buf[0];
    const b1 = buf[1];
    const fin = (b0 & 0x80) != 0;
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0 & 0x0f)));
    const masked = (b1 & 0x80) != 0;
    const len7: u7 = @truncate(b1 & 0x7f);

    var offset: usize = 2;
    var payload_len: u64 = len7;
    if (len7 == 126) {
        if (buf.len < offset + 2) return null;
        payload_len = std.mem.readInt(u16, buf[offset..][0..2], .big);
        offset += 2;
    } else if (len7 == 127) {
        if (buf.len < offset + 8) return null;
        payload_len = std.mem.readInt(u64, buf[offset..][0..8], .big);
        if (payload_len > std.math.maxInt(u63)) return DecodeError.InvalidFrame;
        offset += 8;
    }

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (buf.len < offset + 4) return null;
        mask_key = buf[offset..][0..4].*;
        offset += 4;
    }

    if (payload_len > buf.len - offset) return null;
    const plen: usize = @intCast(payload_len);
    const payload = buf[offset .. offset + plen];
    if (masked) {
        for (payload, 0..) |*byte, i| byte.* ^= mask_key[i % 4];
    }

    return Frame{
        .fin = fin,
        .opcode = opcode,
        .payload = payload,
        .frame_len = offset + plen,
    };
}

// ---------------------------------------------------------------------------
// Opening handshake (RFC 6455 §4).
// ---------------------------------------------------------------------------

/// The fixed GUID appended to the client key before hashing, per RFC 6455.
pub const accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Computes the `Sec-WebSocket-Accept` value a server must return for a given
/// base64 `Sec-WebSocket-Key`: base64(sha1(key ++ GUID)). The 20-byte SHA-1
/// digest base64-encodes to exactly 28 characters.
pub fn acceptKey(sec_key: []const u8) [28]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(sec_key);
    sha1.update(accept_guid);
    var digest: [20]u8 = undefined;
    sha1.final(&digest);

    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

/// Generates a fresh base64 `Sec-WebSocket-Key` (16 random bytes → 24 chars)
/// using `io` for randomness.
pub fn generateKey(io: std.Io) error{RandomFailed}![24]u8 {
    var raw: [16]u8 = undefined;
    io.randomSecure(&raw) catch return error.RandomFailed;
    var out: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &raw);
    return out;
}

/// Appends the HTTP/1.1 upgrade request for `host`/`path` with `sec_key` (a
/// base64 `Sec-WebSocket-Key`) to `list`.
pub fn appendHandshakeRequest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    host: []const u8,
    path: []const u8,
    sec_key: []const u8,
) std.mem.Allocator.Error!void {
    try list.appendSlice(allocator, "GET ");
    try list.appendSlice(allocator, path);
    try list.appendSlice(allocator, " HTTP/1.1\r\nHost: ");
    try list.appendSlice(allocator, host);
    try list.appendSlice(allocator, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    try list.appendSlice(allocator, sec_key);
    try list.appendSlice(allocator, "\r\nSec-WebSocket-Version: 13\r\n\r\n");
}

pub const HandshakeError = error{
    /// The status line was not `HTTP/1.x 101`.
    BadStatus,
    /// No `Sec-WebSocket-Accept` header was present.
    MissingAccept,
    /// The `Sec-WebSocket-Accept` value did not match the expected digest.
    AcceptMismatch,
};

/// Verifies a server's handshake response head (the bytes up to and including
/// the terminating blank line) against `expected_accept` (from `acceptKey`).
pub fn checkHandshakeResponse(response: []const u8, expected_accept: []const u8) HandshakeError!void {
    var lines = std.mem.splitSequence(u8, response, "\r\n");

    const status = lines.next() orelse return HandshakeError.BadStatus;
    if (!isSwitchingProtocols(status)) return HandshakeError.BadStatus;

    var found = false;
    while (lines.next()) |line| {
        if (line.len == 0) break; // end of headers
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept")) {
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!std.mem.eql(u8, value, expected_accept)) return HandshakeError.AcceptMismatch;
            found = true;
        }
    }
    if (!found) return HandshakeError.MissingAccept;
}

fn isSwitchingProtocols(status_line: []const u8) bool {
    var tokens = std.mem.tokenizeScalar(u8, status_line, ' ');
    const version = tokens.next() orelse return false;
    if (!std.mem.startsWith(u8, version, "HTTP/1.")) return false;
    const code = tokens.next() orelse return false;
    return std.mem.eql(u8, code, "101");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn encode(allocator: std.mem.Allocator, opcode: Opcode, payload: []const u8, mask: [4]u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try appendClientFrame(&list, allocator, opcode, payload, mask);
    return list.toOwnedSlice(allocator);
}

test "acceptKey matches the RFC 6455 worked example" {
    // RFC 6455 §1.3: key "dGhlIHNhbXBsZSBub25jZQ==" -> accept
    // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".
    const accept = acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

test "encode masked frame matches the RFC 6455 example" {
    // RFC 6455 §5.7: a single-frame masked "Hello" with mask 0x37fa213d.
    const allocator = std.testing.allocator;
    const frame = try encode(allocator, .text, "Hello", .{ 0x37, 0xfa, 0x21, 0x3d });
    defer allocator.free(frame);
    const expected = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    try std.testing.expectEqualSlices(u8, &expected, frame);
}

test "decode the RFC 6455 unmasked server 'Hello' frame" {
    // RFC 6455 §5.7: unmasked "Hello" from server.
    var buf = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    const frame = (try decodeFrame(&buf)).?;
    try std.testing.expect(frame.fin);
    try std.testing.expectEqual(Opcode.text, frame.opcode);
    try std.testing.expectEqualStrings("Hello", frame.payload);
    try std.testing.expectEqual(@as(usize, 7), frame.frame_len);
}

test "decode unmasks a masked frame in place" {
    var buf = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    const frame = (try decodeFrame(&buf)).?;
    try std.testing.expectEqualStrings("Hello", frame.payload);
    try std.testing.expectEqual(@as(usize, 11), frame.frame_len);
}

test "decode returns null on a partial buffer" {
    // 2-byte header claims a 5-byte payload; only 3 payload bytes present.
    var buf = [_]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c };
    try std.testing.expect((try decodeFrame(&buf)) == null);
    // Header itself incomplete.
    var buf2 = [_]u8{0x81};
    try std.testing.expect((try decodeFrame(&buf2)) == null);
}

test "encode/decode round trip across all length classes" {
    const allocator = std.testing.allocator;
    const sizes = [_]usize{ 0, 1, 125, 126, 200, 0xffff, 0x10000, 70000 };
    for (sizes) |n| {
        const payload = try allocator.alloc(u8, n);
        defer allocator.free(payload);
        for (payload, 0..) |*b, i| b.* = @truncate(i * 7 + 1);

        const frame = try encode(allocator, .binary, payload, .{ 0xaa, 0xbb, 0xcc, 0xdd });
        defer allocator.free(frame);

        const decoded = (try decodeFrame(frame)).?;
        try std.testing.expectEqual(Opcode.binary, decoded.opcode);
        try std.testing.expectEqual(frame.len, decoded.frame_len);
        try std.testing.expectEqualSlices(u8, payload, decoded.payload);
    }
}

test "decode carries control opcodes and fin bit" {
    var ping = [_]u8{ 0x89, 0x00 }; // FIN + ping, empty payload
    const pf = (try decodeFrame(&ping)).?;
    try std.testing.expectEqual(Opcode.ping, pf.opcode);
    try std.testing.expect(pf.fin);

    var cont = [_]u8{ 0x00, 0x01, 0x41 }; // non-FIN continuation "A"
    const cf = (try decodeFrame(&cont)).?;
    try std.testing.expectEqual(Opcode.continuation, cf.opcode);
    try std.testing.expect(!cf.fin);
    try std.testing.expectEqualStrings("A", cf.payload);
}

test "decode rejects a 64-bit length with the reserved bit set" {
    var buf = [_]u8{ 0x82, 0x7f, 0xff, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(DecodeError.InvalidFrame, decodeFrame(&buf));
}

test "generateKey produces a 24-char base64 nonce" {
    const key = try generateKey(std.testing.io);
    try std.testing.expectEqual(@as(usize, 24), key.len);
    // Must decode back to 16 bytes of entropy.
    var raw: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&raw, &key);
}

test "handshake request has the required fields" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    try appendHandshakeRequest(&list, allocator, "relay.example.com", "/", "dGhlIHNhbXBsZSBub25jZQ==");
    const req = list.items;
    try std.testing.expect(std.mem.startsWith(u8, req, "GET / HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: relay.example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Upgrade: websocket\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Connection: Upgrade\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "Sec-WebSocket-Version: 13\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, req, "\r\n\r\n"));
}

test "checkHandshakeResponse accepts a valid response" {
    const accept = acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    const response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    try checkHandshakeResponse(response, &accept);
}

test "checkHandshakeResponse rejects bad status, missing, and mismatched accept" {
    const good_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    try std.testing.expectError(HandshakeError.BadStatus, checkHandshakeResponse(
        "HTTP/1.1 400 Bad Request\r\n\r\n",
        good_accept,
    ));
    try std.testing.expectError(HandshakeError.MissingAccept, checkHandshakeResponse(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        good_accept,
    ));
    try std.testing.expectError(HandshakeError.AcceptMismatch, checkHandshakeResponse(
        "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
        good_accept,
    ));
}
