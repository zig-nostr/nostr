//! NIP-04 legacy encrypted direct messages (kind 4).
//!
//! NIP-04 is deprecated in favour of NIP-44 and offers no authentication. It
//! exists for interoperability with older clients. The construction is:
//!
//!   - key:      the raw x coordinate of ECDH(sec, pub), with no hashing
//!   - cipher:   AES-256-CBC with PKCS7 padding and a random 16-byte iv
//!   - payload:  "<base64 ciphertext>?iv=<base64 iv>"
//!
//! Because there is no MAC, a wrong key or a tampered ciphertext is only
//! noticed when the padding or the base64 framing is invalid. Callers must not
//! treat a successful decrypt as proof of authenticity.

const std = @import("std");
const keys = @import("keys.zig");

const Aes256 = std.crypto.core.aes.Aes256;

pub const Error = error{
    /// The peer public key is not a valid curve point.
    InvalidPublicKey,
    /// The secret key is zero or out of range.
    InvalidSecretKey,
    /// The payload has no `?iv=` part, or a part is not valid base64, or the
    /// ciphertext is empty or not a multiple of the block size.
    InvalidPayload,
    /// The iv is not exactly 16 bytes.
    InvalidIv,
    /// The PKCS7 padding is malformed (also the usual result of a wrong key).
    InvalidPadding,
    /// The randomness source failed while generating the iv.
    RandomFailed,
    /// The caller was cancelled while waiting for randomness.
    Canceled,
    OutOfMemory,
};

const block = 16;
const iv_marker = "?iv=";

fn sharedKey(signer: keys.Signer, secret_key: keys.SecretKey, peer_pubkey: keys.PublicKey) Error![32]u8 {
    return signer.sharedSecretX(secret_key, peer_pubkey) catch |e| switch (e) {
        error.InvalidPublicKey => Error.InvalidPublicKey,
        else => Error.InvalidSecretKey,
    };
}

/// Encrypts with a caller supplied iv. Deterministic; use `encrypt` unless a
/// test needs a fixed iv. Returns the payload, owned by the caller.
pub fn encryptWithIv(
    gpa: std.mem.Allocator,
    key: [32]u8,
    iv: [block]u8,
    plaintext: []const u8,
) Error![]u8 {
    const pad: usize = block - plaintext.len % block;
    const ct_len = plaintext.len + pad;

    const buf = gpa.alloc(u8, ct_len) catch return Error.OutOfMemory;
    defer gpa.free(buf);
    @memcpy(buf[0..plaintext.len], plaintext);
    @memset(buf[plaintext.len..], @intCast(pad));

    const ctx = Aes256.initEnc(key);
    var chain = iv;
    var i: usize = 0;
    while (i < ct_len) : (i += block) {
        const blk = buf[i..][0..block];
        for (blk, chain) |*b, c| b.* ^= c;
        ctx.encrypt(blk, blk);
        chain = blk.*;
    }

    const enc = std.base64.standard.Encoder;
    const ct_b64 = enc.calcSize(ct_len);
    const iv_b64 = enc.calcSize(block);
    const out = gpa.alloc(u8, ct_b64 + iv_marker.len + iv_b64) catch return Error.OutOfMemory;
    _ = enc.encode(out[0..ct_b64], buf);
    @memcpy(out[ct_b64..][0..iv_marker.len], iv_marker);
    _ = enc.encode(out[ct_b64 + iv_marker.len ..], &iv);
    return out;
}

/// Encrypts `plaintext` from `secret_key` to `peer_pubkey` with a fresh random
/// iv drawn from `io`. Returns `"<b64 ciphertext>?iv=<b64 iv>"`, owned by the
/// caller.
pub fn encrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    secret_key: keys.SecretKey,
    peer_pubkey: keys.PublicKey,
    plaintext: []const u8,
) Error![]u8 {
    var key = try sharedKey(signer, secret_key, peer_pubkey);
    defer std.crypto.secureZero(u8, &key);
    var iv: [block]u8 = undefined;
    io.randomSecure(&iv) catch |err| switch (err) {
        error.Canceled => |e| return e,
        error.EntropyUnavailable => return Error.RandomFailed,
    };
    return encryptWithIv(gpa, key, iv, plaintext);
}

/// Decrypts a NIP-04 payload exchanged between `secret_key` and `peer_pubkey`.
/// Returns the plaintext, owned by the caller.
pub fn decrypt(
    gpa: std.mem.Allocator,
    signer: keys.Signer,
    secret_key: keys.SecretKey,
    peer_pubkey: keys.PublicKey,
    payload: []const u8,
) Error![]u8 {
    var key = try sharedKey(signer, secret_key, peer_pubkey);
    defer std.crypto.secureZero(u8, &key);
    return decryptWithKey(gpa, key, payload);
}

pub fn decryptWithKey(gpa: std.mem.Allocator, key: [32]u8, payload: []const u8) Error![]u8 {
    const split = std.mem.lastIndexOf(u8, payload, iv_marker) orelse return Error.InvalidPayload;
    const ct_b64 = payload[0..split];
    const iv_b64 = payload[split + iv_marker.len ..];

    const dec = std.base64.standard.Decoder;
    const iv_len = dec.calcSizeForSlice(iv_b64) catch return Error.InvalidPayload;
    if (iv_len != block) return Error.InvalidIv;
    var iv: [block]u8 = undefined;
    dec.decode(&iv, iv_b64) catch return Error.InvalidPayload;

    const ct_len = dec.calcSizeForSlice(ct_b64) catch return Error.InvalidPayload;
    if (ct_len == 0 or ct_len % block != 0) return Error.InvalidPayload;
    const buf = gpa.alloc(u8, ct_len) catch return Error.OutOfMemory;
    errdefer gpa.free(buf);
    dec.decode(buf, ct_b64) catch return Error.InvalidPayload;

    const ctx = Aes256.initDec(key);
    var chain = iv;
    var i: usize = 0;
    while (i < ct_len) : (i += block) {
        const blk = buf[i..][0..block];
        const next = blk.*;
        ctx.decrypt(blk, blk);
        for (blk, chain) |*b, c| b.* ^= c;
        chain = next;
    }

    // Check the PKCS7 padding without branching on secret bytes: every one of
    // the last 16 bytes is examined regardless of where a mismatch occurs.
    const pad = buf[ct_len - 1];
    var bad: u8 = @intFromBool(pad == 0 or pad > block);
    for (0..block) |k| {
        const b = buf[ct_len - 1 - k];
        const in_pad: u8 = @intFromBool(k < pad);
        const differs: u8 = @intFromBool(b != pad);
        bad |= in_pad & differs;
    }
    if (bad != 0) return Error.InvalidPadding;

    const out = gpa.realloc(buf, ct_len - pad) catch return Error.OutOfMemory;
    return out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexTo(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// Throwaway keys: secret 1 and secret 2. The vector was produced by
// `nak encrypt --nip04 --sec <sk1> -p <pk2> hello`.
const sk1 = hexTo(32, "0000000000000000000000000000000000000000000000000000000000000001");
const sk2 = hexTo(32, "0000000000000000000000000000000000000000000000000000000000000002");
const pk1 = hexTo(32, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
const pk2 = hexTo(32, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
const nak_payload = "x80ZByas7SlU3jqzY7I8ZA==?iv=pxlXuZ9VabBOKBGYoaZ8mg==";

test "nip04: decrypts a payload produced by nak" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = try decrypt(testing.allocator, signer, sk2, pk1, nak_payload);
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("hello", a);
    const b = try decrypt(testing.allocator, signer, sk1, pk2, nak_payload);
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("hello", b);
}

test "nip04: fixed iv reproduces the nak payload" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const key = try signer.sharedSecretX(sk1, pk2);
    var iv: [16]u8 = undefined;
    try std.base64.standard.Decoder.decode(&iv, "pxlXuZ9VabBOKBGYoaZ8mg==");
    const out = try encryptWithIv(testing.allocator, key, iv, "hello");
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(nak_payload, out);
}

test "nip04: round trip across lengths" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const msgs = [_][]const u8{ "", "a", "0123456789abcdef", "0123456789abcdefg", "héllo wörld, long enough to span several blocks of data" };
    for (msgs) |m| {
        const p = try encrypt(testing.allocator, testing.io, signer, sk1, pk2, m);
        defer testing.allocator.free(p);
        try testing.expect(std.mem.indexOf(u8, p, "?iv=") != null);
        const d = try decrypt(testing.allocator, signer, sk2, pk1, p);
        defer testing.allocator.free(d);
        try testing.expectEqualStrings(m, d);
    }
}

test "nip04: fresh iv on every encrypt" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = try encrypt(testing.allocator, testing.io, signer, sk1, pk2, "same");
    defer testing.allocator.free(a);
    const b = try encrypt(testing.allocator, testing.io, signer, sk1, pk2, "same");
    defer testing.allocator.free(b);
    try testing.expect(!std.mem.eql(u8, a, b));
}

test "nip04: rejects malformed payloads" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = testing.allocator;
    // missing ?iv=
    try testing.expectError(Error.InvalidPayload, decrypt(a, signer, sk2, pk1, "x80ZByas7SlU3jqzY7I8ZA=="));
    // bad base64 in the ciphertext and in the iv
    try testing.expectError(Error.InvalidPayload, decrypt(a, signer, sk2, pk1, "x80Z!yas7SlU3jqzY7I8ZA==?iv=pxlXuZ9VabBOKBGYoaZ8mg=="));
    try testing.expectError(Error.InvalidPayload, decrypt(a, signer, sk2, pk1, "x80ZByas7SlU3jqzY7I8ZA==?iv=pxlXuZ9Vab!OKBGYoaZ8mg=="));
    // iv of the wrong length (8 bytes)
    try testing.expectError(Error.InvalidIv, decrypt(a, signer, sk2, pk1, "x80ZByas7SlU3jqzY7I8ZA==?iv=AAECAwQFBgc="));
    // ciphertext not a multiple of the block size (3 bytes) and empty
    try testing.expectError(Error.InvalidPayload, decrypt(a, signer, sk2, pk1, "AAEC?iv=pxlXuZ9VabBOKBGYoaZ8mg=="));
    try testing.expectError(Error.InvalidPayload, decrypt(a, signer, sk2, pk1, "?iv=pxlXuZ9VabBOKBGYoaZ8mg=="));
}

test "nip04: tampered ciphertext and bad padding fail" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const a = testing.allocator;
    // Flipping the last ciphertext block garbles the padding byte.
    const p = try a.dupe(u8, nak_payload);
    defer a.free(p);
    p[0] = if (p[0] == 'A') 'B' else 'A';
    if (decrypt(a, signer, sk2, pk1, p)) |d| {
        defer a.free(d);
        try testing.expect(!std.mem.eql(u8, d, "hello"));
    } else |e| try testing.expectEqual(Error.InvalidPadding, e);

    // Wrong key: the decrypt either fails padding or yields something else.
    var sk3 = sk1;
    sk3[31] = 3;
    if (decrypt(a, signer, sk3, pk1, nak_payload)) |d| {
        defer a.free(d);
        try testing.expect(!std.mem.eql(u8, d, "hello"));
    } else |e| try testing.expectEqual(Error.InvalidPadding, e);

    // Hand built block whose padding byte is out of range.
    const key = try signer.sharedSecretX(sk1, pk2);
    const iv = [_]u8{0} ** 16;
    const good = try encryptWithIv(a, key, iv, "x");
    defer a.free(good);
    var raw: [16]u8 = .{0x41} ** 16;
    raw[15] = 0; // pad byte zero
    const ctx = Aes256.initEnc(key);
    ctx.encrypt(&raw, &raw);
    var buf: [64]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(buf[0..24], &raw);
    const payload = try std.fmt.allocPrint(a, "{s}?iv=AAAAAAAAAAAAAAAAAAAAAA==", .{b64});
    defer a.free(payload);
    try testing.expectError(Error.InvalidPadding, decryptWithKey(a, key, payload));
}

fn encryptAfterCancel(io: std.Io, signer: keys.Signer) Error!void {
    // Waits to be cancelled, then carries the cancel into the call.
    io.sleep(.fromMilliseconds(60_000), .awake) catch |err| switch (err) {
        error.Canceled => io.recancel(),
    };
    const payload = try encrypt(testing.allocator, io, signer, sk1, pk2, "hello");
    testing.allocator.free(payload);
}

test "nip04: encrypt while cancelled reports the cancel" {
    const io = testing.io;
    var signer = keys.Signer.init();
    defer signer.deinit();
    var pending = try io.concurrent(encryptAfterCancel, .{ io, signer });
    // Where a cancel lands depends on the system: on Linux the read of
    // randomness takes it, elsewhere randomness never blocks and the call
    // completes. Either is fine. A cancel turned into another error is not.
    pending.cancel(io) catch |err| try testing.expectEqual(error.Canceled, err);
}
