//! NIP-44 v2 payload encryption.
//!
//! Authenticated encryption for Nostr direct messages and the NIP-46 signer
//! transport. The construction (per the NIP-44 spec) is:
//!
//!   - conversation key: HKDF-extract(salt = "nip44-v2", IKM = ECDH-x(sec, pub))
//!   - per-message keys:  HKDF-expand(conversation_key, info = nonce, L = 76)
//!                        -> ChaCha20 key(32) | ChaCha20 nonce(12) | HMAC key(32)
//!   - ciphertext:        ChaCha20(key, nonce, pad(plaintext))
//!   - MAC:               HMAC-SHA256(hmac_key, nonce | ciphertext)
//!   - payload:           base64(version(0x02) | nonce(32) | ciphertext | mac(32))
//!
//! The elliptic-curve step is delegated to libsecp256k1 via `keys.Signer`
//! (see `Signer.sharedSecretX`); everything else uses Zig's std.crypto.
//!
//! Verified against the official NIP-44 test vectors: the tests below run
//! every `v2` vector embedded from `data/nip44_vectors.json`.

const std = @import("std");
const keys = @import("keys.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;

pub const Error = error{
    /// Plaintext was empty (NIP-44 requires 1..=65535 bytes).
    MessageEmpty,
    /// Plaintext exceeded the 65535-byte maximum.
    MessageTooLong,
    /// The peer public key is not a valid curve point.
    InvalidPublicKey,
    /// The secret key is zero or out of range.
    InvalidSecretKey,
    /// The payload is not valid base64, has an out-of-range length, or an
    /// unknown version byte.
    InvalidPayload,
    /// The decoded padding frame is malformed.
    InvalidPadding,
    /// The authentication tag did not match (tampered ciphertext or wrong key).
    InvalidMac,
    /// The randomness source failed while generating a nonce.
    RandomFailed,
    OutOfMemory,
};

/// NIP-44 v2 version byte.
pub const version: u8 = 2;

const min_plaintext_len: usize = 1;
const max_plaintext_len: usize = 65535;

/// Smallest and largest decoded payload sizes:
///   version(1) + nonce(32) + frame(2 + calcPaddedLen) + mac(32)
/// with calcPaddedLen ranging over 32 .. 65536.
const min_payload_len: usize = 1 + 32 + (2 + 32) + 32;
const max_payload_len: usize = 1 + 32 + (2 + 65536) + 32;

/// A 32-byte conversation key: symmetric, shared by both parties, derived once
/// per (secret, peer-pubkey) pair and reusable across many messages.
pub const ConversationKey = [32]u8;

/// Derives the NIP-44 conversation key for `secret_key` talking to
/// `peer_pubkey`. `signer` provides the libsecp256k1 ECDH.
pub fn conversationKey(
    signer: keys.Signer,
    secret_key: keys.SecretKey,
    peer_pubkey: keys.PublicKey,
) Error!ConversationKey {
    const shared_x = signer.sharedSecretX(secret_key, peer_pubkey) catch |err| switch (err) {
        error.InvalidPublicKey => return Error.InvalidPublicKey,
        else => return Error.InvalidSecretKey,
    };
    return HkdfSha256.extract("nip44-v2", &shared_x);
}

const MessageKeys = struct {
    chacha_key: [32]u8,
    chacha_nonce: [12]u8,
    hmac_key: [32]u8,
};

fn messageKeys(conversation_key: ConversationKey, nonce: [32]u8) MessageKeys {
    var expanded: [76]u8 = undefined;
    HkdfSha256.expand(&expanded, &nonce, conversation_key);
    var mk: MessageKeys = undefined;
    @memcpy(&mk.chacha_key, expanded[0..32]);
    @memcpy(&mk.chacha_nonce, expanded[32..44]);
    @memcpy(&mk.hmac_key, expanded[44..76]);
    return mk;
}

/// The padded-frame content length (excluding the 2-byte length prefix) for a
/// message of `unpadded_len` bytes, per NIP-44's padding scheme.
fn calcPaddedLen(unpadded_len: usize) usize {
    std.debug.assert(unpadded_len > 0);
    if (unpadded_len <= 32) return 32;
    const bits = std.math.log2_int(usize, unpadded_len - 1) + 1;
    const next_power = @as(usize, 1) << bits;
    const chunk: usize = if (next_power <= 256) 32 else next_power / 8;
    return chunk * (((unpadded_len - 1) / chunk) + 1);
}

/// Writes `be_u16(len) | plaintext | zeros` into a freshly allocated buffer.
fn pad(gpa: std.mem.Allocator, plaintext: []const u8) Error![]u8 {
    const buf = try gpa.alloc(u8, 2 + calcPaddedLen(plaintext.len));
    std.mem.writeInt(u16, buf[0..2], @intCast(plaintext.len), .big);
    @memcpy(buf[2..][0..plaintext.len], plaintext);
    @memset(buf[2 + plaintext.len ..], 0);
    return buf;
}

/// Reverses `pad`, validating the frame shape. Returns an owned copy of the
/// plaintext.
fn unpad(gpa: std.mem.Allocator, padded: []const u8) Error![]u8 {
    if (padded.len < 2) return Error.InvalidPadding;
    const unpadded_len = std.mem.readInt(u16, padded[0..2], .big);
    if (unpadded_len < min_plaintext_len) return Error.InvalidPadding;
    if (padded.len != 2 + calcPaddedLen(unpadded_len)) return Error.InvalidPadding;
    return gpa.dupe(u8, padded[2..][0..unpadded_len]);
}

/// HMAC-SHA256 over `nonce | ciphertext` (NIP-44 authenticates the nonce as
/// associated data).
fn computeMac(out: *[32]u8, hmac_key: [32]u8, nonce: [32]u8, ciphertext: []const u8) void {
    var mac = HmacSha256.init(&hmac_key);
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.final(out);
}

/// Encrypts `plaintext` with an explicit `nonce` and a precomputed conversation
/// key, returning the base64 payload (owned by the caller). Deterministic given
/// the nonce; used by the test vectors and by `encrypt`.
pub fn encryptWithConversationKey(
    gpa: std.mem.Allocator,
    conversation_key: ConversationKey,
    plaintext: []const u8,
    nonce: [32]u8,
) Error![]u8 {
    if (plaintext.len < min_plaintext_len) return Error.MessageEmpty;
    if (plaintext.len > max_plaintext_len) return Error.MessageTooLong;

    const mk = messageKeys(conversation_key, nonce);

    const padded = try pad(gpa, plaintext);
    defer gpa.free(padded);

    // version(1) | nonce(32) | ciphertext(padded.len) | mac(32)
    const raw = try gpa.alloc(u8, 1 + 32 + padded.len + 32);
    defer gpa.free(raw);
    raw[0] = version;
    @memcpy(raw[1..33], &nonce);
    const ciphertext = raw[33 .. 33 + padded.len];
    ChaCha20.xor(ciphertext, padded, 0, mk.chacha_key, mk.chacha_nonce);
    computeMac(raw[33 + padded.len ..][0..32], mk.hmac_key, nonce, ciphertext);

    const encoder = std.base64.standard.Encoder;
    const out = try gpa.alloc(u8, encoder.calcSize(raw.len));
    _ = encoder.encode(out, raw);
    return out;
}

/// Decrypts a base64 NIP-44 payload with a precomputed conversation key,
/// returning the plaintext (owned by the caller). Fails closed on any malformed
/// input or MAC mismatch.
pub fn decryptWithConversationKey(
    gpa: std.mem.Allocator,
    conversation_key: ConversationKey,
    payload: []const u8,
) Error![]u8 {
    // A leading '#' marks a reserved/unknown encoding per NIP-44.
    if (payload.len == 0 or payload[0] == '#') return Error.InvalidPayload;

    const decoder = std.base64.standard.Decoder;
    const raw_len = decoder.calcSizeForSlice(payload) catch return Error.InvalidPayload;
    if (raw_len < min_payload_len or raw_len > max_payload_len) return Error.InvalidPayload;

    const raw = try gpa.alloc(u8, raw_len);
    defer gpa.free(raw);
    decoder.decode(raw, payload) catch return Error.InvalidPayload;
    if (raw[0] != version) return Error.InvalidPayload;

    const nonce = raw[1..33].*;
    const ciphertext = raw[33 .. raw.len - 32];
    const mac = raw[raw.len - 32 ..][0..32];

    const mk = messageKeys(conversation_key, nonce);

    var expected_mac: [32]u8 = undefined;
    computeMac(&expected_mac, mk.hmac_key, nonce, ciphertext);
    if (!std.crypto.timing_safe.eql([32]u8, expected_mac, mac.*)) return Error.InvalidMac;

    const padded = try gpa.alloc(u8, ciphertext.len);
    defer gpa.free(padded);
    ChaCha20.xor(padded, ciphertext, 0, mk.chacha_key, mk.chacha_nonce);

    return unpad(gpa, padded);
}

/// Encrypts `plaintext` from `secret_key` to `peer_pubkey`, generating a fresh
/// random nonce from `io`. Returns the base64 payload (owned by the caller).
pub fn encrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    signer: keys.Signer,
    secret_key: keys.SecretKey,
    peer_pubkey: keys.PublicKey,
    plaintext: []const u8,
) Error![]u8 {
    const conversation_key = try conversationKey(signer, secret_key, peer_pubkey);
    var nonce: [32]u8 = undefined;
    io.randomSecure(&nonce) catch return Error.RandomFailed;
    return encryptWithConversationKey(gpa, conversation_key, plaintext, nonce);
}

/// Decrypts a base64 NIP-44 payload exchanged between `secret_key` and
/// `peer_pubkey`. Returns the plaintext (owned by the caller).
pub fn decrypt(
    gpa: std.mem.Allocator,
    signer: keys.Signer,
    secret_key: keys.SecretKey,
    peer_pubkey: keys.PublicKey,
    payload: []const u8,
) Error![]u8 {
    const conversation_key = try conversationKey(signer, secret_key, peer_pubkey);
    return decryptWithConversationKey(gpa, conversation_key, payload);
}

// ---------------------------------------------------------------------------
// Tests — official NIP-44 v2 vectors (data/nip44_vectors.json)
// ---------------------------------------------------------------------------

const testing = std.testing;
const vectors_json = @embedFile("data/nip44_vectors.json");

fn hexTo(comptime N: usize, s: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn parseVectors() !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, vectors_json, .{});
}

test "NIP-44 calc_padded_len official vectors" {
    const parsed = try parseVectors();
    defer parsed.deinit();
    const valid = parsed.value.object.get("v2").?.object.get("valid").?.object;
    for (valid.get("calc_padded_len").?.array.items) |pair| {
        const unpadded: usize = @intCast(pair.array.items[0].integer);
        const padded: usize = @intCast(pair.array.items[1].integer);
        try testing.expectEqual(padded, calcPaddedLen(unpadded));
    }
}

test "NIP-44 conversation key official vectors" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const parsed = try parseVectors();
    defer parsed.deinit();
    const valid = parsed.value.object.get("v2").?.object.get("valid").?.object;
    for (valid.get("get_conversation_key").?.array.items) |entry| {
        const o = entry.object;
        const sec1 = hexTo(32, o.get("sec1").?.string);
        const pub2 = hexTo(32, o.get("pub2").?.string);
        const want = hexTo(32, o.get("conversation_key").?.string);
        const got = try conversationKey(signer, sec1, pub2);
        try testing.expectEqualSlices(u8, &want, &got);
    }
}

test "NIP-44 message keys official vectors" {
    const parsed = try parseVectors();
    defer parsed.deinit();
    const valid = parsed.value.object.get("v2").?.object.get("valid").?.object;
    const mk_obj = valid.get("get_message_keys").?.object;
    const ck = hexTo(32, mk_obj.get("conversation_key").?.string);
    for (mk_obj.get("keys").?.array.items) |entry| {
        const o = entry.object;
        const mk = messageKeys(ck, hexTo(32, o.get("nonce").?.string));
        try testing.expectEqualSlices(u8, &hexTo(32, o.get("chacha_key").?.string), &mk.chacha_key);
        try testing.expectEqualSlices(u8, &hexTo(12, o.get("chacha_nonce").?.string), &mk.chacha_nonce);
        try testing.expectEqualSlices(u8, &hexTo(32, o.get("hmac_key").?.string), &mk.hmac_key);
    }
}

test "NIP-44 encrypt/decrypt official vectors" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const parsed = try parseVectors();
    defer parsed.deinit();
    const valid = parsed.value.object.get("v2").?.object.get("valid").?.object;
    for (valid.get("encrypt_decrypt").?.array.items) |entry| {
        const o = entry.object;
        const sec1 = hexTo(32, o.get("sec1").?.string);
        const sec2 = hexTo(32, o.get("sec2").?.string);
        const ck = hexTo(32, o.get("conversation_key").?.string);
        const nonce = hexTo(32, o.get("nonce").?.string);
        const plaintext = o.get("plaintext").?.string;
        const payload = o.get("payload").?.string;

        // The conversation key derives from sec1 + pubkey(sec2) and matches the
        // vector — this exercises the full ECDH path.
        const pub2 = (try signer.keyPairFromSecretKey(sec2)).public_key;
        const derived = try conversationKey(signer, sec1, pub2);
        try testing.expectEqualSlices(u8, &ck, &derived);

        // Encrypting with the vector nonce reproduces the exact payload.
        const enc = try encryptWithConversationKey(testing.allocator, ck, plaintext, nonce);
        defer testing.allocator.free(enc);
        try testing.expectEqualStrings(payload, enc);

        // Decryption recovers the plaintext.
        const dec = try decryptWithConversationKey(testing.allocator, ck, payload);
        defer testing.allocator.free(dec);
        try testing.expectEqualStrings(plaintext, dec);
    }
}

test "NIP-44 invalid decrypt official vectors all fail" {
    const parsed = try parseVectors();
    defer parsed.deinit();
    const invalid = parsed.value.object.get("v2").?.object.get("invalid").?.object;
    for (invalid.get("decrypt").?.array.items) |entry| {
        const o = entry.object;
        const ck = hexTo(32, o.get("conversation_key").?.string);
        const payload = o.get("payload").?.string;
        if (decryptWithConversationKey(testing.allocator, ck, payload)) |plaintext| {
            testing.allocator.free(plaintext);
            return error.TestExpectedDecryptToFail;
        } else |_| {}
    }
}

test "NIP-44 invalid conversation-key vectors all fail" {
    var signer = keys.Signer.init();
    defer signer.deinit();
    const parsed = try parseVectors();
    defer parsed.deinit();
    const invalid = parsed.value.object.get("v2").?.object.get("invalid").?.object;
    for (invalid.get("get_conversation_key").?.array.items) |entry| {
        const o = entry.object;
        const sec1 = hexTo(32, o.get("sec1").?.string);
        const pub2 = hexTo(32, o.get("pub2").?.string);
        if (conversationKey(signer, sec1, pub2)) |_| {
            return error.TestExpectedConversationKeyToFail;
        } else |_| {}
    }
}

test "NIP-44 rejects out-of-range plaintext lengths" {
    const ck: ConversationKey = [_]u8{0x11} ** 32;
    const nonce = [_]u8{0x22} ** 32;
    try testing.expectError(Error.MessageEmpty, encryptWithConversationKey(testing.allocator, ck, "", nonce));
    const too_long = try testing.allocator.alloc(u8, max_plaintext_len + 1);
    defer testing.allocator.free(too_long);
    @memset(too_long, 'a');
    try testing.expectError(Error.MessageTooLong, encryptWithConversationKey(testing.allocator, ck, too_long, nonce));
}

test "NIP-44 encrypt/decrypt round trip with a random nonce" {
    var signer = try keys.Signer.initRandomized(testing.io);
    defer signer.deinit();
    const alice = try signer.generateKeyPair(testing.io);
    const bob = try signer.generateKeyPair(testing.io);

    const message = "hello over nip-44";
    const payload = try encrypt(testing.allocator, testing.io, signer, alice.secret_key, bob.public_key, message);
    defer testing.allocator.free(payload);

    // The conversation key is symmetric: Bob decrypts with his secret and
    // Alice's public key.
    const out = try decrypt(testing.allocator, signer, bob.secret_key, alice.public_key, payload);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(message, out);

    // A third party cannot recover it — the MAC fails.
    const eve = try signer.generateKeyPair(testing.io);
    try testing.expectError(
        Error.InvalidMac,
        decrypt(testing.allocator, signer, eve.secret_key, alice.public_key, payload),
    );
}
