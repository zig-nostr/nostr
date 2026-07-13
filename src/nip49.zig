//! NIP-49: private key encryption at rest (`ncryptsec`).
//!
//! scrypt-derived symmetric key + XChaCha20-Poly1305, bech32-encoded.
//!
//! Per the spec, the password is Unicode-NFKC-normalized before the KDF (via
//! the pure-Zig `zg` Normalize module), so the same password derives the same
//! key across implementations regardless of its input Unicode form.

const std = @import("std");
const bech32 = @import("bech32.zig");
const Normalize = @import("Normalize");

pub const Error = bech32.Error || std.Io.RandomSecureError || error{
    InvalidPrefix,
    InvalidLength,
    InvalidVersion,
    DecryptionFailed,
    WeakParameters,
};

pub const KeySecurity = enum(u8) {
    /// The key is known to have been handled insecurely (unencrypted storage, clipboard, etc).
    known_insecure = 0x00,
    /// The key is known NOT to have been handled insecurely.
    known_secure = 0x01,
    /// The client does not track this data.
    unknown = 0x02,
};

const version_number: u8 = 0x02;
const salt_len = 16;
const nonce_len = 24;
const tag_len = 16;
const ad_len = 1;
const key_len = 32;
/// 1 (version) + 1 (log_n) + 16 (salt) + 24 (nonce) + 1 (ad) + 32 (ciphertext) + 16 (tag) = 91
const payload_len = 1 + 1 + salt_len + nonce_len + ad_len + key_len + tag_len;

/// Encrypts `privkey` with `password`. `log_n` is the scrypt cost parameter
/// (spec recommends 16 for ~100ms/64MiB up to 20+ for stronger protection).
/// `io` supplies fresh randomness for the salt and nonce (see `std.Io.randomSecure`).
/// Caller owns the returned `ncryptsec1...` string.
pub fn encrypt(
    allocator: std.mem.Allocator,
    io: std.Io,
    privkey: [32]u8,
    password: []const u8,
    log_n: u6,
    key_security: KeySecurity,
) Error![]u8 {
    var salt: [salt_len]u8 = undefined;
    try io.randomSecure(&salt);
    var nonce: [nonce_len]u8 = undefined;
    try io.randomSecure(&nonce);

    // NIP-49 requires the password to be NFKC-normalized before the KDF, so the
    // same password derives the same key across implementations regardless of
    // Unicode form. nfkc() returns the input unchanged, without allocating, when
    // it is ASCII-only or already normalized.
    const norm_pw = try Normalize.nfkc(allocator, password);
    defer norm_pw.deinit(allocator);

    var key: [key_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    std.crypto.pwhash.scrypt.kdf(allocator, &key, norm_pw.slice, &salt, .{ .ln = log_n, .r = 8, .p = 1 }) catch
        return Error.WeakParameters;

    const ad = [ad_len]u8{@intFromEnum(key_security)};
    var ciphertext: [key_len]u8 = undefined;
    var tag: [tag_len]u8 = undefined;
    std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(&ciphertext, &tag, &privkey, &ad, nonce, key);

    var payload: [payload_len]u8 = undefined;
    var i: usize = 0;
    payload[i] = version_number;
    i += 1;
    payload[i] = log_n;
    i += 1;
    @memcpy(payload[i .. i + salt_len], &salt);
    i += salt_len;
    @memcpy(payload[i .. i + nonce_len], &nonce);
    i += nonce_len;
    @memcpy(payload[i .. i + ad_len], &ad);
    i += ad_len;
    @memcpy(payload[i .. i + key_len], &ciphertext);
    i += key_len;
    @memcpy(payload[i .. i + tag_len], &tag);
    i += tag_len;
    std.debug.assert(i == payload_len);

    const data5 = try bech32.convertBits(allocator, &payload, 8, 5, true);
    defer allocator.free(data5);
    return bech32.encode(allocator, "ncryptsec", data5);
}

/// Decrypts an `ncryptsec1...` string with `password`, returning the raw
/// 32-byte private key.
pub fn decrypt(allocator: std.mem.Allocator, ncryptsec: []const u8, password: []const u8) Error![32]u8 {
    var decoded = try bech32.decode(allocator, ncryptsec);
    defer decoded.deinit(allocator);
    if (!std.mem.eql(u8, decoded.hrp, "ncryptsec")) return Error.InvalidPrefix;

    const payload = try bech32.convertBits(allocator, decoded.data, 5, 8, false);
    defer allocator.free(payload);
    if (payload.len != payload_len) return Error.InvalidLength;

    var i: usize = 0;
    const version = payload[i];
    i += 1;
    if (version != version_number) return Error.InvalidVersion;
    const log_n = payload[i];
    i += 1;
    const salt = payload[i .. i + salt_len];
    i += salt_len;
    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&nonce, payload[i .. i + nonce_len]);
    i += nonce_len;
    const ad = payload[i .. i + ad_len];
    i += ad_len;
    const ciphertext = payload[i .. i + key_len];
    i += key_len;
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, payload[i .. i + tag_len]);
    i += tag_len;
    std.debug.assert(i == payload_len);

    const norm_pw = try Normalize.nfkc(allocator, password);
    defer norm_pw.deinit(allocator);

    var key: [key_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    std.crypto.pwhash.scrypt.kdf(allocator, &key, norm_pw.slice, salt, .{ .ln = @intCast(log_n), .r = 8, .p = 1 }) catch
        return Error.WeakParameters;

    var privkey: [key_len]u8 = undefined;
    std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(&privkey, ciphertext, tag, ad, nonce, key) catch
        return Error.DecryptionFailed;

    return privkey;
}

fn hexToBytes32(hex: []const u8) ![32]u8 {
    if (hex.len != 64) return error.InvalidLength;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

test "decrypt matches the official NIP-49 spec vector" {
    const allocator = std.testing.allocator;
    const ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const expected = try hexToBytes32("3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683");

    const privkey = try decrypt(allocator, ncryptsec, "nostr");
    try std.testing.expectEqualSlices(u8, &expected, &privkey);
}

test "encrypt/decrypt round trip" {
    const allocator = std.testing.allocator;
    const privkey = try hexToBytes32("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");

    const ncryptsec = try encrypt(allocator, std.testing.io, privkey, "correct horse battery staple", 16, .known_secure);
    defer allocator.free(ncryptsec);
    try std.testing.expect(std.mem.startsWith(u8, ncryptsec, "ncryptsec1"));

    const decrypted = try decrypt(allocator, ncryptsec, "correct horse battery staple");
    try std.testing.expectEqualSlices(u8, &privkey, &decrypted);
}

test "decrypt rejects wrong password" {
    const allocator = std.testing.allocator;
    const privkey = try hexToBytes32("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");

    const ncryptsec = try encrypt(allocator, std.testing.io, privkey, "right password", 16, .unknown);
    defer allocator.free(ncryptsec);

    try std.testing.expectError(Error.DecryptionFailed, decrypt(allocator, ncryptsec, "wrong password"));
}

test "NFKC: compatibility-equivalent passwords derive the same key" {
    const allocator = std.testing.allocator;
    const privkey = try hexToBytes32("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");

    // U+FB00 (ﬀ, LATIN SMALL LIGATURE FF) is NFKC-compatibility-equal to "ff".
    // Encrypting with one form and decrypting with the other only works if the
    // password is normalized before the KDF.
    const ncryptsec = try encrypt(allocator, std.testing.io, privkey, "\u{FB00}", 16, .known_secure);
    defer allocator.free(ncryptsec);

    const decrypted = try decrypt(allocator, ncryptsec, "ff");
    try std.testing.expectEqualSlices(u8, &privkey, &decrypted);
}

test "NFKC: precomposed and decomposed accents derive the same key" {
    const allocator = std.testing.allocator;
    const privkey = try hexToBytes32("67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa");

    // "café" with a precomposed é (U+00E9) vs a decomposed e + combining acute
    // accent (U+0065 U+0301). NFKC maps both to the same normal form, so the
    // round trip across forms succeeds.
    const ncryptsec = try encrypt(allocator, std.testing.io, privkey, "caf\u{00E9}", 16, .known_secure);
    defer allocator.free(ncryptsec);

    const decrypted = try decrypt(allocator, ncryptsec, "cafe\u{0301}");
    try std.testing.expectEqualSlices(u8, &privkey, &decrypted);
}
