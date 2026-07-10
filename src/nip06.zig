//! NIP-06: basic key derivation from a mnemonic seed phrase.
//!
//! BIP-39 (`src/bip39.zig`) turns a mnemonic into a 64-byte seed; this
//! module implements BIP-32 HD derivation over that seed for the path
//! `m/44'/1237'/<account>'/0/0` (1237 is Nostr's registered SLIP-44 index).
//!
//! Non-hardened derivation steps require the parent's compressed public key
//! (an EC point multiplication), so this binds to `keys.Signer` rather than
//! reimplementing elliptic-curve arithmetic.

const std = @import("std");
const bip39 = @import("bip39.zig");
const keys = @import("keys.zig");

const hardened_offset: u32 = 0x80000000;

const ExtendedKey = struct {
    key: keys.SecretKey,
    chain_code: [32]u8,
};

fn masterKey(seed: [64]u8) ExtendedKey {
    var i: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, &seed, "Bitcoin seed");
    return .{ .key = i[0..32].*, .chain_code = i[32..64].* };
}

/// BIP-32 `CKDpriv`: derives one child extended key at `index` (>=
/// `hardened_offset` for a hardened child).
fn deriveChild(signer: keys.Signer, parent: ExtendedKey, index: u32) keys.Error!ExtendedKey {
    var data: [37]u8 = undefined;
    if (index >= hardened_offset) {
        data[0] = 0;
        @memcpy(data[1..33], &parent.key);
    } else {
        const compressed = try signer.compressedPublicKey(parent.key);
        @memcpy(data[0..33], &compressed);
    }
    std.mem.writeInt(u32, data[33..37], index, .big);

    var i: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&i, &data, &parent.chain_code);

    const child_key = try signer.tweakAdd(parent.key, i[0..32].*);
    return .{ .key = child_key, .chain_code = i[32..64].* };
}

/// Derives the Nostr secret key for `account` from a BIP-39 seed, following
/// path `m/44'/1237'/<account>'/0/0`.
pub fn derivePrivateKey(signer: keys.Signer, seed: [64]u8, account: u32) keys.Error!keys.SecretKey {
    var node = masterKey(seed);
    const path = [_]u32{
        44 + hardened_offset,
        1237 + hardened_offset,
        account + hardened_offset,
        0,
        0,
    };
    for (path) |index| {
        node = try deriveChild(signer, node, index);
    }
    return node.key;
}

/// Convenience: mnemonic + passphrase -> BIP-39 seed -> NIP-06 secret key.
pub fn keyFromMnemonic(
    signer: keys.Signer,
    mnemonic: []const u8,
    passphrase: []const u8,
    account: u32,
) keys.Error!keys.SecretKey {
    const seed = bip39.mnemonicToSeed(mnemonic, passphrase);
    return derivePrivateKey(signer, seed, account);
}

fn hexToBytes32(hex: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "official NIP-06 vector 1" {
    var signer = keys.Signer.init();
    defer signer.deinit();

    const mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const secret_key = try keyFromMnemonic(signer, mnemonic, "", 0);
    try std.testing.expectEqualSlices(u8, &hexToBytes32("7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a"), &secret_key);

    const kp = try signer.keyPairFromSecretKey(secret_key);
    try std.testing.expectEqualSlices(u8, &hexToBytes32("17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"), &kp.public_key);
}

test "official NIP-06 vector 2" {
    var signer = keys.Signer.init();
    defer signer.deinit();

    const mnemonic = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
    const secret_key = try keyFromMnemonic(signer, mnemonic, "", 0);
    try std.testing.expectEqualSlices(u8, &hexToBytes32("c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add"), &secret_key);

    const kp = try signer.keyPairFromSecretKey(secret_key);
    try std.testing.expectEqualSlices(u8, &hexToBytes32("d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573"), &kp.public_key);
}

test "different accounts derive different keys" {
    var signer = keys.Signer.init();
    defer signer.deinit();

    const mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const key0 = try keyFromMnemonic(signer, mnemonic, "", 0);
    const key1 = try keyFromMnemonic(signer, mnemonic, "", 1);
    try std.testing.expect(!std.mem.eql(u8, &key0, &key1));
}

test "different passphrases derive different keys" {
    var signer = keys.Signer.init();
    defer signer.deinit();

    const mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const key_a = try keyFromMnemonic(signer, mnemonic, "", 0);
    const key_b = try keyFromMnemonic(signer, mnemonic, "extra words", 0);
    try std.testing.expect(!std.mem.eql(u8, &key_a, &key_b));
}
