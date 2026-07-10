//! BIP-39: mnemonic seed phrases.
//!
//! Generates mnemonic word lists from entropy (with their checksum) and
//! derives the 64-byte binary seed from a mnemonic via PBKDF2-HMAC-SHA512,
//! per the BIP-39 spec. Used by NIP-06 (`src/nip06.zig`) as the first step
//! before BIP-32 key derivation.
//!
//! Known limitation: BIP-39 specifies NFKD Unicode normalization of the
//! mnemonic and passphrase before use. Zig's standard library has no
//! Unicode normalization support (see the same limitation documented in
//! `src/nip49.zig`), so this module operates on the input bytes as given.
//! ASCII mnemonics (the English wordlist used here) are unaffected by NFKD
//! normalization, so this only matters for non-ASCII passphrases.

const std = @import("std");

/// The official BIP-39 English wordlist (2048 words, sorted).
pub const wordlist: [2048][]const u8 = blk: {
    @setEvalBranchQuota(200000);
    const raw = @embedFile("data/bip39_english.txt");
    var words: [2048][]const u8 = undefined;
    var it = std.mem.tokenizeScalar(u8, raw, '\n');
    var i: usize = 0;
    while (it.next()) |w| : (i += 1) {
        words[i] = w;
    }
    if (i != 2048) @compileError("bip39 wordlist must have exactly 2048 words");
    break :blk words;
};

pub const Error = error{
    InvalidWordCount,
    UnknownWord,
    InvalidChecksum,
    InvalidEntropyLength,
} || std.mem.Allocator.Error;

fn wordIndex(word: []const u8) ?u11 {
    // The wordlist is sorted, so a binary search is correct and avoids a
    // linear scan per word during mnemonic parsing.
    var lo: usize = 0;
    var hi: usize = wordlist.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, wordlist[mid], word)) {
            .eq => return @intCast(mid),
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

/// Encodes `entropy` (16, 20, 24, 28, or 32 bytes — 128/160/192/224/256
/// bits) as a mnemonic (12/15/18/21/24 words respectively), appending the
/// BIP-39 checksum. Caller owns the returned, space-separated string.
pub fn entropyToMnemonic(allocator: std.mem.Allocator, entropy: []const u8) Error![]u8 {
    switch (entropy.len) {
        16, 20, 24, 28, 32 => {},
        else => return Error.InvalidEntropyLength,
    }

    var checksum_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entropy, &checksum_hash, .{});
    const checksum_bits = entropy.len / 4; // entropy_bits / 32

    const word_count = (entropy.len * 8 + checksum_bits) / 11;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var bit_pos: usize = 0;
    const total_bits = entropy.len * 8 + checksum_bits;
    for (0..word_count) |wi| {
        if (wi != 0) try out.append(allocator, ' ');
        var idx: u16 = 0;
        for (0..11) |_| {
            const byte = if (bit_pos < entropy.len * 8)
                entropy[bit_pos / 8]
            else
                checksum_hash[(bit_pos - entropy.len * 8) / 8];
            const bit: u1 = @truncate(byte >> @intCast(7 - (bit_pos % 8)));
            idx = (idx << 1) | bit;
            bit_pos += 1;
        }
        std.debug.assert(bit_pos <= total_bits);
        try out.appendSlice(allocator, wordlist[idx]);
    }

    return out.toOwnedSlice(allocator);
}

/// Decodes a mnemonic back to its entropy bytes, verifying the checksum.
/// Caller owns the returned slice.
pub fn mnemonicToEntropy(allocator: std.mem.Allocator, mnemonic: []const u8) Error![]u8 {
    var indices: [24]u11 = undefined;
    var count: usize = 0;
    var it = std.mem.tokenizeScalar(u8, mnemonic, ' ');
    while (it.next()) |word| {
        if (count >= 24) return Error.InvalidWordCount;
        indices[count] = wordIndex(word) orelse return Error.UnknownWord;
        count += 1;
    }
    switch (count) {
        12, 15, 18, 21, 24 => {},
        else => return Error.InvalidWordCount,
    }

    const total_bits = count * 11;
    const checksum_bits = total_bits / 33;
    const entropy_bits = total_bits - checksum_bits;
    const entropy_len = entropy_bits / 8;

    var bits: [24 * 11]u1 = undefined;
    for (indices[0..count], 0..) |idx, wi| {
        for (0..11) |b| {
            bits[wi * 11 + b] = @truncate(idx >> @intCast(10 - b));
        }
    }

    const entropy = try allocator.alloc(u8, entropy_len);
    errdefer allocator.free(entropy);
    for (entropy, 0..) |*byte, i| {
        var v: u8 = 0;
        for (0..8) |b| v = (v << 1) | bits[i * 8 + b];
        byte.* = v;
    }

    var checksum_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entropy, &checksum_hash, .{});
    for (0..checksum_bits) |b| {
        const expected: u1 = @truncate(checksum_hash[b / 8] >> @intCast(7 - (b % 8)));
        if (bits[entropy_bits + b] != expected) return Error.InvalidChecksum;
    }

    return entropy;
}

/// Derives the 64-byte BIP-39 seed from a mnemonic and optional passphrase
/// via PBKDF2-HMAC-SHA512 (2048 rounds), independent of whether the
/// mnemonic's checksum is valid — this matches BIP-39's own seed-derivation
/// algorithm, which does not re-validate the checksum.
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: []const u8) [64]u8 {
    var salt: [8 + 256]u8 = undefined;
    @memcpy(salt[0..8], "mnemonic");
    std.debug.assert(passphrase.len <= 256);
    @memcpy(salt[8 .. 8 + passphrase.len], passphrase);

    var seed: [64]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&seed, mnemonic, salt[0 .. 8 + passphrase.len], 2048, std.crypto.auth.hmac.sha2.HmacSha512) catch unreachable;
    return seed;
}

test "wordlist is sorted and has 2048 entries" {
    try std.testing.expectEqual(@as(usize, 2048), wordlist.len);
    try std.testing.expectEqualStrings("abandon", wordlist[0]);
    try std.testing.expectEqualStrings("zoo", wordlist[2047]);
    for (1..wordlist.len) |i| {
        try std.testing.expect(std.mem.order(u8, wordlist[i - 1], wordlist[i]) == .lt);
    }
}

test "entropyToMnemonic / mnemonicToEntropy round trip, all supported lengths" {
    const allocator = std.testing.allocator;
    for ([_]usize{ 16, 20, 24, 28, 32 }) |len| {
        var entropy: [32]u8 = undefined;
        for (entropy[0..len], 0..) |*b, i| b.* = @intCast(i);

        const mnemonic = try entropyToMnemonic(allocator, entropy[0..len]);
        defer allocator.free(mnemonic);

        const decoded = try mnemonicToEntropy(allocator, mnemonic);
        defer allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, entropy[0..len], decoded);
    }
}

test "mnemonicToEntropy rejects a bad checksum" {
    const allocator = std.testing.allocator;
    // Valid 12-word structure, but the last word is swapped for another
    // valid word, which will not satisfy the checksum for this entropy.
    const tampered = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    try std.testing.expectError(error.InvalidChecksum, mnemonicToEntropy(allocator, tampered));
}

test "official NIP-06 vector 1: mnemonic checksum is valid" {
    const allocator = std.testing.allocator;
    const mnemonic = "leader monkey parrot ring guide accident before fence cannon height naive bean";
    const entropy = try mnemonicToEntropy(allocator, mnemonic);
    defer allocator.free(entropy);
    try std.testing.expectEqual(@as(usize, 16), entropy.len);
}

test "official NIP-06 vector 2: mnemonic checksum is valid" {
    const allocator = std.testing.allocator;
    const mnemonic = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade";
    const entropy = try mnemonicToEntropy(allocator, mnemonic);
    defer allocator.free(entropy);
    try std.testing.expectEqual(@as(usize, 32), entropy.len);
}
