//! secp256k1 keys and BIP-340 Schnorr signatures.
//!
//! This module is a thin, safe Zig wrapper over bitcoin-core's audited
//! libsecp256k1 (compiled from source, pinned in build.zig.zon). Signing and
//! verification are never reimplemented here — we only marshal bytes to and
//! from the C API, exactly as Nostr (NIP-01) requires: x-only public keys and
//! 64-byte Schnorr signatures over the secp256k1 curve.

const std = @import("std");
const c = @import("secp256k1");

pub const SecretKey = [32]u8;
/// x-only public key, 32 bytes (the Nostr `pubkey`).
pub const PublicKey = [32]u8;
/// 64-byte BIP-340 Schnorr signature (the Nostr `sig`).
pub const Signature = [64]u8;

pub const Error = error{
    InvalidSecretKey,
    InvalidPublicKey,
    SigningFailed,
    ContextRandomizationFailed,
};

pub const KeyPair = struct {
    secret_key: SecretKey,
    public_key: PublicKey,
};

/// Owns a libsecp256k1 context. Create one, reuse it for many operations,
/// and `deinit` it when done. Not thread-safe for concurrent signing on the
/// same instance; create one per thread if needed.
pub const Signer = struct {
    ctx: *c.secp256k1_context,

    /// Creates a signer. For production signing, prefer `initRandomized`,
    /// which adds side-channel (timing) hardening. Randomization does not
    /// change signature output — signatures remain deterministic given the
    /// aux_rand argument — so either constructor produces identical results.
    pub fn init() Signer {
        const ctx = c.secp256k1_context_create(c.SECP256K1_CONTEXT_NONE).?;
        return .{ .ctx = ctx };
    }

    /// Like `init`, but blinds the context with fresh randomness to harden
    /// against side-channel attacks (recommended for production signing).
    pub fn initRandomized(io: std.Io) Error!Signer {
        var self = init();
        errdefer self.deinit();
        var seed: [32]u8 = undefined;
        io.randomSecure(&seed) catch return Error.ContextRandomizationFailed;
        if (c.secp256k1_context_randomize(self.ctx, &seed) != 1) {
            return Error.ContextRandomizationFailed;
        }
        return self;
    }

    pub fn deinit(self: *Signer) void {
        c.secp256k1_context_destroy(self.ctx);
        self.* = undefined;
    }

    /// Derives the keypair (secret key + x-only public key) for a 32-byte
    /// secret key. Returns `InvalidSecretKey` if the key is out of range.
    pub fn keyPairFromSecretKey(self: Signer, secret_key: SecretKey) Error!KeyPair {
        var kp: c.secp256k1_keypair = undefined;
        if (c.secp256k1_keypair_create(self.ctx, &kp, &secret_key) != 1) {
            return Error.InvalidSecretKey;
        }
        var xonly: c.secp256k1_xonly_pubkey = undefined;
        if (c.secp256k1_keypair_xonly_pub(self.ctx, &xonly, null, &kp) != 1) {
            return Error.InvalidSecretKey;
        }
        var public_key: PublicKey = undefined;
        _ = c.secp256k1_xonly_pubkey_serialize(self.ctx, &public_key, &xonly);
        return .{ .secret_key = secret_key, .public_key = public_key };
    }

    /// Generates a fresh random keypair using `io` for entropy.
    pub fn generateKeyPair(self: Signer, io: std.Io) Error!KeyPair {
        while (true) {
            var secret_key: SecretKey = undefined;
            io.randomSecure(&secret_key) catch return Error.InvalidSecretKey;
            // Reject the negligibly-rare out-of-range key and retry.
            if (c.secp256k1_ec_seckey_verify(self.ctx, &secret_key) != 1) continue;
            return self.keyPairFromSecretKey(secret_key);
        }
    }

    /// Signs an arbitrary-length message per BIP-340. `aux_rand`, when
    /// provided, is 32 bytes of fresh randomness (recommended); pass `null`
    /// for deterministic signing. Nostr signs the 32-byte event id — see
    /// `signId`.
    pub fn sign(self: Signer, msg: []const u8, keypair: KeyPair, aux_rand: ?[32]u8) Error!Signature {
        var kp: c.secp256k1_keypair = undefined;
        if (c.secp256k1_keypair_create(self.ctx, &kp, &keypair.secret_key) != 1) {
            return Error.InvalidSecretKey;
        }

        var extra = c.secp256k1_schnorrsig_extraparams{
            .magic = .{ 0xda, 0x6f, 0xb3, 0x8c },
            .noncefp = null,
            .ndata = null,
        };
        if (aux_rand) |*rand| {
            extra.ndata = @ptrCast(@constCast(rand));
        }

        var sig: Signature = undefined;
        if (c.secp256k1_schnorrsig_sign_custom(self.ctx, &sig, msg.ptr, msg.len, &kp, &extra) != 1) {
            return Error.SigningFailed;
        }
        return sig;
    }

    /// Convenience for the Nostr case: sign a 32-byte event id.
    pub fn signId(self: Signer, id: [32]u8, keypair: KeyPair, aux_rand: ?[32]u8) Error!Signature {
        return self.sign(&id, keypair, aux_rand);
    }

    /// Verifies a BIP-340 signature over `msg` against an x-only public key.
    /// Returns false (rather than erroring) for any invalid input, including
    /// a public key that is not a valid curve point.
    pub fn verify(self: Signer, sig: Signature, msg: []const u8, public_key: PublicKey) bool {
        var xonly: c.secp256k1_xonly_pubkey = undefined;
        if (c.secp256k1_xonly_pubkey_parse(self.ctx, &xonly, &public_key) != 1) {
            return false;
        }
        return c.secp256k1_schnorrsig_verify(self.ctx, &sig, msg.ptr, msg.len, &xonly) == 1;
    }

    /// Convenience for the Nostr case: verify a signature over a 32-byte id.
    pub fn verifyId(self: Signer, sig: Signature, id: [32]u8, public_key: PublicKey) bool {
        return self.verify(sig, &id, public_key);
    }

    /// Adds `tweak` to `secret_key` modulo the curve order (BIP-32
    /// `CKDpriv`'s `parse256(IL) + kpar mod n`). Returns `InvalidSecretKey`
    /// in the negligibly-rare case the result would be invalid.
    pub fn tweakAdd(self: Signer, secret_key: SecretKey, tweak: [32]u8) Error!SecretKey {
        var sk = secret_key;
        if (c.secp256k1_ec_seckey_tweak_add(self.ctx, &sk, &tweak) != 1) {
            return Error.InvalidSecretKey;
        }
        return sk;
    }

    /// Serializes the compressed SEC1 public key (33 bytes: a 0x02/0x03
    /// parity prefix plus the x-coordinate) for a secret key. BIP-32 (used
    /// by NIP-06) needs this full compressed point for non-hardened child
    /// derivation — distinct from Nostr's 32-byte x-only public key.
    pub fn compressedPublicKey(self: Signer, secret_key: SecretKey) Error![33]u8 {
        var pk: c.secp256k1_pubkey = undefined;
        if (c.secp256k1_ec_pubkey_create(self.ctx, &pk, &secret_key) != 1) {
            return Error.InvalidSecretKey;
        }
        var out: [33]u8 = undefined;
        var out_len: usize = out.len;
        _ = c.secp256k1_ec_pubkey_serialize(self.ctx, &out, &out_len, &pk, c.SECP256K1_EC_COMPRESSED);
        std.debug.assert(out_len == out.len);
        return out;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn hexToBytes(comptime N: usize, hex: []const u8) [N]u8 {
    var out: [N]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "keypair derivation and sign/verify round trip" {
    var signer = Signer.init();
    defer signer.deinit();

    const kp = try signer.keyPairFromSecretKey(hexToBytes(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"));
    // Public key for this secret key, per BIP-340 test vector index 1.
    try std.testing.expectEqualSlices(u8, &hexToBytes(32, "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"), &kp.public_key);

    const id = hexToBytes(32, "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");
    const sig = try signer.signId(id, kp, null);
    try std.testing.expect(signer.verifyId(sig, id, kp.public_key));

    // A different message must not verify against the same signature.
    var other = id;
    other[0] ^= 0xff;
    try std.testing.expect(!signer.verifyId(sig, other, kp.public_key));
}

test "generated keypairs sign and verify" {
    var signer = try Signer.initRandomized(std.testing.io);
    defer signer.deinit();

    const kp = try signer.generateKeyPair(std.testing.io);
    const msg = "the quick brown fox";
    const sig = try signer.sign(msg, kp, null);
    try std.testing.expect(signer.verify(sig, msg, kp.public_key));
}

/// Official BIP-340 test vectors (bitcoin/bips bip-0340/test-vectors.csv).
/// `secret_key`/`aux_rand` are empty for verify-only vectors.
const Bip340Vector = struct {
    secret_key: []const u8,
    public_key: []const u8,
    aux_rand: []const u8,
    message: []const u8,
    signature: []const u8,
    valid: bool,
};

const bip340_vectors = [_]Bip340Vector{
    .{ .secret_key = "0000000000000000000000000000000000000000000000000000000000000003", .public_key = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", .aux_rand = "0000000000000000000000000000000000000000000000000000000000000000", .message = "0000000000000000000000000000000000000000000000000000000000000000", .signature = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0", .valid = true },
    .{ .secret_key = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "0000000000000000000000000000000000000000000000000000000000000001", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A", .valid = true },
    .{ .secret_key = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", .public_key = "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8", .aux_rand = "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906", .message = "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", .signature = "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7", .valid = true },
    .{ .secret_key = "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710", .public_key = "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517", .aux_rand = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", .message = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", .signature = "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3", .valid = true },
    .{ .secret_key = "", .public_key = "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9", .aux_rand = "", .message = "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703", .signature = "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4", .valid = true },
    .{ .secret_key = "", .public_key = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false },
    .{ .secret_key = "", .public_key = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", .valid = false },
    .{ .secret_key = "", .public_key = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30", .aux_rand = "", .message = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B", .valid = false },
    .{ .secret_key = "0340034003400340034003400340034003400340034003400340034003400340", .public_key = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux_rand = "0000000000000000000000000000000000000000000000000000000000000000", .message = "", .signature = "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63", .valid = true },
    .{ .secret_key = "0340034003400340034003400340034003400340034003400340034003400340", .public_key = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux_rand = "0000000000000000000000000000000000000000000000000000000000000000", .message = "11", .signature = "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF", .valid = true },
    .{ .secret_key = "0340034003400340034003400340034003400340034003400340034003400340", .public_key = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux_rand = "0000000000000000000000000000000000000000000000000000000000000000", .message = "0102030405060708090A0B0C0D0E0F1011", .signature = "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5", .valid = true },
    .{ .secret_key = "0340034003400340034003400340034003400340034003400340034003400340", .public_key = "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117", .aux_rand = "0000000000000000000000000000000000000000000000000000000000000000", .message = "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999", .signature = "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367", .valid = true },
};

test "BIP-340 official test-vector suite" {
    const allocator = std.testing.allocator;
    var signer = Signer.init();
    defer signer.deinit();

    for (bip340_vectors, 0..) |v, i| {
        errdefer std.debug.print("BIP-340 vector {d} failed\n", .{i});

        const public_key = hexToBytes(32, v.public_key);
        const sig = hexToBytes(64, v.signature);

        const message = try allocator.alloc(u8, v.message.len / 2);
        defer allocator.free(message);
        _ = try std.fmt.hexToBytes(message, v.message);

        // Signing half: for vectors that carry a secret key, deriving the
        // keypair must reproduce the vector's public key, and signing with
        // the given aux_rand must reproduce the exact expected signature.
        if (v.secret_key.len != 0) {
            const secret_key = hexToBytes(32, v.secret_key);
            const kp = try signer.keyPairFromSecretKey(secret_key);
            try std.testing.expectEqualSlices(u8, &public_key, &kp.public_key);

            const aux = hexToBytes(32, v.aux_rand);
            const produced = try signer.sign(message, kp, aux);
            try std.testing.expectEqualSlices(u8, &sig, &produced);
        }

        // Verification half: applies to every vector.
        try std.testing.expectEqual(v.valid, signer.verify(sig, message, public_key));
    }
}
