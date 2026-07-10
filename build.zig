const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Audited BIP-340 Schnorr implementation. We compile bitcoin-core's
    // libsecp256k1 from source (pinned in build.zig.zon) rather than
    // hand-rolling signing, and expose its C API to Zig via translate-c.
    const secp = buildSecp256k1(b, target, optimize);

    // The "nostr" module is the library's public API surface (src/root.zig).
    // This is what consumers import via `@import("nostr")`.
    const mod = b.addModule("nostr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("secp256k1", secp.c_module);
    mod.linkLibrary(secp.library);

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);
}

const Secp256k1 = struct {
    library: *std.Build.Step.Compile,
    c_module: *std.Build.Module,
};

/// Compiles bitcoin-core/libsecp256k1 as a static library with the
/// schnorrsig + extrakeys modules enabled (schnorrsig depends on extrakeys),
/// and produces a translate-c module exposing its C API to Zig.
fn buildSecp256k1(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Secp256k1 {
    const upstream = b.dependency("secp256k1", .{});

    const lib = b.addLibrary(.{
        .name = "secp256k1",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.root_module.addIncludePath(upstream.path("include"));
    lib.root_module.addIncludePath(upstream.path("src"));
    lib.root_module.addCSourceFiles(.{
        .root = upstream.path("."),
        .flags = secp_flags,
        .files = &.{
            "src/secp256k1.c",
            "src/precomputed_ecmult.c",
            "src/precomputed_ecmult_gen.c",
        },
    });
    lib.installHeadersDirectory(upstream.path("include"), "", .{});

    const translate_c = b.addTranslateC(.{
        .root_source_file = upstream.path("include/secp256k1_schnorrsig.h"),
        .target = target,
        .optimize = optimize,
    });
    translate_c.addIncludePath(upstream.path("include"));

    const c_module = translate_c.createModule();
    c_module.linkLibrary(lib);

    return .{ .library = lib, .c_module = c_module };
}

const secp_flags = &.{
    "-DENABLE_MODULE_SCHNORRSIG=1",
    "-DENABLE_MODULE_EXTRAKEYS=1",
};
