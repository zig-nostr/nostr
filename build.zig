const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Audited BIP-340 Schnorr implementation. We compile bitcoin-core's
    // libsecp256k1 from source (pinned in build.zig.zon) rather than
    // hand-rolling signing, and expose its C API to Zig via translate-c.
    const secp = buildSecp256k1(b, target, optimize);

    // LMDB backs the local-first event store (src/store.zig): a zero-copy,
    // memory-mapped key/value engine. We compile the canonical liblmdb C
    // sources (pinned in build.zig.zon) directly and expose them via
    // translate-c, mirroring how we vendor libsecp256k1.
    const lmdb = buildLmdb(b, target, optimize);

    // The "nostr" module is the library's public API surface (src/root.zig).
    // This is what consumers import via `@import("nostr")`.
    const mod = b.addModule("nostr", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("secp256k1", secp.c_module);
    mod.linkLibrary(secp.library);
    mod.addImport("lmdb", lmdb.c_module);
    mod.linkLibrary(lmdb.library);

    // NFKC password normalization for NIP-49 (src/nip49.zig). zg is a pure-Zig
    // Unicode library; we import only its Normalize module to keep the footprint
    // small. Normalize.nfkc has a built-in ASCII fast-path (no allocation for
    // ASCII-only input), so the common password path stays allocation-free.
    const zg = b.dependency("zg", .{ .target = target, .optimize = optimize });
    mod.addImport("Normalize", zg.module("Normalize"));

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);

    // Store benchmark (src/bench.zig). Installed so `zig build` keeps it
    // compiling, and runnable via `zig build bench -- [num_events]`.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("nostr", mod);
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| run_bench.addArgs(args);
    const bench_step = b.step("bench", "Run the store benchmark");
    bench_step.dependOn(&run_bench.step);
}

const Secp256k1 = struct {
    library: *std.Build.Step.Compile,
    c_module: *std.Build.Module,
};

/// Compiles bitcoin-core/libsecp256k1 as a static library with the
/// schnorrsig + extrakeys + ecdh modules enabled (schnorrsig depends on
/// extrakeys; ecdh backs NIP-44), and produces a translate-c module exposing
/// its C API to Zig. The translate-c root is a small umbrella header
/// (src/secp256k1_bindings.h) so keys.zig and nip44.zig share one binding.
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
        .root_source_file = b.path("src/secp256k1_bindings.h"),
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
    "-DENABLE_MODULE_ECDH=1",
};

const Lmdb = struct {
    library: *std.Build.Step.Compile,
    c_module: *std.Build.Module,
};

/// Compiles the canonical liblmdb (two C files: mdb.c + midl.c) as a static
/// library and produces a translate-c module exposing its C API to Zig.
///
/// We disable Zig's C UBSan for these sources: liblmdb intentionally performs
/// unaligned reads and pointer arithmetic over its memory-mapped pages that
/// are well-defined for the engine but trip -fsanitize=undefined.
fn buildLmdb(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Lmdb {
    const upstream = b.dependency("lmdb", .{});
    const src = upstream.path("libraries/liblmdb");

    const lib = b.addLibrary(.{
        .name = "lmdb",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .sanitize_c = .off,
        }),
    });
    lib.root_module.addIncludePath(src);
    lib.root_module.addCSourceFiles(.{
        .root = src,
        .files = &.{ "mdb.c", "midl.c" },
    });
    lib.installHeadersDirectory(src, "", .{ .include_extensions = &.{"lmdb.h"} });

    const translate_c = b.addTranslateC(.{
        .root_source_file = src.path(b, "lmdb.h"),
        .target = target,
        .optimize = optimize,
    });
    translate_c.addIncludePath(src);

    const c_module = translate_c.createModule();
    c_module.linkLibrary(lib);

    return .{ .library = lib, .c_module = c_module };
}
