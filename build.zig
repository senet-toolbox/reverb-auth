const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const reverb = b.dependency("reverb", .{ .target = target, .optimize = optimize });
    const reverb_mod = reverb.module("reverb");

    // OAuth and session handling for Reverb. Depends on reverb for Context,
    // Cookie and the request helpers; the dependency only goes this way.
    const mod = b.addModule("reverb_auth", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("reverb", reverb_mod);

    // `src/tests.zig` forces analysis of every declaration -- Zig checks
    // only what is reachable, and none of this had ever been compiled.
    const tests = b.addTest(.{
        .name = "reverb_auth",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "reverb", .module = reverb_mod }},
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    run_tests.has_side_effects = true;

    const test_step = b.step("test", "Run the tests");
    test_step.dependOn(&run_tests.step);
}
