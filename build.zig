const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("dbuz", .{
        .root_source_file = b.path("src/dbuz.zig"),
        .optimize = optimize,
        .target = target,
    });

    const tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .optimize = optimize,
        .target = target,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_tests.step);

}
