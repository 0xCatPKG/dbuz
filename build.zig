const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dbuz_mod = b.addModule("dbuz", .{
        .root_source_file = b.path("src/dbuz.zig"),
        .optimize = optimize,
        .target = target,
    });

    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .optimize = optimize,
        .target = target,
        })
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_tests.step);

    const check_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("check.zig"),
            .optimize = optimize,
            .target = target,
            .imports = &.{ .{ .name = "dbuz", .module = dbuz_mod} },
        })
    });

    const run_check = b.addRunArtifact(check_test);

    const check = b.step("check", "Step for ZLS checks");
    check.dependOn(&run_check.step);

}
