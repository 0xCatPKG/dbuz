const std = @import("std");
const builtin = @import("builtin");

const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .optimize = optimize,
        .target = target,
    });

    const tests = b.addTest(.{
        .root_module = test_mod,
        .use_llvm = b.option(bool, "llvm", ""),
    });

    const run_test = b.addRunArtifact(tests);

    b.step("test", "Run tests").dependOn(&run_test.step);
b.step("check", "ZLS check step").dependOn(&tests.step);
}
