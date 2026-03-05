const std = @import("std");
const builtin = @import("builtin");

const Build = std.Build;

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dbuz_mod = b.addModule("dbuz", .{
        .root_source_file = b.path("src/dbuz.zig"),
        .optimize = optimize,
        .target = target,
    });

    const proxy_scanner_exe = b.addExecutable(.{
        .name = "proxy-host-scanner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/codegen/xml_scanner.zig"),
            .target = b.resolveTargetQuery(.{}),
        }),
    });
    if (b.lazyDependency("xml", .{})) |xml_dep| proxy_scanner_exe.root_module.addImport("xml", xml_dep.module("dishwasher"));

    const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path("src/test.zig"),
            .optimize = optimize,
            .target = target,
            .imports = &.{ .{ .name = "dbuz", .module = dbuz_mod } }
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

pub const ProxyScanner = struct {
    b: *Build,
    dbuz: *Build.Module,
    proxies: std.StringArrayHashMapUnmanaged(*Build.Module) = .empty,

    scanner_exe: *Build.Step.Compile,

    pub fn create(b: *Build, dbuz: *Build.Dependency) *ProxyScanner {
        const self = b.allocator.create(ProxyScanner) catch @panic("OOM");
        self.* = .{
            .b = b,
            .dbuz = dbuz.module("dbuz"),
            .scanner_exe = dbuz.artifact("proxy-host-scanner"),
        };


        return self;
    }

    pub fn addProxy(self: *ProxyScanner, name: []const u8, path: Build.LazyPath) void {
        const scan = self.b.addRunArtifact(self.scanner_exe);
        scan.addArg("-n");
        scan.addArg(name);
        scan.addArg("-i");
        scan.addFileArg(path);
        scan.addArg("-d");
        const proxy_file = scan.addOutputFileArg(self.b.fmt("{s}.zig", .{name}));

        const mod = self.b.createModule(.{
            .root_source_file = proxy_file,
            .imports = &.{ .{ .name = "dbuz", .module = self.dbuz } }
        });

        self.proxies.put(self.b.allocator, name, mod) catch @panic("OOM");
    }

    pub fn generate(self: *ProxyScanner) *Build.Module {
        var file = std.Io.Writer.Allocating.init(self.b.allocator);
        const writer = &file.writer;

        const mod = self.b.createModule(.{});

        var it = self.proxies.iterator();
        while (it.next()) |kv| {
            writer.print("pub const {s} = @import(\"{s}\");\n", .{ kv.key_ptr.*, kv.key_ptr.* }) catch @panic( "OOM");
            mod.addImport(kv.key_ptr.*, kv.value_ptr.*);
        }

        const write_file = self.b.addWriteFiles();
        mod.root_source_file = write_file.add("dbuz_proxies.zig", file.written());

        self.proxies.deinit(self.b.allocator);
        return mod;
    }
};
