//! MatchGroup is a interface for match handling.
//! It uses compile time reflection to generate the necessary code.
//! See docs/MatchGroups.md for more information.

const std = @import("std");

const Self = @This();

const DBusMessage = @import("DBusMessage.zig");
const DBusConnection = @import("DBusConnection.zig");

ptr: *anyopaque, // Pointer to actual interface implementation
vtable: *const VTable,
rule: Rule,

pub const VTable = struct {
    signal: *const fn (*anyopaque, *DBusMessage) anyerror!void,
    deinit: *const fn (*anyopaque) void,
};

pub const Rule = struct {
    sender: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    path: ?[]const u8 = null,
    path_namespace: ?[]const u8 = null,
    destination: ?[]const u8 = null,

    silent: bool = false,
};

pub fn init(comptime RGroup: type, userdata: *anyopaque, alloc: std.mem.Allocator, rule: Rule) !Self {
    const S = struct {
        const RGroupSelf = @This();

        allocator: std.mem.Allocator,
        iface_impl: RGroup,

        pub fn init(allocator: std.mem.Allocator, udata: *anyopaque) !*RGroupSelf {
            const self = try allocator.create(RGroupSelf);
            self.* = .{
                .allocator = allocator,
                .iface_impl = RGroup.init(udata, allocator),
            };
            return self;
        }

        pub fn deinit(erased_impl: *anyopaque) void {
            const self: *RGroupSelf = @alignCast(@ptrCast(erased_impl));
            self.allocator.destroy(self);
        }

        pub fn signal(erased_impl: *anyopaque, msg: *DBusMessage) anyerror!void {
            const self: *RGroupSelf = @alignCast(@ptrCast(erased_impl));
            const typeinfo = @typeInfo(RGroup);

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            const allocator = arena.allocator();

            switch (typeinfo) {
                else => @compileError("Invalid container type"),
                .@"struct" => |s| {
                    inline for (s.decls) |decl_| {
                        const decl = @field(RGroup, decl_.name);
                        const decl_info = @typeInfo(@TypeOf(decl));
                        switch (decl_info) {
                            else => continue,
                            .@"fn" => |func| {
                                if (!(
                                        func.params.len < 1
                                        or func.params[0].type.? != *RGroup
                                    )
                                    and std.mem.eql(u8, decl_.name, msg.member.?)
                                    and decl_.name[0] != '_'
                                ) {
                                    comptime var read_args_slice: [func.params.len-1]type = undefined;
                                    inline for (func.params[1..], 0..) |param, i| {
                                        read_args_slice[i] = param.type.?;
                                    }

                                    const args = .{&self.iface_impl} ++ try msg.read(std.meta.Tuple(&read_args_slice), allocator);

                                    try @call(.auto, decl, args);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            return error.NotHandled;
        }
    };
    const rgroup_impl = try S.init(alloc, userdata);
    return .{
        .ptr = rgroup_impl,
        .vtable = &.{
            .signal = S.signal,
            .deinit = S.deinit,
        },
        .rule = rule
    };
}

pub fn deinit(self: Self) void {
    self.vtable.deinit(self.ptr);
}
