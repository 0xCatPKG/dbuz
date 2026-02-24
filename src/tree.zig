
const std = @import("std");

pub fn comptimeKey(comptime key: []const u8) []const []const u8 {
    std.debug.assert(key.len > 0);
    comptime var key_arr: []const []const u8 = &.{};
    comptime var it = std.mem.splitScalar(u8, key[1..], '/');
    comptime while (it.next()) |part| {
        key_arr = key_arr ++ .{part};
    };
    return key_arr;
}

pub fn comptimePathWithLastComponent(comptime path: []const u8, comptime last_component: []const u8) []const []const u8 {
    std.debug.assert(path.len > 0);
    comptime var key_arr: []const []const u8 = &.{};
    comptime var it = std.mem.splitScalar(u8, path[1..], '/');
    comptime while (it.next()) |part| {
        key_arr = key_arr ++ .{part};
    };
    key_arr = key_arr ++ .{last_component};
    return key_arr;
}

pub fn runtimeKey(key: []const u8, allocator: std.mem.Allocator) ![]const []const u8 {
    std.debug.assert(key.len > 0);
    var component_list = std.ArrayList([]const u8).empty;
    errdefer {
        for (component_list.items) |component| allocator.free(component);
        component_list.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, key[1..], '/');
    while (it.next()) |part| {
        try component_list.append(allocator, try allocator.dupe(u8, part));
    }
    return component_list.toOwnedSlice(allocator);
}

pub fn runtimePathWithLastComponent(key: []const u8, last_component: []const u8, gpa: std.mem.Allocator) ![]const []const u8 {
    std.debug.assert(key.len > 0);
    var component_list = std.ArrayList([]const u8).empty;
    errdefer {
        for (component_list.items) |component| gpa.free(component);
        component_list.deinit(gpa);
    }
    var it = std.mem.splitScalar(u8, key[1..], '/');
    while (it.next()) |part| {
        try component_list.append(gpa, try gpa.dupe(u8, part));
    }
    try component_list.append(gpa, try gpa.dupe(u8, last_component));
    return component_list.toOwnedSlice(gpa);
}

pub fn runtimeKeyFree(key: []const []const u8, gpa: std.mem.Allocator) void {
    for (key) |part| gpa.free(part);
    gpa.free(key);
}

pub fn Tree(comptime Value: type) type {
    return struct {
        const Self = @This();
        pub const V = Value;
        pub const Branch = struct {
            pub const Node = union(enum) {
                leaf: V,
                branch: Branch,
            };
            branches: std.StringArrayHashMapUnmanaged(Node),

            pub fn deinit(self: *Branch, gpa: std.mem.Allocator) void {
                var it = self.branches.iterator();
                while (it.next()) |entry| {
                    switch (entry.value_ptr.*) {
                        .leaf => {},
                        .branch => entry.value_ptr.branch.deinit(gpa),
                    }
                    gpa.free(entry.key_ptr.*);
                }
                self.branches.deinit(gpa);
            }
        };

        pub const empty: Self = .{
            .root = .{
                .branch = .{
                    .branches = .empty,
                }
            }
        };

        root: Branch.Node,

        pub fn get(self: *const Self, key: []const []const u8) ?Branch.Node {
            var branch = &self.root.branch;
            var result: ?Branch.Node = null;
            for (key) |k| {
                if (result) |r| switch (r) {
                    .leaf => return null,
                    .branch => branch = &r.branch,
                };
                result = branch.branches.get(k);
                if (result == null) return null;
            }
            return result;
        }

        pub fn insert(self: *Self, gpa: std.mem.Allocator, key: []const []const u8, value: V) !void {
            var branch = &self.root.branch;
            for (key[0..key.len - 1]) |k| {
                const node = branch.branches.getPtr(k);
                if (node) |c| switch (c.*) {
                    .leaf => return error.KeyConflict,
                    .branch => {
                        branch = &c.branch;
                    },
                } else {
                    const new_node = try branch.branches.getOrPut(gpa, k);
                    if (!new_node.found_existing) { 
                        new_node.value_ptr.* = .{
                            .branch = .{
                                .branches = .empty,
                            }
                        };
                        new_node.key_ptr.* = try gpa.dupe(u8, k);
                        branch = &(new_node.value_ptr.branch);
                    } else return error.KeyConflict;
                }
            }
            const target_node = try branch.branches.getOrPut(gpa, key[key.len - 1]);
            if (target_node.found_existing) return error.KeyConflict;
            target_node.value_ptr.* = .{ .leaf = value };
            target_node.key_ptr.* = try gpa.dupe(u8, key[key.len - 1]);
        }

        pub fn remove(self: *Self, gpa: std.mem.Allocator, key: []const []const u8) bool {
            var branch = &self.root.branch;
            for (key[0..key.len - 1]) |k| {
                const node = branch.branches.getPtr(k);
                if (node) |c| switch (c.*) {
                    .leaf => return false,
                    .branch => {
                        branch = &c.branch;
                    }
                } else {
                    return false;
                }
            }
            const entry = branch.branches.fetchSwapRemove(key[key.len - 1]);
            if (entry) |kv| {
                gpa.free(kv.key);
                return true;
            }
            return false;
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.root.branch.deinit(gpa);
        }
    };
}

test "insert" {
    const testing = std.testing;
    const gpa = std.testing.allocator;
    var tree = Tree(i32).empty;
    defer tree.deinit(gpa);

    try tree.insert(gpa, comptimeKey("/a/b/c"), 42);
    try tree.insert(gpa, comptimeKey("/a/b/d"), 43);
    try testing.expectError(error.KeyConflict, tree.insert(gpa, comptimeKey("/a/b/c"), 44));

    const v1 = tree.get(comptimeKey("/a/b/c")) orelse unreachable;

    std.debug.print("{any}\n", .{v1});
    try testing.expect(tree.remove(gpa, comptimeKey("/a/b/c")));
    try testing.expect(!tree.remove(gpa, comptimeKey("/a/b/c")));
}
