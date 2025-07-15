const std = @import("std");
const dbus_types = @import("../types/dbus_types.zig");

const String = dbus_types.String;

const DBusConnection = @import("../types/DBusConnection.zig");
const DBusMessage = @import("../types/DBusMessage.zig");
const DBusInterface = @import("../types/Interface.zig");

const DBusIntrospectable = @This();

conn: *DBusConnection,
allocator: std.mem.Allocator,
ctx: *IntrospectableCtx,

pub const IntrospectableCtx = struct {
    allocator: std.mem.Allocator,
    introspection_cache: std.StringHashMap(String),
    connection: *DBusConnection,

    pub fn dropCacheForPair(self: *IntrospectableCtx, path: []const u8, name: []const u8) void {
        const key = std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ path, name }) catch return;
        defer self.allocator.free(key);
        const kv_wrapped = self.introspection_cache.fetchRemove(key);
        if (kv_wrapped) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.value);
        }
    }

    pub fn dropCacheForName(self: *IntrospectableCtx, name: []const u8) void {
        const key = std.fmt.allocPrint(self.allocator, "@{s}", .{name}) catch return;
        defer self.allocator.free(key);
        var hashmap_clone = self.introspection_cache.clone() catch return;
        defer hashmap_clone.deinit();
        var it = hashmap_clone.iterator();
        var i: usize = 0;

        while (it.next()) |kv| : (i += 1) {
            if (std.mem.endsWith(u8, kv.key_ptr.*, key)) {
                self.allocator.free(kv.value_ptr.value);
                _ = self.introspection_cache.fetchRemove(kv.key_ptr.*);
                self.allocator.free(kv.key_ptr.*);
            }
        }
    }

    pub fn reset(self: *IntrospectableCtx) void {
        var it = self.introspection_cache.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            self.allocator.free(kv.value_ptr.value);
        }
        self.introspection_cache.deinit();
        self.introspection_cache = .init(self.allocator);
    }
};

pub fn init(userdata: *anyopaque, allocator: std.mem.Allocator) anyerror!DBusIntrospectable {
    const ctx: *IntrospectableCtx = @alignCast(@ptrCast(userdata));
    const self = DBusIntrospectable{
        .ctx = ctx,
        .allocator = allocator,
        .conn = ctx.connection,
    };
    return self;
}

pub fn @"method@Introspect"(self: *DBusIntrospectable, message: *DBusMessage) !String {
    if (message.path == null) return error.NoPathHeader;
    if (message.sender == null) return error.NoSenderHeader;
    if (message.interface == null) return error.NoInterfaceHeader;

    self.conn.names.mutex.lock();
    self.conn.global_objects.mutex.lock();
    defer self.conn.names.mutex.unlock();
    defer self.conn.global_objects.mutex.unlock();

    const key = try std.fmt.allocPrint(self.allocator, "{s}@{s}", .{message.path.?, message.destination.?});
    errdefer self.allocator.free(key);

    if (self.ctx.introspection_cache.get(key)) |s| {
        self.allocator.free(key);
        return s;
    }

    if (message.destination) |dest| {
        const name = self.conn.names.map.get(dest);
        if (name) |nam| {
            nam.objects.mutex.lock();
            defer nam.objects.mutex.unlock();
            const introspection = String{.value = try self.introspector(nam.objects.map, message.path.?), .ownership = true};
            errdefer introspection.deinit(self.allocator);
            try self.ctx.introspection_cache.put(key, introspection);
            return introspection;
        }
    }

    const introspection = String{.value = try self.introspector(null, message.path.?), .ownership = true};
    errdefer introspection.deinit(self.allocator);
    try self.ctx.introspection_cache.put(key, introspection);
    return introspection;
}

fn traverseStringHashmap(self: *DBusIntrospectable, map: std.StringHashMap(std.ArrayList(DBusInterface)), node: []const u8, traversed_nodes: *std.StringHashMap(void), output: *std.ArrayList(u8)) !void {
    var local_children_iterator = map.iterator();
    while (local_children_iterator.next()) |entry| {
        const child_node = entry.key_ptr.*;
        if (!std.mem.startsWith(u8, child_node, node)) continue;
        var child_node_without_prefix = child_node[node.len..];
        if (child_node_without_prefix.len > 0 and child_node_without_prefix[0] == '/') child_node_without_prefix = child_node_without_prefix[1..];
        const child_node_slash_pos: usize = std.ascii.indexOfIgnoreCase(child_node_without_prefix, "/") orelse child_node_without_prefix.len;
        const child_node_name = child_node_without_prefix[0..child_node_slash_pos];
        if (child_node_name.len == 0) continue;
        if (traversed_nodes.contains(child_node_name)) continue;
        traversed_nodes.put(child_node_name, {}) catch unreachable;
        const child_node_tag = try std.fmt.allocPrint(self.allocator, "<node name=\"{s}\"/>\n", .{child_node_name});
        defer self.allocator.free(child_node_tag);
        try output.appendSlice(child_node_tag);
    }
}

fn addInterfaces(self: *DBusIntrospectable, list: ?std.ArrayList(DBusInterface), _: []const u8, output: *std.ArrayList(u8)) !void {
    if (list) |ifaces| {
        for (ifaces.items) |interface| {
            if (interface.hidden) continue;
            const interface_tag = try std.fmt.allocPrint(self.allocator, "<interface name=\"{s}\">\n", .{interface.interface});
            defer self.allocator.free(interface_tag);
            try output.appendSlice(interface_tag);
            try output.appendSlice(interface.introspection);
            try output.appendSlice("</interface>\n");
        }
    }
}

fn introspector(self: *DBusIntrospectable, map: ?std.StringHashMap(std.ArrayList(DBusInterface)), node: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).init(self.allocator);
    defer result.deinit();

    const node_tag = try std.fmt.allocPrint(self.allocator, "<node name=\"{s}\">\n", .{node});
    defer self.allocator.free(node_tag);

    try result.appendSlice(node_tag);

    try addInterfaces(self, self.conn.global_objects.map.get("*"), node, &result);
    try addInterfaces(self, self.conn.global_objects.map.get(node), node, &result);

    var traversed_nodes = std.StringHashMap(void).init(self.allocator);
    defer traversed_nodes.deinit();

    try traverseStringHashmap(self, self.conn.global_objects.map, node, &traversed_nodes, &result);

    if (map) |local_map| {
        try traverseStringHashmap(self, local_map, node, &traversed_nodes, &result);
        try addInterfaces(self, local_map.get(node), node, &result);
    } else {
        var nameit = self.conn.names.map.iterator();
        while (nameit.next()) |entry| {
            const name = entry.value_ptr.*;
            name.objects.mutex.lock();
            defer name.objects.mutex.unlock();
            try traverseStringHashmap(self, name.objects.map, node, &traversed_nodes, &result);
            try addInterfaces(self, name.objects.map.get(node), node, &result);
        }
    }

    try result.appendSlice("</node>\n");
    return try result.toOwnedSlice();
}

pub inline fn introspectInterface(comptime Interface: type) []const u8 {
    comptime var data: []const u8 = "";
    const iface_info = @typeInfo(Interface).@"struct";

    for (iface_info.decls) |decl_| {
        data = data ++ if (isMethodNameValid(decl_.name)) introspectMethodCall(Interface, decl_.name, @field(Interface, decl_.name))
        else if (isSignalNameValid(decl_.name)) introspectSignal(Interface, decl_.name, @field(Interface, decl_.name))
        else if (isPropertyNameValid(decl_.name)) introspectProperty(Interface, decl_.name, @field(Interface, decl_.name))
        else "";
    }

    return data;
}

inline fn introspectMethodCall(comptime Interface: type, comptime name: []const u8, func: anytype) []const u8 {
    const fntype = @TypeOf(func);
    const typeinfo = @typeInfo(fntype);

    comptime var data: []const u8 = "";

    switch (typeinfo) {
        else => {},
        .@"fn" => |fninfo| {
            comptime if (fninfo.params.len == 0) return "";
            comptime if (fninfo.params[0].type.? != *Interface) return "";

            inline for (fninfo.params[1..]) |param| {
                comptime if (!dbus_types.isTypeSerializable(param.type.?) and param.type.? != *DBusMessage) return "";
            }

            data = data ++ "<method name=\"" ++ methodName(name) ++ "\">\n";
            for (fninfo.params[1..]) |param| {
                if (param.type.? == *DBusMessage) continue;
                data = data ++ "<arg name=\"arg_" ++ dbus_types.guessSignature(param.type.?) ++ "\" type=\"" ++ dbus_types.guessSignature(param.type.?) ++ "\" direction=\"in\"/>\n";
            }
            const retinfo = @typeInfo(fninfo.return_type.?);

            switch (retinfo) {
                else => {
                    switch (retinfo) {
                        else => {
                            if (!dbus_types.isTypeSerializable(fninfo.return_type.?)) return "";
                            data = data ++ "<arg name=\"out_" ++ dbus_types.guessSignature(fninfo.return_type.?) ++ "\" type=\"" ++ dbus_types.guessSignature(fninfo.return_type.?) ++ "\" direction=\"out\"/>\n";
                        },
                        .@"struct" => |structinfo| {
                            if (!dbus_types.isTypeSerializable(fninfo.return_type.?)) return "";
                            if (structinfo.is_tuple) {
                                for (structinfo.fields) |field| {
                                    data = data ++ "<arg name=\"" ++ field.name ++ "\" type=\"" ++ dbus_types.guessSignature(field.type.?) ++ "\" direction=\"out\"/>\n";
                                }
                            }
                            else data = data ++ "<arg name=\"out_" ++ dbus_types.guessSignature(fninfo.return_type.?) ++ "\" type=\"" ++ dbus_types.guessSignature(fninfo.return_type.?) ++ "\" direction=\"out\"/>\n";
                        },
                        .void => {}
                    }
                },
                .error_union => |errorinfo| {
                    const payloadinfo = @typeInfo(errorinfo.payload);
                    switch (payloadinfo) {
                        else => {
                            if (!dbus_types.isTypeSerializable(errorinfo.payload)) return "";
                            data = data ++ "<arg name=\"out_" ++ dbus_types.guessSignature(errorinfo.payload) ++ "\" type=\"" ++ dbus_types.guessSignature(errorinfo.payload) ++ "\" direction=\"out\"/>\n";
                        },
                        .@"struct" => |structinfo| {
                            if (!dbus_types.isTypeSerializable(errorinfo.payload)) return "";
                            if (structinfo.is_tuple) {
                                for (structinfo.fields) |field| {
                                    data = data ++ "<arg name=\"" ++ field.name ++ "\" type=\"" ++ dbus_types.guessSignature(field.type.?) ++ "\" direction=\"out\"/>\n";
                                }
                            }
                            else data = data ++ "<arg name=\"out_" ++ dbus_types.guessSignature(errorinfo.payload) ++ "\" type=\"" ++ dbus_types.guessSignature(errorinfo.payload) ++ "\" direction=\"out\"/>\n";
                        },
                        .void => {}
                    }
                }
            }

            data = data ++ "</method>\n";
        },
    }
    return data;
}

inline fn introspectSignal(comptime _: type, comptime name: []const u8, func: anytype) []const u8 {
    if (!validMemberName(name[7..])) return "";
    const fntype = @TypeOf(func);
    const typeinfo = @typeInfo(fntype);

    comptime var data: []const u8 = "";

    switch (typeinfo) {
        else => {},
        .@"fn" => |fninfo| {
            inline for (fninfo.params[0..]) |param| {
                comptime if (!dbus_types.isTypeSerializable(param.type.?)) return "";
            }
            data = data ++ "<signal name=\"" ++ signalName(name) ++ "\">\n";
            for (fninfo.params[0..]) |param| {
                data = data ++ "<arg name=\"arg_" ++ dbus_types.guessSignature(param.type.?) ++ "\" type=\"" ++ dbus_types.guessSignature(param.type.?) ++ "\" direction=\"out\"/>\n";
            }

            data = data ++ "</signal>\n";
        },
    }
    return data;
}

inline fn introspectProperty(comptime Interface: type, comptime name: []const u8, func: anytype) []const u8 {
    const fntype = @TypeOf(func);
    const typeinfo = @typeInfo(fntype);

    comptime var data: []const u8 = "";

    switch (typeinfo) {
        else => {},
        .@"fn" => |fninfo| {
            comptime if (fninfo.params.len == 0) return "";
            comptime if (fninfo.params[0].type.? != *Interface) return "";

            const readwrite = fninfo.params.len == 2;

            data = data ++ "<property name=\"" ++ propertyName(name) ++ "\"";
            const retinfo = @typeInfo(fninfo.return_type.?);

            switch (retinfo) {
                else => {
                    if (readwrite) {
                        if (fninfo.return_type.? != unwrapOptional(fninfo.params[1].type.?)) return "";
                    }
                    switch (retinfo) {
                        else => {
                            if (!dbus_types.isTypeSerializable(fninfo.return_type.?)) return "";
                            data = data ++ " type=\"" ++ dbus_types.guessSignature(fninfo.return_type.?) ++ "\"";
                        },
                        .void => {}
                    }
                },
                .error_union => |errorinfo| {
                    const payloadinfo = @typeInfo(errorinfo.payload);
                    if (readwrite) {
                        if (errorinfo.payload != fninfo.params[1].type.?) return "";
                    }
                    switch (payloadinfo) {
                        else => {
                            if (!dbus_types.isTypeSerializable(errorinfo.payload)) return "";
                            data = data ++ " type=\"" ++ dbus_types.guessSignature(errorinfo.payload) ++ "\"";
                        },
                        .void => {}
                    }
                }
            }
            data = data ++ " access=\"" ++ (if (readwrite) "readwrite" else "read") ++ "\"/>\n";
        },
    }
    return data;
}

pub inline fn isMethodNameValid(comptime name: []const u8) bool {
    if (name.len < 8) return false;
    if (name.len > 255 + 7) return false;
    if (!std.mem.eql(u8, name[0..7], "method@")) return false;
    return validMemberName(name[7..]);
}

pub inline fn methodName(comptime name: []const u8) []const u8 {
    return name[7..];
}

pub inline fn isPropertyNameValid(comptime name: []const u8) bool {
    if (name.len < 10) return false;
    if (name.len > 265) return false;
    if (!std.mem.eql(u8, name[0..9], "property@")) return false;
    return validMemberName(name[9..]);
}

pub inline fn propertyName(comptime name: []const u8) []const u8 {
    return name[9..];
}

pub inline fn isSignalNameValid(comptime name: []const u8) bool {
    if (name.len < 8) return false;
    if (name.len > 255 + 7) return false;
    if (!std.mem.eql(u8, name[0..7], "signal@")) return false;
    return validMemberName(name[7..]);
}

pub inline fn signalName(comptime name: []const u8) []const u8 {
    return name[7..];
}

pub inline fn validMemberName(comptime name: []const u8) bool {
    if (name.len == 0) return false;
    if (name.len > 255) return false;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    }
    return true;
}

inline fn unwrapOptional(comptime T: type) type {
    const typeinfo = @typeInfo(T);
    switch (typeinfo) {
        else => return T,
        .optional => |optional| return optional.child
    }
    unreachable;
}
