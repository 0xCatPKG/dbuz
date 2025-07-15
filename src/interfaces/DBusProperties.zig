const std = @import("std");
const dbuz = @import("../dbuz.zig");

const String = dbuz.types.DBusString;

const DBusConnection = dbuz.types.DBusConnection;
const DBusMessage = dbuz.types.DBusMessage;
const DBusInterface = dbuz.types.DBusInterface;
const DBusName = dbuz.types.DBusName;
const DBusDictionary = dbuz.types.DBusDictionary;
const DBusCommon = dbuz.interfaces.DBusCommon;

pub const Action = enum {
    Get,
    Set
};

pub const Error = DBusConnection.Error || error {
    NoSuchProperty,
};

const DBusProperties = @This();

conn: *DBusConnection,
allocator: std.mem.Allocator,

pub fn init(userdata: *anyopaque, allocator: std.mem.Allocator) anyerror!DBusProperties {
    const conn: *DBusConnection = @alignCast(@ptrCast(userdata));
    return DBusProperties {
        .conn = conn,
        .allocator = allocator,
    };
}

pub fn @"method@GetAll"(self: *DBusProperties, interface_name: String, message: *DBusMessage) anyerror!void {
    if (message.path == null) return error.NoPathHeader;
    if (message.sender == null) return error.NoSenderHeader;

    self.conn.names.mutex.lock();
    self.conn.global_objects.mutex.lock();
    defer self.conn.names.mutex.unlock();
    defer self.conn.global_objects.mutex.unlock();

    const iface_pair = self.findInterface(message.destination, interface_name.value, message.path.?);
    if (iface_pair) |unwrapped| {
        const iface, const wrapped_mutex = unwrapped;
        defer if (wrapped_mutex) |mutex| mutex.unlock();
        message.flags |= DBusMessage.Flags.NO_REPLY_EXPECTED;
        errdefer message.flags &= ~DBusMessage.Flags.NO_REPLY_EXPECTED;
        return iface.vtable.all_properties(iface.ptr, self.conn, message);
    }

    return error.InterfaceNotFound;
}

pub fn @"method@Set"(self: *DBusProperties, interface_name: String, property_name: String, message: *DBusMessage) anyerror!void {
    if (message.path == null) return error.NoPathHeader;
    if (message.sender == null) return error.NoSenderHeader;

    self.conn.names.mutex.lock();
    self.conn.global_objects.mutex.lock();
    defer self.conn.names.mutex.unlock();
    defer self.conn.global_objects.mutex.unlock();

    const iface_pair = self.findInterface(message.destination, interface_name.value, message.path.?);
    if (iface_pair) |unwrapped| {
        const iface, const wrapped_mutex = unwrapped;
        defer if (wrapped_mutex) |mutex| mutex.unlock();
        message.flags |= DBusMessage.Flags.NO_REPLY_EXPECTED;
        errdefer message.flags &= ~DBusMessage.Flags.NO_REPLY_EXPECTED;
        return try iface.vtable.property(iface.ptr, self.conn, message, property_name.value, .Set);
    }
    return error.InterfaceNotFound;
}

pub fn @"method@Get"(self: *DBusProperties, interface_name: String, property_name: String, message: *DBusMessage) anyerror!void {
    if (message.path == null) return error.NoPathHeader;
    if (message.sender == null) return error.NoSenderHeader;

    self.conn.names.mutex.lock();
    self.conn.global_objects.mutex.lock();
    defer self.conn.names.mutex.unlock();
    defer self.conn.global_objects.mutex.unlock();

    const iface_pair = self.findInterface(message.destination, interface_name.value, message.path.?);
    if (iface_pair) |unwrapped| {
        const iface, const wrapped_mutex = unwrapped;
        defer if (wrapped_mutex) |mutex| mutex.unlock();
        message.flags |= DBusMessage.Flags.NO_REPLY_EXPECTED;
        errdefer message.flags &= ~DBusMessage.Flags.NO_REPLY_EXPECTED;
        return iface.vtable.property(iface.ptr, self.conn, message, property_name.value, .Get);
    }
    return error.InterfaceNotFound;
}

fn findInterface(self: DBusProperties, destination: ?[]const u8, interface_name: []const u8, path: []const u8) ?std.meta.Tuple(&.{DBusInterface, ?*DBusName.Mutex}) {
    if (destination) |dest| {
        const name = self.conn.names.map.get(dest);
        if (name) |nam| {
            nam.objects.mutex.lock();

            const interfaces = nam.objects.map.get(path);
            if (interfaces) |ifaces| {
                for (ifaces.items) |iface| {
                    if (!std.mem.eql(u8, iface.interface, interface_name)) continue;
                    return .{iface, &nam.objects.mutex};
                }
            }

            nam.objects.mutex.unlock();
        }
    }

    const interfaces = self.conn.global_objects.map.get(path);
    if (interfaces) |ifaces| {
        for (ifaces.items) |iface| {
            if (!std.mem.eql(u8, iface.interface, interface_name)) continue;
            return .{iface, null};
        }
    }

    return null;
}

const StubVariantMap = DBusDictionary.from(String, union(enum){});
pub fn @"signal@PropertiesChanged"(_: String, _: StubVariantMap, _: []const String) void {}

pub fn getProperty(self: DBusProperties, comptime T: type, path: []const u8, destination: []const u8, interface_name: []const u8, property_name: []const u8, allocator: std.mem.Allocator) !T {
    const ReplyVariant = union(enum) { v: T };

    var future = try self.conn.call(.{
        .destination = destination,
        .path = path,
        .interface = "org.freedesktop.DBus.Properties",
        .member = "Get"
    }, .{String{.value = interface_name}, String{.value = property_name}}, allocator) orelse unreachable;
    defer future.deinit();

    const reply = try future.wait(.{}) orelse unreachable;
    return (try DBusCommon.toErrorUnion(reply, self.conn.allocator, ReplyVariant)).v;
}

pub fn setProperty(self: DBusProperties, path: []const u8, destination: []const u8, interface_name: []const u8, property_name: []const u8, value: anytype) !void {
    const CallVariant = union(enum) { v: @TypeOf(value) };

    var future = try self.conn.call(.{
        .destination = destination,
        .path = path,
        .interface = "org.freedesktop.DBus.Properties",
        .method = "Set"
    }, .{String{.value = interface_name}, String{.value = property_name}, CallVariant{ .v = value }}, self.conn.allocator) orelse unreachable;
    defer future.deinit();

    const reply = try future.wait(.{}) orelse unreachable;
    return DBusCommon.toErrorUnion(reply, self.conn.allocator, void);
}

pub fn getAllProperties(self: DBusProperties, comptime T: type, path: []const u8, destination: []const u8, interface_name: []const u8, allocator: std.mem.Allocator) !DBusDictionary.from(String, T) {
    var future = try self.conn.call(.{
        .destination = destination,
        .path = path,
        .interface = "org.freedesktop.DBus.Properties",
        .method = "GetAll"
    }, .{String{.value = interface_name}}, allocator) orelse unreachable;
    defer future.deinit();

    const reply = try future.wait(.{}) orelse unreachable;
    return DBusCommon.toErrorUnion(reply, self.conn.allocator, DBusDictionary.from(String, T));

}
