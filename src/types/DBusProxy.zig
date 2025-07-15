const std = @import("std");
const dbus_types = @import("dbus_types.zig");

const DBusConnection = @import("DBusConnection.zig");
const DBusPendingResponse = @import("DBusPendingResponse.zig");

const DBusProxy = @This();

pub const Options = struct {
    destination: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    object_path: ?[]const u8 = null,
    sender: ?[]const u8 = null,

    check_presence: bool = true,
};

connection: *DBusConnection,
allocator: std.mem.Allocator,

destination: []const u8,
interface: ?[]const u8,
object_path: ?[]const u8,
sender: ?[]const u8,

pub fn init(conn: *DBusConnection, allocator: std.mem.Allocator, options: Options) DBusProxy {
    return .{
        .connection = conn,
        .allocator = allocator,
        .destination = options.destination.?,
        .interface = options.interface,
        .object_path = options.object_path,
        .sender = options.sender,
    };
}

pub fn at(self: DBusProxy, path: []const u8) DBusProxy {
    return DBusProxy.init(self.connection, self.allocator, .{
        .destination = self.destination,
        .interface = self.interface,
        .object_path = path,
        .check_presence = false,
    });
}

pub fn to(self: DBusProxy, name: []const u8) DBusProxy {
    return DBusProxy.init(self.connection, self.allocator, .{
        .destination = self.destination,
        .interface = name,
        .object_path = self.object_path,
        .check_presence = false,
    });
}

pub fn as(self: DBusProxy, name: []const u8) DBusProxy {
    return DBusProxy.init(self.connection, self.allocator, .{
        .destination = self.destination,
        .interface = self.interface,
        .object_path = self.object_path,
        .sender = name,
        .check_presence = false,
    });
}

const SimplifiedCallOptions = struct {
    flags: DBusConnection.MethodCallParams.Flags = .{},
    feedback: DBusPendingResponse.Feedback = .{ .store = null },
};

pub fn call(self: DBusProxy, member: []const u8, values: anytype, options: SimplifiedCallOptions) !?*DBusPendingResponse {
    if (self.object_path == null) @panic("Object path is null");
    if (self.interface == null) @panic("Interface is null");

    return try self.connection.call(.{
        .destination = self.destination,
        .interface = self.interface.?,
        .path = self.object_path.?,
        .method = member,
        .sender = self.sender,
        .flags = options.flags,
        .feedback = options.feedback,
    }, values, self.allocator);
}

/// Checks if name is on the bus
pub fn check(self: DBusProxy) !void {
    try self.connection.dbus().nameHasOwner(self.destination) orelse return error.NoSuchName;
}
