const std = @import("std");
const dbus_types = @import("../types/dbus_types.zig");

const String = dbus_types.String;

const DBusPeer = @This();

const DBusConnection = @import("../types/DBusConnection.zig");
const DBusMessage = @import("../types/DBusMessage.zig");

conn: *DBusConnection,


pub fn init(userdata: *anyopaque, _: std.mem.Allocator) anyerror!DBusPeer {
    const conn: *DBusConnection = @alignCast(@ptrCast(userdata));
    return DBusPeer {
        .conn = conn,
    };
}

pub fn @"method@Ping"(_: *DBusPeer) anyerror!void {}
// pub fn @"method@GetMachineId"(self: *DBusPeer) anyerror!String { return self.machine_id; } // Do i really need to implement that?
