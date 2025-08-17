const std = @import("std");

const dbuz = @import("../dbuz.zig");

const DBusMessage = dbuz.types.DBusMessage;
const DBusConnection = dbuz.types.DBusConnection;
const DBusPendingResponse = dbuz.types.DBusPendingResponse;
const DBusName = dbuz.types.DBusName;
const DBusDictionary = dbuz.types.DBusDictionary;

const DBusProperties = dbuz.interfaces.DBusProperties;

const String = dbuz.types.DBusString;

const DBusProxy = @This();

pub const Destination = "org.freedesktop.DBus";
pub const Interface = Destination;
pub const Path = "/org/freedesktop/DBus";

pub const Error = error {
    Failed, // Generic

    NoMemory,
    ServiceUnknown,
    NoReply,
    LimitsExceeded,
    AccessDenied,
    InvalidArgs,
    Timeout,

} || DBusMessage.SerializationError || DBusMessage.DeserializationError;

conn: *DBusConnection,

pub fn init(connection: *DBusConnection) DBusProxy {
    return .{
        .conn = connection,
    };
}

pub fn Hello(self: DBusProxy) !void {
    var future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "Hello",
        },
        .{},
        self.conn.allocator
    ) orelse unreachable;
    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    const unique_name = try toErrorUnion(reply, self.conn.allocator, String);
    self.conn.unique_name = unique_name.value;
}

// RequestName
pub const RequestNameFlags = packed struct {
    allow_replacement: bool = false,
    replace_existing:  bool = false,
    do_not_queue:      bool = true,
    _: u29 = 0,
};

/// Requests a name on the bus.
///
/// NOTE: Names created by this method are not automatically added to the connection
pub fn RequestName(self: DBusProxy, name: []const u8, flags: RequestNameFlags) !void {
    const _flags: u32 = @bitCast(flags);
    const _name: String = .{ .value = name };

    const future = try self.conn.call(.{
        .destination = Destination,
        .path = Path,
        .interface = Interface,
        .member = "RequestName",
    }, .{ _name, _flags }, self.conn.allocator) orelse unreachable;
    defer future.deinit();

    const reply = try future.wait(.{}) orelse return Error.Timeout;

    const status = try toErrorUnion(reply, self.conn.allocator, u32);
    return switch (status) {
        1 => {},
        2 => DBusName.Error.Queued,
        3 => DBusName.Error.AlreadyExists,
        4 => DBusName.Error.AlreadyOwned,
        else => DBusName.Error.UnexpectedError,
    };
}

/// Asks the bus to release the name. You can call this method if you care about the result.
pub fn ReleaseName(self: DBusProxy, name: []const u8) !void {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "ReleaseName",
        },
        .{String{.value = name}}, self.conn.allocator
    ) orelse unreachable;
    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    const status = try toErrorUnion(reply, self.conn.allocator, u32);
    return switch (status) {
        1 => {},
        2 => DBusName.Error.NoSuchName,
        3 => DBusName.Error.NotOwner,
        else => DBusName.Error.UnexpectedError,
    };
}

pub fn ListQueuedOwners(self: DBusProxy, name: []const u8) ![]const String {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "ListQueuedOwners"
        }, .{String{.value = name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, []String);
}

pub fn ListNames(self: DBusProxy) ![]const String {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "ListNames"
        }, .{}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, []String);
}

pub fn ListActivatableNames(self: DBusProxy) ![]const String {

    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "ListActivatableNames"
        }, .{}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, []String);
}

pub fn NameHasOwner(self: DBusProxy, name: []const u8) !bool {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "NameHasOwner"
        }, .{String{.value = name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, bool);
}

pub fn StartServiceByName(self: DBusProxy, name: []const u8, flags: u32) !void {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "StartServiceByName"
        }, .{String{.value = name}, flags}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return error.Timeout;

    if (reply.message_type == .ERROR) return error.DBusError;

    const status = try reply.read(u32, self.conn.allocator);
    return switch (status) {
        1 => {},
        2 => error.ServiceAlreadyRunning,
        else => error.UnexpectedError
    };
}

pub fn UpdateActivationEnvironment(self: DBusProxy, environment: DBusDictionary.from(String, String)) !void {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "UpdateActivationEnvironment"
        }, .{environment}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, void);
}

pub fn GetNameOwner(self: DBusProxy, name: []const u8) !String {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "GetNameOwner"
        }, .{String{.value = name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, String);
}

pub fn GetConnectionUnixUser(self: DBusProxy, bus_name: []const u8) !u32 {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "GetConnectionUnixUser"
        }, .{String{.value = bus_name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, u32);
}

pub fn GetConnectionUnixProcessID(self: DBusProxy, bus_name: []const u8) !u32 {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "GetConnectionUnixProcessID"
        }, .{String{.value = bus_name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, u32);
}

const ConnectionCredentialsValueTypes = union(enum) {
    uint32: u32,
    fd: std.fs.File,
    array_uint32: []u32,
    string: String,
    bytearray: []u8,
};

const ConnectionCredentialsVardict = DBusDictionary.from(String, ConnectionCredentialsValueTypes);

pub const ConnectionCredentials = struct {
    unix_user_id: ?u32 = null,
    unix_group_ids: ?[]const u32 = null,
    process_fd: ?std.fs.File = null,
    process_id: ?u32 = null,
    windows_sid: ?String = null,
    linux_security_label: ?[]const u8 = null,

    _source: ConnectionCredentialsVardict,

    pub fn init(source: ConnectionCredentialsVardict) ConnectionCredentials {
        var self: ConnectionCredentials = .{
            ._source = source
        };

        var it = self._source.iterator();
        while (it.next()) |pair| {
            const key = pair.key_ptr.value;
            if (std.mem.eql(u8, "UnixUserID", key)) {
                self.unix_user_id = pair.value_ptr.uint32;
            } else if (std.mem.eql(u8, "UnixGroupIDs", key)) {
                self.unix_group_ids = pair.value_ptr.array_uint32;
            } else if (std.mem.eql(u8, "ProcessID", key)) {
                self.process_id = pair.value_ptr.uint32;
            } else if (std.mem.eql(u8, "ProcessFD", key)) {
                self.process_fd = pair.value_ptr.fd;
            } else if (std.mem.eql(u8, "WindowsSID", key)) {
                self.windows_sid = pair.value_ptr.string;
            } else if (std.mem.eql(u8, "LinuxSecurityLabel", key)) {
                self.linux_security_label = pair.value_ptr.bytearray;
            }
        }

        return self;
    }

    pub fn deinit(self: *ConnectionCredentials) void {
        var it = self._source.iterator();
        while (it.next()) |pair| {
            switch (pair.value_ptr.*) {
                .fd => |fd| {
                    fd.close();
                },
                .string => |str| {
                    str.deinit(self._source.allocator);
                },
                .bytearray => |slice| {
                    self._source.allocator.free(slice);
                },
                .array_uint32 => |slice| {
                    self._source.allocator.free(slice);
                },
                else => {}
            }
        }
        self._source.deinit();
    }
};

pub fn GetConnectionCredentials(self: DBusProxy, bus_name: []const u8) !ConnectionCredentials {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "GetConnectionCredentials"
        }, .{String{.value = bus_name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return error.Timeout;

    if (reply.message_type == .ERROR) return error.DBusError;

    const vardict = try toErrorUnion(reply, self.conn.allocator, ConnectionCredentialsVardict);
    return ConnectionCredentials.init(vardict);
}

pub fn GetAdtAuditSessionData(self: DBusProxy, bus_name: []const u8) ![]const u8 {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "GetAdtAuditSessionData"
        }, .{String{.value = bus_name}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, []const u8);
}

pub fn AddMatch(self: DBusProxy, rule: []const u8) !void {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "AddMatch"
        }, .{String{.value = rule}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, void);
}

pub fn RemoveMatch(self: DBusProxy, rule: []const u8) !void {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "RemoveMatch"
        }, .{String{.value = rule}}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, void);
}

pub fn GetId(self: DBusProxy) !String {
    const future = try self.conn.call(
        .{
            .destination = Destination,
            .path = Path,
            .interface = Interface,
            .member = "GetId"
        }, .{}, self.conn.allocator
    ) orelse unreachable;

    defer future.deinit();
    const reply = try future.wait(.{}) orelse return Error.Timeout;

    return toErrorUnion(reply, self.conn.allocator, String);
}

pub const Listeners = struct {
    conn: *DBusConnection,
    allocator: std.mem.Allocator,

    pub fn init(userdata: *anyopaque, allocator: std.mem.Allocator) Listeners {
        const conn: *DBusConnection = @alignCast(@ptrCast(userdata));
        return .{
            .conn = conn,
            .allocator = allocator,
        };
    }

    pub fn NameLost(self: *Listeners, name: String) !void {
        self.conn.nameLost(name.value);
    }

    pub fn NameAcquired(self: *Listeners, name: String) !void {
        self.conn.nameAcquired(name.value);
    }
};

pub fn getFeatures(self: DBusProxy, allocator: std.mem.Allocator) ![]const String {
    const props = try DBusProperties.init(self.conn, allocator);
    return try props.getProperty([]String, Path, Destination, Interface, "Features", allocator);
}

pub fn getInterfaces(self: DBusProxy, allocator: std.mem.Allocator) ![]const String {
    const props = try DBusProperties.init(self.conn, allocator);
    return try props.getProperty([]String, Path, Destination, Interface, "Interfaces", allocator);
}

pub fn toErrorUnion(message: *DBusMessage, allocator: std.mem.Allocator, comptime T: type) Error!T {
    switch (message.message_type) {
        .METHOD_RETURN => {
            return message.read(T, allocator);
        },
        .ERROR => {
            if (message.error_name) |error_name| {
                if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.NoMemory")) {
                    return Error.NoMemory;
                } else if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.UnknownService")) {
                    return Error.ServiceUnknown;
                } else if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.NoReply")) {
                    return Error.NoReply;
                } else if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.Timeout")) {
                    return Error.Timeout;
                } else if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.InvalidArgs")) {
                    return Error.InvalidArgs;
                } else if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.LimitsExceeded")) {
                    return Error.LimitsExceeded;
                } else if (std.mem.eql(u8, error_name, "org.freedesktop.DBus.Error.AccessDenied")) {
                    return Error.AccessDenied;
                }
            }
            return Error.Failed;
        },
        else => unreachable
    }
}
