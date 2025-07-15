
const BusType = union(enum) {
    Session: void,
    System: void,
    Path: []const u8,
    UnixFD: i32
};

const Options = struct {
    bus: BusType = .Session,
    enable_introspection: bool = true,
    config: types.DBusConnection.Options = .{}
};

pub const ConnectionCreationError = error{
    BusNotAvailable,
    ConnectionRefused,
    ConnectionLost,
    TransportNotSupported,
    Timeout,
} || std.mem.Allocator.Error;

const logger = std.log.scoped(.dbuz);

fn getFDByBusType(bus: BusType, allocator: std.mem.Allocator) !i32 {
    const stream = blk: switch (bus) {
        .Session => {
            var env = std.process.getEnvMap(allocator) catch return error.OutOfMemory;
            defer env.deinit();

            const addresses = env.get("DBUS_SESSION_BUS_ADDRESS") orelse {
                return error.BusNotAvailable;
            };

            var address_it = std.mem.splitScalar(u8, addresses, ';');
            while (address_it.next()) |address| {
                var it = std.mem.splitScalar(u8, address, ':');
                const transport = it.next() orelse continue;
                var param_it = std.mem.splitScalar(u8, (it.next() orelse continue), '=');

                const key = param_it.next() orelse continue;
                const value = param_it.next() orelse continue;

                if (std.mem.eql(u8, transport, "unix")) {
                    const path = if (std.mem.eql(u8, key, "path")) try std.fmt.allocPrint(allocator, "{s}", .{value}) else if (std.mem.eql(u8, key, "abstract")) try std.fmt.allocPrint(allocator, "\x00{s}", .{value}) else continue;
                    defer allocator.free(path);
                    const stream = std.net.connectUnixSocket(path) catch return error.ConnectionRefused;
                    break :blk stream;
                } else {
                    return error.TransportNotSupported;
                }
            }

            return error.BusNotAvailable;
        },
        .System => {
            break :blk std.net.connectUnixSocket("/run/dbus/system_bus_socket") catch return error.ConnectionRefused;
        },
        .Path => |path| {
            break :blk std.net.connectUnixSocket(path) catch return error.ConnectionRefused;
        },
        .UnixFD => |fd| {
            break :blk std.net.Stream{.handle = fd};
        }
    };
    return stream.handle;
}

pub fn connect(allocator: std.mem.Allocator, options: Options) ConnectionCreationError!*types.DBusConnection {
    const fd = try getFDByBusType(options.bus, allocator);
    errdefer std.posix.close(fd);

    var connection = try types.DBusConnection.init(allocator, fd, options.config);
    errdefer connection.deinit();

    connection.connect() catch return error.ConnectionLost;
    const reply = connection.call(.{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
        .feedback = .{
            .call = .{
                .userdata = connection,
                .method_reply = helloReply,
                .method_error = helloError,
            }
        }
    }, .{}, allocator) catch return error.ConnectionLost;
    defer reply.?.deinit();

    if (options.enable_introspection) {
        connection.introspectable_ctx = .{
            .allocator = connection.allocator,
            .connection = connection,
            .introspection_cache = .init(connection.allocator)
        };
        _ = connection.registerInterface(interfaces.DBusIntrospectable, "org.freedesktop.DBus.Introspectable", "*", true, &connection.introspectable_ctx) catch return error.OutOfMemory;
    }
    _ = connection.registerInterface(interfaces.DBusProperties, "org.freedesktop.DBus.Properties", "*", true, connection) catch return error.OutOfMemory;
    _ = connection.registerInterface(interfaces.DBusPeer, "org.freedesktop.DBus.Peer", "*", true, connection) catch return error.OutOfMemory;

    _ = connection.addMatchGroup(interfaces.DBusCommon.Listeners, .{
        .interface = "org.freedesktop.DBus",
        .silent = true,
    }, connection) catch return error.OutOfMemory;

    return connection;
}

pub fn spawnPollingThread(conn: *types.DBusConnection, allocator: std.mem.Allocator) !struct{*bool, std.Thread} {
    const running = try allocator.create(bool);
    running.* = true;

    errdefer allocator.destroy(running);

    const thread = try std.Thread.spawn(.{}, poller, .{conn, running});
    thread.setName("DBuzConnectionPoller") catch {};
    return .{running, thread};
}

fn poller(conn: *types.DBusConnection, running: *bool) !void {
    logger.debug("Dispatcher thread started with thread id {d}", .{std.Thread.getCurrentId()});

    var poll_fds = [_]std.posix.pollfd{
        .{
            .fd = conn.getFd(),
            .events = std.posix.POLL.IN | std.posix.POLL.HUP,
            .revents = 0,
        }
    };

    while (running.*) {
        const evcount = std.posix.poll(&poll_fds, 100) catch continue;
        if (evcount == 0) continue;
        if (poll_fds[0].revents & std.posix.POLL.HUP != 0) {
            conn.update(false) catch {};
            return;
        }
        else if (poll_fds[0].revents & std.posix.POLL.IN != 0) {
            conn.update(false) catch |err| {
                if (err == error.WouldBlock) continue;
                if (err == error.ConnectionLost) {
                    while (running.*) {}
                    return;
                }
            };
        }
    }
}

pub const types = struct {
    pub const DBusConnection = @import("types/DBusConnection.zig");
    pub const DBusMessage = @import("types/DBusMessage.zig");
    pub const DBusPendingResponse = @import("types/DBusPendingResponse.zig");
    pub const DBusInterface = @import("types/Interface.zig");
    pub const DBusName = @import("types/DBusName.zig");
    pub const DBusDictionary = @import("types/dict.zig");

    pub const DBusString = @import("types/dbus_types.zig").String;
    pub const DBusObjectPath = @import("types/dbus_types.zig").ObjectPath;
    pub const DBusSignature = @import("types/dbus_types.zig").Signature;

    pub const DBusProxy = @import("types/DBusProxy.zig");
    pub const DBusMatchGroup = @import("types/MatchGroup.zig");
};

pub const interfaces = struct {
    pub const DBusIntrospectable = @import("interfaces/DBusIntrospectable.zig");
    pub const DBusProperties = @import("interfaces/DBusProperties.zig");
    pub const DBusPeer = @import("interfaces/DBusPeer.zig");
    pub const DBusCommon = @import("interfaces/DBus.zig");
};

pub const errors = struct {
    pub const DBusError = types.DBusConnection.Error;
    pub const DBusLogicError = types.DBusConnection.LogicError;
};

const std = @import("std");

// Helpers

fn helloReply(erased_conn: *anyopaque, msg: *types.DBusMessage) anyerror!void {
    const conn = @as(*types.DBusConnection, @alignCast(@ptrCast(erased_conn)));
    const unique_name = try msg.read(types.DBusString, conn.allocator);
    conn.unique_name = unique_name.value;
}

fn helloError(erased_conn: *anyopaque, _: *types.DBusMessage) anyerror!void {
    const conn = @as(*types.DBusConnection, @alignCast(@ptrCast(erased_conn)));
    conn.state = .Errored;
}

pub inline fn isObjectPathValid(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] != '/') return false;
    if (path.len == 1) return true;

    var prev_is_slash: bool = true;

    for (path[1..]) |c| {
        if (c == '/' and prev_is_slash) return false;
        prev_is_slash = c == '/';
        switch (c) {
            'A'...'Z', 'a'...'z', '0'...'9', '/', '_' => {},
            else => return false
        }
    }

    return true;
}

pub inline fn isNameValid(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name.len > 255) return false;
    if (std.mem.count(u8, name, ".") < 2) return false;

    var start_of_section: bool = true;

    for (name) |c| {
        if (c == '.' and start_of_section) return false;
        start_of_section = c == '.';
        switch (c) {
            'A'...'Z', 'a'...'z', '.', '_' => {},
            '0'...'9' => {
                if (start_of_section) return false;
            },
            else => return false
        }
    }

    return true;
}
