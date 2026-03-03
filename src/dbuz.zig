pub const types = struct {
    pub const String = @import("types/dbus_types.zig").String;
    pub const ObjectPath = @import("types/dbus_types.zig").ObjectPath;
    pub const Signature = @import("types/dbus_types.zig").Signature;
    pub const Message = @import("types/Message.zig");
    pub const Connection = @import("types/Connection.zig");
    pub const Promise = @import("types/promise.zig").Promise;
    pub const PromiseOpaque = @import("types/promise.zig").PromiseOpaque;
    pub const PromiseError = @import("types/promise.zig").ErrorData;
    pub const Interface = @import("types/Interface.zig");
    pub const Proxy = @import("types/Proxy.zig");

    pub const Method = @import("types/dbus_types.zig").Method;
    pub const Property = @import("types/dbus_types.zig").Property;
    pub const PropertyStorage = @import("types/dbus_types.zig").PropertiesStorage;
    pub const Signal = @import("types/dbus_types.zig").Signal;
    pub const SignalManager = @import("types/dbus_types.zig").SignalManager;

    pub const MatchRule = @import("types/MatchRule.zig");

    pub const Dict = @import("types/dict.zig").from;
    pub const Variant = @import("types/dbus_types.zig").Variant;
};

pub const proxies = struct {
    pub const DBus = @import("proxies/DBus.zig");
    pub const Properties = @import("proxies/properties.zig").Properties;
};

pub const utils = struct {
    pub const dupeValue = @import("types/dbus_types.zig").dupeValue;
    pub const deinitValue = @import("types/dbus_types.zig").deinitValueRecursive;
};

pub const codec = @import("codec.zig");
pub const auth = @import("sasl.zig");
pub const transport = @import("transport.zig");

const std = @import("std");
const Thread = std.Thread;

const logger = std.log.scoped(.dbuz);

/// Spawns looper thread that automatically handles incoming messages. Not recommended for production purposes.
/// If you want dispatch message, implement your own looper based on Connection.exportFileDescriptor, Connection.advance and Connection.handleMessage.
pub fn spawnLooperThread(gpa: std.mem.Allocator, c: *types.Connection, exit_condition: *bool) !Thread {
    return Thread.spawn(.{ .allocator = gpa, }, looper, .{gpa, c, exit_condition});
}

fn looper(gpa: std.mem.Allocator, c: *types.Connection, exit_condition: *bool) void {
    logger.debug("Looper started", .{});
    while (!exit_condition.*) {
        const m_a = c.advance(gpa) catch |err| return logger.err("Looper: unable to advance connection: {s}", .{@errorName(err)});
        if (m_a) |ma| {
            c.handleMessage(ma) catch |err| return logger.err("Looper: unable to handle message: {s}", .{@errorName(err)});
        }
    }
    logger.debug("Looper ended", .{});
}


pub const Bus = struct {
    allow_fds: bool,
    sockaddr: std.net.Address,

    pub fn parse(gpa: std.mem.Allocator, address: []const u8) !Bus {
        var ad_it = std.mem.splitScalar(u8, address, ':');
        const protocol, const description = .{ ad_it.next() orelse unreachable, ad_it.next() orelse return error.MissingTransport };

        if (std.mem.eql(u8, protocol, "unix")) {
            const addr = try parseUnixAddress(gpa, description);
            defer gpa.free(addr);
            return .{
                .allow_fds = true,
                .sockaddr = try .initUnix(addr)
            };
        } else return error.UnsupportedTransport;
    }
};

/// Bus socket location.
pub const BusType = union(enum) {
    /// Extracted from $DBUS_SESSION_BUS_ADDRESS
    Session: void,
    /// Equals to unix:path=/var/run/dbus/system_bus_socket
    System: void,
    /// Must be in format described on https://dbus.freedesktop.org/doc/dbus-specification.html#addresses
    Custom: []const u8,
};

fn parseUnixAddress(gpa: std.mem.Allocator, address: []const u8) ![]const u8 {
    var address_it = std.mem.splitScalar(u8, address, ',');
    var path: ?[]const u8 = null;
    var directory: ?[]const u8 = null; 
    var abstract: ?[]const u8 = null;
    var runtime: ?bool = null;

    while (true) {
        const arg = address_it.next() orelse break;
        if (arg.len == 0) break;

        var arg_splitter = std.mem.splitScalar(u8, arg, '=');
        
        const key = arg_splitter.next() orelse return error.InvalidAddress;
        const value = arg_splitter.next() orelse return error.InvalidAddress;

        if (std.mem.eql(u8, key, "path")) if (path != null) return error.InvalidAddress else { path = value; }
        else if (std.mem.eql(u8, key, "dir") or std.mem.eql(u8, key, "tmpdir")) if (directory != null) return error.InvalidAddress else { directory = value; }
        else if (std.mem.eql(u8, key, "abstract")) if (abstract != null) return error.InvalidAddress else { abstract = value; }
        else if (std.mem.eql(u8, key, "runtime")) if (runtime != null) return error.InvalidAddress else { runtime = std.mem.eql(u8, value, "yes"); };
    }
    if (path == null and directory == null and abstract == null and runtime == null) return error.InvalidAddress;
    if (runtime != null) return error.RuntimeAddressUsupported;
    var set_addrs: u8 = 0;
    if (path != null) set_addrs += 1;
    if (directory != null) set_addrs += 1;
    if (abstract != null) set_addrs += 1;

    if (set_addrs > 1) return error.InvalidAddress;

    if (path) |p| return try gpa.dupe(u8, p);
    if (directory) |d| {
        var dir = std.fs.openDirAbsolute(d, .{
            .iterate = true,
            .access_sub_paths = true,
        }) catch |err| {
            if (err == error.AccessDenied) return err
            else return error.BusNotFound;
        };
        defer dir.close();
        var dir_it = dir.iterate();
        while (dir_it.next() catch return error.BusNotFound) |dentry| {
            if (dentry.kind != .unix_domain_socket) continue;
            if (std.mem.startsWith(u8, dentry.name, "dbus-")) return try std.fmt.allocPrint(gpa, "{s}/{s}", .{d, dentry.name});
        }
        return error.BusNotFound;
    }
    if (abstract) |a| return try std.fmt.allocPrint(gpa, "\x00{s}", .{a});
    return error.BusNotFound;
}

/// Connects to DBus using specified address. Uses passed gpa for all allocations.
/// Returns authenticated Connection pointer. Caller owns the memory and must call Connection.deinit() when connection is no longer needed.
pub fn connect(gpa: std.mem.Allocator, bus: BusType) !*types.Connection {
    var env = try std.process.getEnvMap(gpa);
    defer env.deinit();
    const address: []const u8 = switch (bus) {
        .Custom => |c| c,
        .System => "unix:path=/var/run/dbus/system_bus_socket",
        .Session => blk: {
            const session_bus_address = env.get("DBUS_SESSION_BUS_ADDRESS");
            if (session_bus_address) |a| break :blk a;
            return error.BusNotFound;
        }
    };

    var addr_it = std.mem.splitScalar(u8, address, ';');
    while (addr_it.next()) |addr| {
        logger.debug("Trying to connect to DBus by address: \"{s}\"", .{addr});
        const bus_addr = try Bus.parse(gpa, addr);
        const stream = switch (bus_addr.sockaddr.any.family) {
            std.posix.AF.UNIX => blk: {
                logger.debug("Connecting through unix socket...", .{});
                const sockfd = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
                errdefer std.posix.close(sockfd);
                std.posix.connect(sockfd, &bus_addr.sockaddr.any, bus_addr.sockaddr.getOsSockLen()) catch |err| {
                    logger.debug("Unable to connect to address \"{s}\": {s}", .{addr, @errorName(err)});
                    continue;
                };
                logger.debug("Connected to DBus using address \"{s}\"", .{addr});
                break :blk std.net.Stream{ .handle = sockfd };
            },
            else => continue,
        };
        errdefer stream.close();
        auth.AuthClient.auth(gpa, stream) catch {
            stream.close();
            continue;
        };
        return types.Connection.init(gpa, stream.handle);
    }
    return error.BusNotFound;
}
