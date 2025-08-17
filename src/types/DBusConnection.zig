const std = @import("std");
const dbuz = @import("../dbuz.zig");

const Transport = @import("Transport.zig");
const DBusMessage = @import("DBusMessage.zig");
const DBusPendingResponse = @import("DBusPendingResponse.zig");
const DBusName = @import("DBusName.zig");
const DBusProxy = @import("DBusProxy.zig");
const Interface = @import("Interface.zig");
const MatchGroup = @import("MatchGroup.zig");
const OutOfBandData = Transport.OutOfBandData;
const Cmsg = @import("../cmsg.zig");

const DBusIntrospectable = @import("../interfaces/DBusIntrospectable.zig");

const HashMap = std.AutoHashMap;
const Mutex = std.Thread.Mutex.Recursive;

const String = @import("dbus_types.zig").String;
const Signature = @import("dbus_types.zig").Signature;
const ObjectPath = @import("dbus_types.zig").ObjectPath;

const DBusCommon = @import("../interfaces/DBus.zig");

const logger = std.log.scoped(.DBusConnection);

const AllocatorError = std.mem.Allocator.Error;

const ConnectionStatus = enum(u8) {
    Unconnected, // We start here

    Connecting, // Until connection is accept()ed by remote peer,
    Auth, // Authentification sequence, negotiates unix fds if enabled,
    UnixFdsNegotiate,
    Connected,
    Errored,
    Disconnected,
    Rejected,
};

pub const Error = error{
    InvalidObjectPath,
    InvalidInterfaceName,
    InvalidServiceName,
    BadMessage,
    Timeout,
} || DBusMessage.SerializationError || DBusMessage.DeserializationError || Transport.Error;

pub const DBusConnection = @This();

// Unhandled messages collection strategy
const FallbackMessageHandling = union(enum) {
    ignore: void, // Frees message automatically
    fallback_handler: *fn (*DBusConnection, *DBusMessage, ?*anyopaque) anyerror!void
};

/// Options for creating a DBusConnection
pub const Options = struct {
    /// What to do with unhandled messages
    /// .ignore just frees message, .fallback_handler calls user-provided function, it is user's responsibility to .deinit message
    fallback_msgs_strategy: FallbackMessageHandling = .ignore,
    fallback_userdata: ?*anyopaque = null,

    /// Allow SCM_RIGHTS
    enable_unix_fds: bool = true,
};

const InterfaceMap = std.StringHashMap(std.ArrayList(Interface));

allocator: std.mem.Allocator,
transport_layer: ?Transport, // If null dbus is not connected
unique_name: ?[]const u8, // Name not known before connection is established
unix_fds_enabled: bool = false,

state: ConnectionStatus = .Unconnected,
serial_counter: std.atomic.Value(u32) = .init(1),

response_futures: HashMap(u32, *DBusPendingResponse),
response_futures_lock: Mutex = .init,

fallback_msgs_strategy: FallbackMessageHandling,
fallback_userdata: ?*anyopaque,

update_thread_id: ?std.Thread.Id = null,

global_objects: struct {
    map: InterfaceMap,
    mutex: Mutex
},

match_rules: struct {
    list: std.ArrayList(MatchGroup),
    mutex: Mutex,
},

names: struct {
    map: std.StringHashMap(*DBusName),
    mutex: Mutex
},

default_call_timeout: u64 = std.time.ns_per_s * 120,

// Internal state
buffer: std.ArrayList(u8),
fd_list: std.ArrayList(std.posix.fd_t),

introspectable_ctx: ?DBusIntrospectable.IntrospectableCtx = null,

pub fn init(allocator: std.mem.Allocator, socket: std.posix.socket_t, options: Options) AllocatorError!*DBusConnection {
    const self = try allocator.create(DBusConnection);
    self.* = .{
        .allocator = allocator,
        .transport_layer = Transport.init(socket, allocator),
        .unique_name = null,
        .state = .Connecting,
        .response_futures = .init(allocator),
        .fallback_msgs_strategy = options.fallback_msgs_strategy,
        .fallback_userdata = options.fallback_userdata,
        .unix_fds_enabled = options.enable_unix_fds,
        .match_rules = .{
            .list = .init(allocator),
            .mutex = Mutex.init,
        },
        .names = .{
            .map = .init(allocator),
            .mutex = Mutex.init,
        },
        .global_objects = .{
            .map = .init(allocator),
            .mutex = Mutex.init,
        },
        .buffer = try .initCapacity(allocator, std.heap.pageSize()),
        .fd_list = .init(allocator),
    };
    return self;
}

pub fn connect(self: *DBusConnection) !void {
    logger.debug("Authentication started", .{});
    try self.auth(self.unix_fds_enabled);
}

pub fn addMatchGroup(self: *DBusConnection, comptime MatchHandler: type, rule: MatchGroup.Rule, userdata: *anyopaque) !?MatchGroup {

    var mgroup: ?MatchGroup = null;
    if (MatchHandler != void) {
        self.match_rules.mutex.lock();
        defer self.match_rules.mutex.unlock();

        mgroup = try MatchGroup.init(MatchHandler, userdata, self.allocator, rule);
        try self.match_rules.list.append(mgroup.?);
    }
    if (self.state != .Connected) return null;

    var rulestr = std.ArrayList(u8).init(self.allocator);
    defer rulestr.deinit();
    try rulestr.appendSlice("type='signal'");
    if (rule.destination) |dest| {
        const part = try std.fmt.allocPrint(self.allocator, ",destination={s}", .{dest});
        defer self.allocator.free(part);
        try rulestr.appendSlice(part);
    }
    if (rule.interface) |iface| {
        const part = try std.fmt.allocPrint(self.allocator, ",interface={s}", .{iface});
        defer self.allocator.free(part);
        try rulestr.appendSlice(part);
    }
    if (rule.sender) |sender| {
        const part = try std.fmt.allocPrint(self.allocator, ",sender={s}", .{sender});
        defer self.allocator.free(part);
        try rulestr.appendSlice(part);
    }
    if (rule.path) |path| {
        const part = try std.fmt.allocPrint(self.allocator, ",path={s}", .{path});
        defer self.allocator.free(part);
        try rulestr.appendSlice(part);
    }
    if (rule.path_namespace) |path_namespace| {
        const part = try std.fmt.allocPrint(self.allocator, ",path_namespace={s}", .{path_namespace});
        defer self.allocator.free(part);
        try rulestr.appendSlice(part);
    }
    if (rule.member) |member| {
        const part = try std.fmt.allocPrint(self.allocator, ",member={s}", .{member});
        defer self.allocator.free(part);
        try rulestr.appendSlice(part);
    }

    const rule_string = String{.value = try rulestr.toOwnedSlice(), .ownership = true};
    defer rule_string.deinit(self.allocator);

    if (!rule.silent) try self.dbus().AddMatch(rule_string.value);

    return mgroup;
}

pub fn publishDefaultInterface(self: *DBusConnection, comptime T: type, name: []const u8, path: []const u8, userdata: *anyopaque) !Interface {

    if (!isObjectPathValid(path)) return Error.InvalidObjectPath;
    if (!isNameValid(name)) return Error.InvalidInterfaceName;

    self.objects.mutex.lock();
    defer self.objects.mutex.unlock();
    const iface = try Interface.init(T, userdata, self.allocator, path, name);
    const ilist = self.objects.global.getPtr(path);
    if (ilist) |list| {
        try list.append(iface);
    } else {
        var new_ilist = std.ArrayList(Interface).init(self.allocator);
        try new_ilist.append(iface);
        try self.objects.global.put(path, new_ilist);
    }
    return iface;
}

pub fn registerInterface(self: *DBusConnection, comptime T: type, name: []const u8, path: []const u8, hide: bool, userdata: *anyopaque) !Interface {
    if (!isObjectPathValid(path) and !std.mem.eql(u8, path, "*")) return DBusConnection.Error.InvalidObjectPath;
    if (!isNameValid(name)) return DBusConnection.Error.InvalidServiceName;

    defer if (self.introspectable_ctx) |*introspectable| introspectable.reset();

    const interface = try Interface.init(T, userdata, self.allocator, path, name, self, null, hide);
    errdefer interface.destroy();

    self.global_objects.mutex.lock();
    defer self.global_objects.mutex.unlock();

    const interface_list: *std.ArrayList(Interface) = self.global_objects.map.getPtr(path) orelse blk: {
        const list = std.ArrayList(Interface).init(self.allocator);
        try self.global_objects.map.put(path, list);
        break :blk self.global_objects.map.getPtr(path) orelse unreachable;
    };

    for (interface_list.items) |iface| {
        if (std.mem.eql(u8, iface.interface, name)) return error.InterfaceNameAlreadyRegistered;
    }

    try interface_list.append(interface);

    return interface;
}

pub fn unregisterInterface(self: *DBusConnection, interface: Interface) void {
    self.global_objects.mutex.lock();
    defer self.global_objects.mutex.unlock();

    defer if (self.introspectable_ctx) |*introspectable| introspectable.reset();

    const interface_list: ?*std.ArrayList(Interface) = self.global_objects.map.getPtr(interface.path);
    if (interface_list) |list| {
        for (list.items, 0..) |iface, i| {
            if (std.mem.eql(u8, iface.interface, interface.interface)) {
                _ = list.swapRemove(i);
            }
        }
    }
}

pub fn deinit(self: *DBusConnection) void {

    if (self.transport_layer) |ts| {
        std.posix.shutdown(ts.fd, .both) catch {};
    }

    var objects_it = self.global_objects.map.iterator();
    while (objects_it.next()) |entry| {
        for (entry.value_ptr.items) |iface| {
            iface.destroy();
        }
        entry.value_ptr.deinit();
    }

    self.buffer.deinit();
    self.response_futures.deinit();
    self.global_objects.map.deinit();
    self.names.map.deinit();

    for (self.match_rules.list.items) |rule| {
        rule.deinit();
    }
    self.match_rules.list.deinit();

    if (self.introspectable_ctx) |*introspectable| introspectable.reset();

    if (self.unique_name) |name| self.allocator.free(name);

    self.allocator.destroy(self);

}

pub fn getFd(self: *DBusConnection) i32 {
    return self.transport_layer.?.fd;
}

/// Writes the authentication sequence to the transport layer.
pub fn auth(self: *DBusConnection, unix_fds: bool) Transport.Error!void {
    self.state = .Auth;

    try self.transport_layer.?.write("\x00AUTH EXTERNAL\r\nDATA\r\n", .none, true);
    if (unix_fds) {
        self.unix_fds_enabled = true;
        try self.transport_layer.?.write("NEGOTIATE_UNIX_FD\r\n", .none, true);
        logger.debug("Asking bus for unix fd support", .{});
    }
    try self.transport_layer.?.write("BEGIN\r\n", .none, true);
}

pub fn update(self: *DBusConnection, blocking: bool) Error!void {
    std.debug.assert(self.transport_layer != null);
    if (self.state == .Unconnected) return Error.ConnectionLost;

    self.update_thread_id = std.Thread.getCurrentId();
    defer self.update_thread_id = null;

    while (true) {
        const datamsg = self.transport_layer.?.read(blocking) catch |err| {
            switch (err) {
                Transport.Error.WouldBlock => break,
                else => return err,
            }
        };
        defer datamsg.deinit();
        try self.buffer.appendSlice(datamsg.data);
        if (datamsg.fds) |fds| {
            for (fds) |fd| {
                try self.fd_list.append(fd);
            }
        }
    }

    var fixed_bytes_stream = std.io.fixedBufferStream(self.buffer.items);
    const bytes_reader = fixed_bytes_stream.reader().any();

    next: while (true) {
        if (self.state != .Connected and self.state != .Errored and self.state != .Disconnected and self.state != .Rejected and self.state != .Unconnected) {
            try self.processAuth(bytes_reader);
            continue;
        }

        const message = try self.allocator.create(DBusMessage);
        errdefer self.allocator.destroy(message);

        message.* = DBusMessage.parseFromReader(self.allocator, bytes_reader, &self.fd_list) catch |err| {
            if (err != DBusMessage.DeserializationError.MessageTooShort) return err;
            if (self.buffer.items.len - fixed_bytes_stream.pos > 0) try self.buffer.replaceRange(0, self.buffer.items.len - fixed_bytes_stream.pos, self.buffer.items[fixed_bytes_stream.pos..])
            else self.buffer.clearRetainingCapacity();
            self.allocator.destroy(message);
            break;
        };
        errdefer message.deinit();

        switch (message.message_type) {
            .INVALID => {
                logger.warn("[{?s}->{?s}] INVALID_MESSAGE@{d}", .{message.sender, message.destination, message.serial});
                message.deinit();
                self.allocator.destroy(message);
            },
            .METHOD_RETURN, .ERROR => {
                if (message.reply_serial) |serial| {
                    logger.debug("[{?s}->{?s}] {s}@{d}(@{d}): ({s})", .{message.sender, message.destination, @tagName(message.message_type), message.serial, serial, if (message.signature.items.len > 0) message.signature.items else ""});
                    self.response_futures_lock.lock();
                    defer self.response_futures_lock.unlock();

                    if (self.response_futures.get(serial)) |future| {
                        try future.post(message);
                        clearPendingResponse(self, serial);
                        continue;
                    } else {
                        logger.warn("No response future found for serial {d}", .{serial});
                        message.deinit();
                        self.allocator.destroy(message);
                    }
                } else {
                    message.deinit();
                    self.allocator.destroy(message);
                }
            },
            .METHOD_CALL => {
                defer {
                    message.deinit();
                    self.allocator.destroy(message);
                }

                logger.debug("[{?s}->{?s}] METHOD_CALL@{d} {?s}@{?s}.{?s}({s})", .{message.sender, message.destination, message.serial, message.path, message.interface, message.member, if (message.signature.items.len > 0) message.signature.items else ""});

                if (message.sender == null or message.destination == null or message.path == null or message.member == null) {
                    logger.warn("Invalid sender, destination, path, member for method call", .{});
                    message.deinit();
                    self.allocator.destroy(message);
                    continue;
                }
                names_scope: {
                    self.names.mutex.lock();
                    defer self.names.mutex.unlock();


                    var it = self.names.map.iterator();
                    while (it.next()) |entry| {
                        if (std.mem.eql(u8, entry.key_ptr.*, message.destination.?)) {
                            entry.value_ptr.*.routeMethodCall(message) catch |err| {
                                if (err == error.Unhandled) break :names_scope;
                                logger.err("Error routing call: {s}", .{@errorName(err)});
                            };
                            continue :next;
                        }
                    }
                }
                {
                    self.global_objects.mutex.lock();
                    defer self.global_objects.mutex.unlock();

                    if (self.global_objects.map.get(message.path.?)) |list| global_scope: {
                        for (list.items) |interface| {
                            if (std.mem.eql(u8, interface.interface, message.interface.?)) {
                                interface.vtable.route_call(interface.ptr, self, message) catch |err| {
                                    if (err == error.Unhandled) break :global_scope;
                                    logger.err("Error routing call: {s}", .{@errorName(err)});
                                };
                                continue :next;
                            }
                        }
                    }

                    if (self.global_objects.map.get("*")) |list| wildcard_scope: {
                        for (list.items) |interface| {
                            if (std.mem.eql(u8, interface.interface, message.interface.?)) {
                                interface.vtable.route_call(interface.ptr, self, message) catch |err| {
                                    if (err == error.Unhandled) break :wildcard_scope;
                                    logger.err("Error routing call: {s}", .{@errorName(err)});
                                };
                                continue :next;
                            }
                        }
                    }
                }
                switch (self.fallback_msgs_strategy) {
                    .ignore => {},
                    .fallback_handler => |cb| {
                        cb(self, message, self.fallback_userdata) catch {};
                    }
                }
            },
            .SIGNAL => {
                defer {
                    message.deinit();
                    self.allocator.destroy(message);
                }

                logger.debug("[{?s}->{?s}] SIGNAL@{d} {?s}.{?s}({s})", .{message.sender, message.destination, message.serial, message.interface, message.member, if (message.signature.items.len > 0) message.signature.items else ""});
                if (self.match_rules.list.items.len > 0) {
                    self.match_rules.mutex.lock();
                    defer self.match_rules.mutex.unlock();
                    for (self.match_rules.list.items) |*group| {
                        if (group.rule.destination != null and message.destination != null) {
                            if (!std.mem.eql(u8, group.rule.destination.?, message.destination.?)) continue;
                        }
                        if (group.rule.interface != null and message.interface != null) {
                            if (!std.mem.eql(u8, group.rule.interface.?, message.interface.?)) continue;
                        }
                        if (group.rule.member != null and message.member != null) {
                            if (!std.mem.eql(u8, group.rule.member.?, message.member.?)) continue;
                        }
                        if (group.rule.path != null and message.path != null) {
                            if (!std.mem.eql(u8, group.rule.path.?, message.path.?)) continue;
                        }
                        if (group.rule.path_namespace != null and message.path != null) {
                            if (!std.mem.startsWith(u8, message.path.?, group.rule.path_namespace.?)) continue;
                        }
                        if (group.rule.sender != null and message.sender != null) {
                            if (!std.mem.eql(u8, group.rule.sender.?, message.sender.?)) continue;
                        }
                        group.vtable.signal(group.ptr, message) catch |err| {
                            if (err == error.NotHandled) {
                                switch (self.fallback_msgs_strategy) {
                                    .ignore, => {},
                                    .fallback_handler  => |cb| {
                                        cb(self, message, self.fallback_userdata) catch {};
                                    },
                                }
                            }
                        };
                    }
                }
            }
        }
    }
}

fn skipReaderUntil(reader: anytype, delimiter: u8) !void {
    var c: [256]u8 = undefined;
    _ = try reader.readUntilDelimiter(&c, delimiter);
}

fn processAuth(self: *DBusConnection, reader: anytype) !void {
    state: switch (self.state) {
        else => {},
        .Auth => {
            var buf: [256]u8 = undefined;
            while (readerGetPos(reader) != readerGetMax(reader)) {
                const line = reader.readUntilDelimiter(&buf, '\r') catch return Error.ConnectionLost;
                readerSetPos(reader, readerGetPos(reader) + 1);
                if (std.mem.startsWith(u8, line, "OK")) {
                    logger.debug("Bus authenticated connection successfully", .{});
                    if (self.unix_fds_enabled) {
                        self.state = .UnixFdsNegotiate;
                        continue :state .UnixFdsNegotiate;
                    } else {
                        self.state = .Connected;
                        return;
                    }
                } else if (std.mem.startsWith(u8, line, "REJECTED")) {
                    logger.debug("Bus authentication rejected", .{});
                    self.state = .Rejected;
                    return Error.ConnectionLost;
                } else if (std.mem.startsWith(u8, line, "DATA")) {
                } else {
                    return Error.ConnectionLost;
                }
            }
        },
        .UnixFdsNegotiate => {
            var buf: [256]u8 = undefined;
            while (readerGetPos(reader) != readerGetMax(reader)) {
                const line = reader.readUntilDelimiter(&buf, '\r') catch return Error.ConnectionLost;
                readerSetPos(reader, readerGetPos(reader) + 1);
                if (std.mem.startsWith(u8, line, "AGREE_UNIX_FD")) {
                    logger.debug("Bus enabled unix fds", .{});
                    self.state = .Connected;
                    self.unix_fds_enabled = true;
                    return;
                } else if (std.mem.startsWith(u8, line, "ERROR")) {
                    logger.warn("Bus refused unix fds, disabling. Some services may not work correctly.", .{});
                    self.state = .Connected;
                    self.unix_fds_enabled = false;
                    return;
                } else return Error.ConnectionLost;
            }
        }
    }
}

pub const MethodCallParams = struct {
    /// May be null for peer-to-peer connections.
    destination: ?[]const u8 = null,
    path: []const u8,
    /// According to DBus specification, interface is optional for method calls
    interface: ?[]const u8 = null,
    member: []const u8,
    /// By default dbus sets that field, but we can override it if needed
    sender: ?[]const u8 = null,

    flags: Flags = .{},

    /// Feedback type
    /// .store (default mode) will store the response in the DBusPendingResponse struct
    /// .call provides a way to specify callbacks that will be called when reply or error is received
    feedback: DBusPendingResponse.Feedback = .{ .store = null },

    pub const Flags = struct {
        /// If set, peer is expected to not send any replies
        no_reply: bool = false,
        no_auto_start: bool = false,
        allow_interactive_auth: bool = false,
    };

};

/// Finalizes message and sends to bus
pub fn send(self: *DBusConnection, msg: *DBusMessage) Error!void {
    if (self.state == .Unconnected or self.state == .Disconnected or self.state == .Errored or self.state == .Rejected) return Error.ConnectionLost;

    const buffer = try msg.finalize();
    defer msg.allocator.free(buffer);
    var oobd: OutOfBandData = .none;
    if (msg.unix_fds.items.len > 0) {
        oobd = .{ .rights = try msg.unix_fds.toOwnedSliceSentinel(-1) };
        defer msg.allocator.free(oobd.rights);
    }

    try self.transport_layer.?.write(buffer, oobd, true);
    logger.debug("[{?s}->{?s}] {s}@{d}(@{?d}) {?s}@{?s}.{?s}({?s})", .{
        msg.sender,
        msg.destination,
        @tagName(msg.message_type),
        msg.serial,
        msg.reply_serial,
        msg.path,
        msg.interface,
        msg.member,
        if (msg.signature.items.len > 0) msg.signature.items else "",
    });
}

/// Call method on the bus and possibly return a DBusPendingResponse pointer
///
/// Example:
///
/// ```
/// const future = try conn.call(.{
///     .destination = "org.freedesktop.DBus",
///     .path = "/org/freedesktop/DBus",
///     .interface = "org.freedesktop.DBus",
///     .member = "ListNames",
/// }, .{}, allocator) orelse unreachable;
/// defer future.deinit(); // Deinit the future when done
/// ```
pub inline fn call(self: *DBusConnection, params: MethodCallParams, values: anytype, allocator: std.mem.Allocator) Error!?*DBusPendingResponse {
    var msg = try self.newMethodCall(params, allocator);
    defer msg.deinit();
    if (@TypeOf(values) != void) {
        try msg.write(values);
    }

    self.response_futures_lock.lock();
    defer self.response_futures_lock.unlock();

    // Send must be called under response_futures_lock in order to avoid race conditions in response handling
    try self.send(&msg);

    if (params.flags.no_reply) return null;
    const future = try pendingResponse(self, msg, params.feedback);
    _ = future.refcounter.fetchAdd(1, .seq_cst);
    return future;
}

pub inline fn pendingResponse(self: *DBusConnection, msg: DBusMessage, handlers: DBusPendingResponse.Feedback) !*DBusPendingResponse {
    const future = try DBusPendingResponse.init(self, msg.serial, handlers, self.allocator);
    try self.response_futures.put(msg.serial, future);
    return future;
}

pub inline fn clearPendingResponse(self: *DBusConnection, serial: u32) void {
    self.response_futures_lock.lock();
    defer self.response_futures_lock.unlock();

    const kv = self.response_futures.fetchRemove(serial);
    if (kv) |future| {
        future.value.deinit();
    }
}

pub inline fn newMethodCall(self: *DBusConnection, params: MethodCallParams, allocator: std.mem.Allocator) AllocatorError!DBusMessage {
    var flags: u8 = 0;
    if (params.flags.no_reply) flags |= DBusMessage.Flags.NO_REPLY_EXPECTED;
    if (params.flags.no_auto_start) flags |= DBusMessage.Flags.NO_AUTO_START;
    if (params.flags.allow_interactive_auth) flags |= DBusMessage.Flags.ALLOW_INTERACTIVE_AUTHORIZATION;
    var msg = try DBusMessage.init(
        allocator,
        flags,
        .METHOD_CALL,
        self.serial_counter.fetchAdd(1, .seq_cst),
    );
    msg.destination = params.destination;
    msg.path = params.path;
    msg.interface = params.interface;
    msg.member = params.member;
    msg.sender = params.sender;
    return msg;
}

pub inline fn newError(self: *DBusConnection, reply_to: *DBusMessage, error_name: []const u8, allocator: std.mem.Allocator) AllocatorError!DBusMessage {
    var msg = try DBusMessage.init(
        allocator,
        0,
        .ERROR,
        self.serial_counter.fetchAdd(1, .monotonic),
    );
    msg.destination = reply_to.sender.?;
    msg.reply_serial = reply_to.serial;
    msg.error_name = error_name;
    return msg;
}

pub inline fn newMethodReturn(self: *DBusConnection, reply_to: *DBusMessage, allocator: std.mem.Allocator) AllocatorError!DBusMessage {
    var msg = try DBusMessage.init(
        allocator,
        0,
        .METHOD_RETURN,
        self.serial_counter.fetchAdd(1, .monotonic),
    );
    msg.destination = reply_to.sender.?;
    msg.reply_serial = reply_to.serial;
    return msg;
}

const SignalCreationParams = struct {
    path: []const u8,
    interface: []const u8,
    member: []const u8,
    sender: ?[]const u8 = null
};

pub inline fn newSignal(self: *DBusConnection, params: SignalCreationParams, allocator: std.mem.Allocator) AllocatorError!DBusMessage {
    var msg = try DBusMessage.init(
        allocator,
        0,
        .SIGNAL,
        self.serial_counter.fetchAdd(1, .monotonic),
    );
    msg.interface = params.interface;
    msg.path = params.path;
    msg.sender = params.sender;
    msg.member = params.member;
    return msg;
}

pub inline fn replyError(self: *DBusConnection, in_reply_to: *DBusMessage, error_name: []const u8, description: []const u8, allocator: std.mem.Allocator) Error!void {
    var err = try self.newError(in_reply_to, error_name, allocator);
    defer err.deinit();
    try err.write(String{.value = description});
    return self.send(&err);
}

pub inline fn replyToCall(self: *DBusConnection, in_reply_to: *DBusMessage, data: anytype, allocator: std.mem.Allocator) Error!void {
    var msg = try self.newMethodReturn(in_reply_to, allocator);
    defer msg.deinit();
    if (@TypeOf(data) != void) {
        try msg.write(data);
    }
    return self.send(&msg);
}

pub inline fn broadcast(self: *DBusConnection, params: SignalCreationParams, data: anytype, allocator: std.mem.Allocator) Error!void {
    var signal = try self.newSignal(params, allocator);
    defer signal.deinit();
    if (@TypeOf(data) != void) {
        try signal.write(data);
    }
    return self.send(&signal);
}

fn readerGetPos(reader: anytype) usize {
    return switch (@TypeOf(reader.context)) {
        *std.ArrayList(u8) => reader.context.items.len,
        *std.io.FixedBufferStream([]u8) => reader.context.pos,
        *const anyopaque => blk: {
            const ctx: *const *std.io.FixedBufferStream([:0]u8) = @alignCast(@ptrCast(reader.context));
            break :blk ctx.*.pos;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(reader.context)) ++ " in alignRead"),
    };
}

fn readerSetPos(reader: anytype, pos: usize) void {
    return switch (@TypeOf(reader.context)) {
        *std.io.FixedBufferStream([]u8) => reader.context.pos = pos,
        *const anyopaque => {
            const ctx: *const *std.io.FixedBufferStream([:0]u8) = @alignCast(@ptrCast(reader.context));
            ctx.*.pos = pos;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(reader.context)) ++ " in alignRead"),
    };
}

fn readerGetMax(reader: anytype) usize {
    return switch (@TypeOf(reader.context)) {
        *std.ArrayList(u8) => reader.context.items.len,
        *std.io.FixedBufferStream([]u8) => reader.context.buffer.len,
        *const anyopaque => blk: {
            const ctx: *const *std.io.FixedBufferStream([:0]u8) = @alignCast(@ptrCast(reader.context));
            break :blk ctx.*.buffer.len;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(reader.context)) ++ " in alignRead"),
    };
}

pub fn dbus(self: *DBusConnection) DBusCommon {
    return DBusCommon.init(self);
}

const isObjectPathValid = dbuz.isObjectPathValid;
const isNameValid = dbuz.isNameValid;

// Names:

/// Add a name to the connection. If name is not added to the connection, any messages sent to the name will be dropped as connection has no idea where to route them.
pub fn addName(self: *DBusConnection, name: *DBusName) !void {
    self.names.mutex.lock();
    defer self.names.mutex.unlock();

    if (self.names.map.get(name.name)) |_| return DBusName.Error.AlreadyExists else {
        try self.names.map.put(name.name, name.ref());
    }
}

/// Remove a name from the connection. Introspection cache is dropped for the name.
pub fn removeName(self: *DBusConnection, name: *DBusName) !void {
    self.names.mutex.lock();
    defer self.names.mutex.unlock();
    defer if (self.introspectable_ctx) |*introspectable| introspectable.dropCacheForName(name.name);

    if (!self.names.map.remove(name.name)) {
        return DBusName.Error.NoSuchName;
    }
    name.unref();
}

/// If name is accounted for by the connection.
pub fn hasName(self: *DBusConnection, name: []const u8) bool {
    self.names.mutex.lock();
    defer self.names.mutex.unlock();
    return self.names.map.get(name) != null;
}

pub fn getName(self: *DBusConnection, name: []const u8) ?*DBusName {
    self.names.mutex.lock();
    defer self.names.mutex.unlock();
    if (self.names.map.get(name)) |n| {
        return n.ref();
    }
    return null;
}

/// Request a name on the bus. This method should never be used with DBus Activation, as interface registrations are racy in that case. If you need to implement DBus activatable service, please create a DBusName manually and then add it to the connection using the `addName` method.
///
/// This method is also should be never called inside the polling loop, as it will wait for reply from the bus.
pub fn requestName(self: *DBusConnection, name: []const u8, options: DBusName.RequestNameOptions) (Error || DBusName.Error)!*DBusName {
    if (self.hasName(name)) return DBusName.Error.AlreadyExists;

    const name_obj = blk: {
        self.names.mutex.lock();
        defer self.names.mutex.unlock();
        const name_obj = try DBusName.init(self, name, options.flags.allow_replacement, self.allocator, options.callbacks);
        errdefer if (name_obj.refcounter.load(.seq_cst) == 0) name_obj.deinit();

        try self.addName(name_obj);
        break :blk name_obj;
    };
    errdefer self.removeName(name_obj) catch {};
    self.dbus().RequestName(name, options.flags) catch |err| switch (err) {
        else => @panic("Unhandled error type!"),
        DBusName.Error.AlreadyExists => return DBusName.Error.AlreadyExists,
        DBusName.Error.AlreadyOwned =>  return DBusName.Error.AlreadyExists,
        DBusName.Error.Queued => {},
        AllocatorError.OutOfMemory => return AllocatorError.OutOfMemory,
        error.Timeout => return error.Timeout,
    };

    return name_obj.ref();
}

/// Releases the name from the bus, and don't waits for reply.
pub fn releaseName(self: *DBusConnection, name: *DBusName) void {
    _ = self.call(.{
        .destination = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ReleaseName",
        .flags = .{ .no_reply = true }
    }, .{String{.value = name.name}}, self.allocator) catch {};

    self.removeName(name) catch {};
}

/// Signal that name was acquired
pub fn nameAcquired(self: *DBusConnection, name: []const u8) void {
    self.names.mutex.lock();
    defer self.names.mutex.unlock();

    const name_obj = self.getName(name) orelse return;
    defer name_obj.unref();
    if (name_obj.callbacks) |cb| {
        if (cb.acquired) |acquired| acquired(name_obj, cb.userdata);
    }
}

pub fn nameLost(self: *DBusConnection, name: []const u8) void {
    self.names.mutex.lock();
    defer self.names.mutex.unlock();

    const name_obj = self.getName(name) orelse return;
    defer name_obj.unref();
    if (name_obj.callbacks) |cb| {
        if (cb.lost) |lost| lost(name_obj, cb.userdata);
        self.removeName(name_obj) catch {};
    }
}

/// Helper function that creates a proxy object that points to the target name.
pub fn proxy(self: *DBusConnection, target_name: []const u8, allocator: std.mem.Allocator, options: DBusProxy.Options) DBusProxy {
    var opts: DBusProxy.Options = options;
    opts.destination = target_name;
    return DBusProxy.init(self, allocator, opts);
}
