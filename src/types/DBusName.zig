
const std = @import("std");
const dbuz = @import("../dbuz.zig");

const DBusConnection = @import("DBusConnection.zig");
const DBusMessage = @import("DBusMessage.zig");
const DBusProxy = @import("DBusProxy.zig");
const String = @import("dbus_types.zig").String;
const Interface = @import("Interface.zig");

const isObjectPathValid = dbuz.isObjectPathValid;
const isNameValid = dbuz.isNameValid;

// It is public so we can be sure what exactly is being used across the codebase
pub const Mutex = std.Thread.Mutex.Recursive;

const Self = @This();
pub const Error = error{
    NotOwner,
    NoSuchName,

    AlreadyExists,
    AlreadyOwned,

    Queued,

    UnexpectedError,
    NameNotValid,
};

pub const Callbacks = struct {
    acquired: ?*const fn (*Self, *anyopaque) void,
    lost: ?*const fn (*Self, *anyopaque) void,
    userdata: *anyopaque,
};

conn: *DBusConnection,
name: []const u8,
allow_replacement: ?bool = null,

allocator: std.mem.Allocator,

objects: struct {
    map: std.StringHashMap(std.ArrayList(Interface)),
    mutex: Mutex,
},

callbacks: ?Callbacks = null,
refcounter: std.atomic.Value(u32) = .init(0),

pub fn init(conn: *DBusConnection, name: []const u8, allow_replacement: bool, allocator: std.mem.Allocator, callbacks: ?Callbacks) error{OutOfMemory}!*Self {
    const self = try allocator.create(Self);
    self.* =.{.conn = conn, .name = name, .allow_replacement = allow_replacement, .allocator = allocator, .objects = .{
        .map = .init(allocator),
        .mutex = .init
    },
    .callbacks = callbacks
    };
    return self;
}

pub fn ref(self: *Self) *Self {
    _ = self.refcounter.fetchAdd(1, .seq_cst);
    return self;
}

pub fn unref(self: *Self) void {
    const old_refs = self.refcounter.fetchSub(1, .seq_cst);
    if (old_refs == 0) @panic("Unref on zero reference count");
    if (old_refs == 1) {
        self.deinit();
    }
}

const PublishParams = struct {
    path: []const u8,
    name: []const u8,
    /// If interface should be hidden during introspection
    hidden: bool = false,
};

pub fn registerInterface(self: *Self, comptime T: type, userdata: *anyopaque, params: PublishParams) !Interface {
    if (!isObjectPathValid(params.path)) return DBusConnection.Error.InvalidObjectPath;
    if (!isNameValid(params.name)) return DBusConnection.Error.InvalidServiceName;

    defer if (self.conn.introspectable_ctx) |*introspectable| introspectable.dropCacheForPair(params.path, self.name);

    const interface = try Interface.init(T, userdata, self.conn.allocator, params.path, params.name, self.conn, self, params.hidden);
    errdefer interface.destroy();

    self.objects.mutex.lock();
    defer self.objects.mutex.unlock();

    const interface_list: *std.ArrayList(Interface) = self.objects.map.getPtr(params.path) orelse blk: {
        const list = std.ArrayList(Interface).init(self.conn.allocator);
        try self.objects.map.put(params.path, list);
        break :blk self.objects.map.getPtr(params.path) orelse unreachable;
    };

    for (interface_list.items) |iface| {
        if (std.mem.eql(u8, iface.interface, params.name)) return error.InterfaceNameAlreadyRegistered;
    }

    try interface_list.append(interface);

    return interface;
}

pub fn unregisterInterface(self: *Self, interface: Interface) void {

    self.objects.mutex.lock();
    defer self.objects.mutex.unlock();

    defer if (self.conn.introspectable_ctx) |*introspectable| introspectable.dropCacheForPair(interface.path, self.name);

    const interface_list: ?*std.ArrayList(Interface) = self.objects.map.getPtr(interface.path);
    if (interface_list) |list| {
        for (list.items, 0..) |iface, i| {
            if (std.mem.eql(u8, iface.interface, interface.interface)) {
                _ = list.swapRemove(i);
            }
        }
    }
}

pub fn routeMethodCall(self: *Self, msg: *DBusMessage) Interface.Error!void {
    self.objects.mutex.lock();
    defer self.objects.mutex.unlock();

    const interface_list: ?*std.ArrayList(Interface) = self.objects.map.getPtr(msg.path.?);
    if (interface_list) |list| {
        for (list.items) |iface| {
            if (std.mem.eql(u8, iface.interface, msg.interface.?)) {
                return iface.vtable.route_call(iface.ptr, self.conn, msg);
            }
        }
    }
    return Interface.Error.Unhandled;
}

pub fn release(self: *Self) void {
    self.conn.releaseName(self);
    self.unref();
}

pub fn deinit(self: *Self) void {
    self.objects.mutex.lock();
    defer self.objects.mutex.unlock();

    var it = self.objects.map.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.items) |iface| {
            iface.destroy();
        }
        entry.value_ptr.deinit();
    }
    self.objects.map.deinit();
    self.allocator.destroy(self);
}

pub fn proxy(self: *Self, target_name: []const u8, allocator: std.mem.Allocator, options: DBusProxy.Options) DBusProxy {
    var opts: DBusProxy.Options = options;
    opts.destination = target_name;
    opts.sender = self.name;
    return DBusProxy.init(self.conn, allocator, opts);
}
