
const std = @import("std");
const dbuz = @import("../dbuz.zig");

const DBusConnection = @import("DBusConnection.zig");
const DBusMessage = @import("DBusMessage.zig");
const DBusProxy = @import("DBusProxy.zig");
const String = @import("dbus_types.zig").String;
const Interface = @import("Interface.zig");
const DBusCommon = dbuz.interfaces.DBusCommon;

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

/// Creates a new DBusName. If you want to avoid race condition with DBus Activation, you want to call .init by yourself instead of relying on the connection.requestName
///
/// When you are ready to request name, just call .request()
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

/// Increments the reference counter
pub fn ref(self: *Self) *Self {
    _ = self.refcounter.fetchAdd(1, .seq_cst);
    return self;
}

/// Decrements the reference counter. If reference count reaches zero, struct is freed.
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

/// Registers an interface on given name.
///
/// Note: connection will not be able to route messages to this interface, unless name is added to the connection's name table. Usually this is done by calling `DBusConnection.registerName`, but may be done manually by calling `DBusConnection.addName`
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

/// Removes an interface from the name interfaces table.
/// Note that this function does not frees the memory of the interface, but DBusInterface.destroy() calls that function implicitly.
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

/// Routes a message to the appropriate interface. Called from DBusConnection.update(), must have type METHOD_CALL
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

/// Asks dbus to release the name, then unrefs the object.
pub fn release(self: *Self) void {
    self.conn.releaseName(self);
    self.unref();
}

/// Deinits the name, destroying all associated interfaces.
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

/// Helper function to create a proxy object with sender set to name's value.
pub fn proxy(self: *Self, target_name: []const u8, allocator: std.mem.Allocator, options: DBusProxy.Options) DBusProxy {
    var opts: DBusProxy.Options = options;
    opts.destination = target_name;
    opts.sender = self.name;
    return DBusProxy.init(self.conn, allocator, opts);
}

pub const RequestNameOptions = struct {
    flags: DBusCommon.RequestNameFlags = .{},
    callbacks: ?Callbacks = null,
};

/// Synchronously requests the name from the bus and then returns result. That method should be never called from polling loop, as it waits until bus response.
pub fn request(self: *Self, options: RequestNameOptions) Error!void {
    if (options.callbacks) |cb| self.callbacks = cb;
    try self.conn.dbus().RequestName(self.name, options.flags);
}
