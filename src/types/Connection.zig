
/// Represents an active DBus connection.
const Connection = @This();

const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const atomic = std.atomic;

const logger = std.log.scoped(.Connection);

const Thread = std.Thread;

const dbuz = @import("../dbuz.zig");
const transport = dbuz.transport;
const trie = @import("../tree.zig");

const Message = dbuz.types.Message;
const Promise = dbuz.types.Promise;
const PromiseOpaque = dbuz.types.PromiseOpaque;
const PromiseError = dbuz.types.PromiseError;
const Interface = dbuz.types.Interface;
const MatchRule = dbuz.types.MatchRule;

const default_buffer_size = 4096;

const InterfaceManaged = struct {
    interface: *Interface,
    allocator: mem.Allocator,
};

const ListenerManaged = struct {
    interface: *Interface,
    rule: MatchRule,
    allocator: mem.Allocator,
    c: *Connection,
    unique_id: usize,
};

/// Default allocator to be used if another not passed to function.
default_allocator: mem.Allocator,

handle: posix.fd_t,

/// Transport reader created from .handle.
reader: transport.Reader,

/// Queue of special entities received from control message passed with actual message.
fd_queue: std.ArrayList(i32) = .{},
ucreds_queue: std.ArrayList(@import("../cmsg.zig").ucred) = .{},
pidfd_queue: std.ArrayList(i32) = .{},

/// Should unix fd passing be enabled?
enable_fds: bool = true,

next_serial: atomic.Value(u32) = .init(1),
next_listener_id: atomic.Value(usize) = .init(1),

pending_message: ?Message = null,
pending_arena: ?*std.heap.ArenaAllocator = null,

/// MethodCall response tracker.
tracker: std.AutoArrayHashMapUnmanaged(u32, *PromiseOpaque) = .{},
tracker_lock: Thread.Mutex = .{},

object_tree: struct {
    mutex: Thread.Mutex,
    tree: trie.Tree(InterfaceManaged),
},

listeners: struct {
    mutex: Thread.Mutex,
    list: std.ArrayList(ListenerManaged),
},

/// org.freedesktop.DBus proxy bound to current connection.
dbus: dbuz.proxies.DBus,

/// DBus unique name. null before call to hello(Async);
unique_name: ?[]const u8 = null,

/// Create new instance of connection, allocating new Connection on heap using passed allocator.
/// Takes ownership of passed handle. If function returns an error, handle is guaranteed to be valid.
pub fn init(allocator: mem.Allocator, handle: posix.fd_t) !*Connection {
    errdefer |err| logger.debug("Connection creation for fd:{} failed: {s}", .{handle, @errorName(err)});

    var reader = try transport.Reader.init(allocator, handle, default_buffer_size);
    errdefer reader.deinit();
    
    const c = try allocator.create(Connection);
    errdefer allocator.destroy(c);

    c.* = .{
        .default_allocator = allocator,
        .handle = handle,
        .reader = reader,
        .object_tree = .{
            .mutex = .{},
            .tree = .empty,
        },
        .listeners = .{
            .mutex = .{},
            .list = .empty,
        },
        .dbus = try .init(c),
        .pending_message = null,
        .pending_arena = null,
    };
    logger.debug("Created {*} for fd:{}", .{c, handle});
    return c;
}

/// Exports handle used for sending and receiving data. Exists for cases, where owner of *Connection does not opened socket by themself.
pub fn exportFileDescriptor(self: *const Connection) i32 {
    return self.handle;
}

/// Advances current connection internal state. Returns null if message is still in reading phase, returns tuple of Message, *ArenaAllocator when message is ready.
/// ArenaAllocator is initialized by passed allocator (or default one if null is passed). All Message's internal allocations are made using returned ArenaAllocator.
/// Caller owns returned memory. Caller MUST call Message.deinit() when all operations on message is ended, as ArenaAllocator.deinit() not closes associated file descriptors.
pub fn advance(self: *Connection, allocator: ?mem.Allocator) !?struct {Message, *std.heap.ArenaAllocator} {
    logger.debug("Advancing connection...", .{});
    const r = &self.reader.interface;
    const alloc = if (allocator) |a| a else self.default_allocator;
    const msg: *Message = if (self.pending_message) |*pm| @constCast(pm) else blk: {
        const arena = try alloc.create(std.heap.ArenaAllocator);
        arena.* = .init(alloc);
        errdefer alloc.destroy(arena);
        errdefer arena.deinit();

        self.pending_message = try Message.initReading(arena.allocator(), r, &self.fd_queue);
        self.pending_arena = arena;
        break :blk @constCast(&self.pending_message.?);
    };

    while (true) {
        if (self.reader.pendingControlMessageType()) |scm| {
            switch (scm) {
                .RIGHTS => {
                    if (self.enable_fds) {
                        var rights: [100]i32 = undefined;
                        const rights_len = try self.reader.takeFileDescriptors(&rights);
                        try self.fd_queue.appendSlice(self.default_allocator, rights[0..rights_len]);
                    } else {
                        self.reader.discardControlMessage();
                    }
                },
                .CREDENTIALS => {
                    const cred = try self.reader.takeCredentials();
                    try self.ucreds_queue.append(self.default_allocator, cred);
                },
                .PIDFD => {
                    const pidfd = try self.reader.takePidFD();
                    try self.pidfd_queue.append(self.default_allocator, pidfd);
                },
                else => {}
            }
        }
        if (msg.isComplete()) {
            const m = self.pending_message orelse unreachable;
            const a = self.pending_arena orelse unreachable;
            self.pending_message = null;
            logger.debug("[Message:{}] Received message: {?s} -> {?s} ({?s}@{?s}.{?s}())", .{
                m.serial,
                m.fields.sender,
                m.fields.destination,
                m.fields.path,
                m.fields.interface,
                m.fields.member,
            });
            return .{m, a};
        }
        _ = msg.continueReading() catch |err| {
            switch (err) {
                error.ReadFailed => break,
                else => return err,
            }
        };
    }
    return null;
}

/// Initializes Message struct in writing mode. Called owns returned memory and must call Message.deinit() to release the resources.
pub fn startMessage(self: *Connection, gpa: ?std.mem.Allocator) !Message {
    const serial = self.next_serial.fetchAdd(1, .seq_cst);
    var message = try Message.initWriting(gpa orelse self.default_allocator, .little, self.enable_fds);
    message.serial = serial;
    return message;
}

fn helloReplied(_: *Promise(dbuz.types.String), name: dbuz.types.String, _: *std.heap.ArenaAllocator, userdata: ?*anyopaque) void {
    const c: *Connection = @alignCast(@ptrCast(userdata));
    var unique_id: usize = undefined;
    const promise = c.registerListenerAsync(&c.dbus, .{
        .interface = "org.freedesktop.DBus",
        .path = "/org/freedesktop/DBus",
    }, &unique_id, c.default_allocator) catch unreachable;
    if (promise.release() == 1) promise.destroy();

    c.unique_name = c.default_allocator.dupe(u8, name.value) catch null;
    logger.debug("Hello received: unique name is {s}", .{name.value});
}

fn helloFailed(_: *Promise(dbuz.types.String), err: PromiseError, _: ?*anyopaque) void {
    logger.debug("Hello failed: {s}", .{
        err.message orelse @errorName(err.error_code)
    });
}

/// Sends org.freedesktop.DBus.Hello on message bus in asyncronous manner.
/// Must be first sent message after bus authentication.
/// (Internally, just a wrapper above Connection.dbus.Hello proxy call, that setups some callbacks, you can do it your way if you want to)
///
/// Returns promise to a DBus String, that is connection's unique name.
pub fn helloAsync(c: *Connection) !*Promise(dbuz.types.String) {
    const promise = try c.dbus.Hello();
    promise.setupCallbacks(.{
        .response = &helloReplied,
        .@"error" = &helloFailed,
        .timeout = null
    }, c);

    return promise;
}

/// Sends org.freedesktop.DBus.Hello and blocks until bus replies. See helloAsync for more information.
///
/// Calling that method in single threaded environment is an **unchecked illegal behavior** and will result in possible deadlock.
pub fn hello(c: *Connection) !void {
    const promise = try c.helloAsync();
    defer if (promise.release() == 1) promise.destroy();
    const value, const arena = try promise.wait(null);
    switch (value) {
        .response => return,
        .@"error" => |e| return e.error_code,
    }
    _ = arena;
}

/// Create a *Promise of type T from a message. Bus will update promise if message will get response, error or will timeout (only if you provided implementation for it)
/// 
/// Callers owns reference to a Promise. As release order is unclear, caller, when releasing reference must check if it was last reference and destroy promise if so.
pub fn trackResponse(c: *Connection, message: Message, comptime T: type) !*Promise(T) {
    const promise = try Promise(T).create(c.default_allocator);
    errdefer promise.destroy();

    c.tracker_lock.lock();
    defer c.tracker_lock.unlock();

    const entry = try c.tracker.getOrPut(c.default_allocator, message.serial);
    if (entry.found_existing) return error.DuplicateSerial;
    entry.value_ptr.* = &promise.interface;

    return promise.reference();
}

/// Should be called from external mechanism to inform connection that response timeout for Promise with serial `serial` is reached.
pub fn promiseDeadlineReached(c: *Connection, serial: u32) void {
    c.tracker_lock.lock();
    defer c.tracker_lock.unlock();

    const entry = c.tracker.fetchSwapRemove(serial);

    if (!entry) {
        return;
    }

    const promise = entry.?.value;
    promise.vtable.timedout(promise);
    if (promise.vtable.release(promise) == 1) promise.vtable.destroy(promise);
}

fn handleProperties(c: *Connection, m: *Message, arena: mem.Allocator) !void {
    const r = try m.reader();
    const interface_name = (try r.read(dbuz.types.String, arena)).value;
    const branch = c.object_tree.tree.get( try trie.runtimePathWithLastComponent(m.fields.path.?, interface_name, arena) );
    if (branch) |node| {
        var response = try node.leaf.interface.vtable.property_op.?(node.leaf.interface, m, arena);
        if (response) |*res| try c.sendMessage(res);
    }
}

fn handleIntrospection(c: *Connection, m: *Message, arena: mem.Allocator) !void {
    logger.debug("[Message:{}] {?s} requested introspection for path {?s}", .{m.serial, m.fields.sender, m.fields.destination});
    const branch = if (
        !std.mem.eql(u8, m.fields.path.?, "/")
    ) c.object_tree.tree.get( try trie.runtimeKey(m.fields.path.?, arena) )
    else c.object_tree.tree.root;
    if (branch) |node| {
        var xml = std.Io.Writer.Allocating.init(arena);
        defer xml.deinit();
        const xml_w = &xml.writer;

        errdefer |e| {
            var error_reply: ?Message = c.startMessage(arena) catch null;
            if (error_reply) |*err| {
                err.type = .@"error";
                err.fields = .{
                    .destination = m.fields.sender,
                    .reply_serial = m.serial,
                    .error_name = std.fmt.allocPrint(arena, "com.github.0xCatPKG.dbuz.Error.{s}", .{@errorName(e)}) catch null,
                };
                c.sendMessage(err) catch {};
            }
        }

        _ = try xml_w.write("<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n<node>\n");
        switch (node) {
            .branch => |b| {
                var it = b.branches.iterator();
                while (it.next()) |br| {
                    switch (br.value_ptr.*) {
                        .leaf => |l| {
                            _ = try xml_w.write(l.interface.description);
                        },
                        .branch => {
                            var buf: [256]u8 = undefined;
                            _ = try xml_w.write(try std.fmt.bufPrint(&buf, "    <node name=\"{s}\"/>\n", .{br.key_ptr.*}));
                        }
                    }
                }
            },
            .leaf => return error.UnknownObject,
        }
        _ = try xml_w.write("</node>\n");

        var reply = try c.startMessage(arena);
        reply.type = .method_response;
        reply.fields = .{
            .destination = m.fields.sender,
            .reply_serial = m.serial,
            .signature = "s",
        };
        const w = reply.writer();
        try w.write(dbuz.types.String{.value = xml.written()});
        // std.debug.print("{s}\n", .{xml.written()});
        return c.sendMessage(&reply);
    } else {
        var err = try c.startMessage(arena);
        err.type = .@"error";
        err.fields = .{
            .destination = m.fields.sender,
            .reply_serial = m.serial,
            .error_name = "org.freedesktop.DBus.Error.UnknownObject",
        };
        return c.sendMessage(&err);
    }
}

/// Handle tuple of Message, *ArenaAllocator received from Connection.advance.
/// Takes ownership of Message and *ArenaAllocator, automatically runs callbacks from published interfaces, registered listeners
/// and updates promises
pub fn handleMessage(c: *Connection, m_a: struct {Message, *std.heap.ArenaAllocator}) !void {
    var message, const arena = m_a;
    var handled: bool = false;

    defer {
        if (!handled) {
            message.deinit();
            arena.deinit();
            arena.child_allocator.destroy(arena);
        }
    }

    switch (message.type) {
        .method_response, .@"error" => {
            // Reply without reply_serial is protocol violation, so we silently drop it.
            if (message.fields.reply_serial == null) return;

            c.tracker_lock.lock();
            const entry = c.tracker.fetchSwapRemove(message.fields.reply_serial.?);
            c.tracker_lock.unlock();
            if (entry == null) {
                return;
            }

            const promise = entry.?.value;
            promise.vtable.received(promise, message, arena);
            if (promise.vtable.release(promise) == 1) promise.vtable.destroy(promise);
            handled = true;
        },
        .method_call => {
            // Sanity check
            if (message.fields.sender == null or message.fields.interface == null or message.fields.member == null or message.fields.path == null) return;

            c.object_tree.mutex.lock();
            defer c.object_tree.mutex.unlock();

            if (mem.eql(u8, message.fields.interface.?, "org.freedesktop.DBus.Properties")) {
                try c.handleProperties(&message, arena.allocator());
                return;
            }

            if (mem.eql(u8, message.fields.interface.?, "org.freedesktop.DBus.Introspectable")) {
                try c.handleIntrospection(&message, arena.allocator());
                return;
            }

            const child = c.object_tree.tree.get(try trie.runtimePathWithLastComponent(message.fields.path.?, message.fields.interface.?, arena.allocator()));
            if (child) |node| {
                var response = node.leaf.interface.vtable.method_call.?(node.leaf.interface, &message, arena.allocator()) catch return;
                if (response) |*r| try c.sendMessage(r);

            } else {
                var err = try c.startMessage(arena.allocator());
                err.type = .@"error";
                err.fields = .{
                    .destination = message.fields.sender,
                    .reply_serial = message.serial,
                    .error_name = "org.freedesktop.DBus.Error.UnknownInterface",
                };
                try c.sendMessage(&err);
            }
        },
        .signal => {
            if (message.fields.path == null or message.fields.interface == null or message.fields.member == null or message.fields.sender == null) return;
            
            c.listeners.mutex.lock();
            defer c.listeners.mutex.unlock();

            for (c.listeners.list.items) |listener| {
                if (!listener.rule.match(&message)) continue;
                listener.interface.vtable.signal.?(listener.interface, &message, arena.allocator()) catch {};
            }
        },
        else => {}
    }
}

/// Registers interface at specified path. 
///
/// impl is an container, that contains field "interface" of type dbuz.types.Interface. Passed interface
/// must implement method_call and property_op vtable methods. gpa is an allocator used for impl's allocation.
/// registerInterface takes reference to impl.interface and will use provided gpa when releases last reference to interface.
pub fn registerInterface(c: *Connection, impl: anytype, comptime path: []const u8, gpa: mem.Allocator) !void {
    _ = impl.interface.reference();
    errdefer if (impl.interface.release() == 1) impl.interface.deinit(gpa);
    if (impl.interface.vtable.method_call == null or impl.interface.vtable.property_op == null) return error.InvalidVTable;

    c.object_tree.mutex.lock();
    defer c.object_tree.mutex.unlock();

    const key = trie.comptimePathWithLastComponent(path, @TypeOf(impl.*).interface_name);
    try c.object_tree.tree.insert(key, .{ .interface = &impl.interface, .allocator = gpa });
    impl.interface.bind(c, path);
}

/// Unregisters interface at specified path.
pub fn unregisterInterface(c: *Connection, impl: anytype, comptime path: []const u8) bool {
    const key = trie.comptimePathWithLastComponent(path, @TypeOf(impl.*).interface_name);
    
    c.object_tree.mutex.lock();
    defer c.object_tree.mutex.unlock();

    const branch = c.object_tree.tree.get(key);
    if (branch) |node| {
        const managed = node.leaf;

        if (&impl.interface != managed.interface) @panic("Logic error: &impl.interface != managed.interface");
        if (managed.interface.release() == 1) managed.interface.deinit(managed.allocator);
        return c.object_tree.tree.remove(key);
    } else return false;
}

fn listenerAdded(_: *Promise(void), _: void, _: *std.heap.ArenaAllocator, userdata: ?*anyopaque) void {
    const listener: *ListenerManaged = @alignCast(@ptrCast(userdata));
    logger.debug("[Listener:{}] Successfully registered on DBus", .{listener.unique_id});
}

fn listenerAddError(_: *Promise(void), cause: PromiseError, userdata: ?*anyopaque) void {
    const listener: *ListenerManaged = @alignCast(@ptrCast(userdata));
    logger.err("[Listener:{}] Unable to register on DBus: {s}", .{listener.unique_id, cause.message orelse @errorName(cause.error_code)});

    listener.c.listeners.mutex.lock();
    defer listener.c.listeners.mutex.unlock();

    for (listener.c.listeners.list.items, 0..) |data, i| {
        if (data.unique_id != listener.unique_id) continue;
        if (data.interface.release() == 1) data.interface.deinit(data.allocator);
        _ = listener.c.listeners.list.swapRemove(i);
        return;
    }
}

/// Requests listener to be added.
/// Doesn't guarantee that listener will be added
/// unique_id is unique id of listener that can be used for listener unregistering.
pub fn registerListenerAsync(c: *Connection, impl: anytype, rule: MatchRule, unique_id: *usize, allocator: mem.Allocator) !*Promise(void) {
    _ = impl.interface.reference();
    errdefer if (impl.interface.release() == 1) impl.interface.deinit(allocator);

    const key = try rule.string(allocator);
    defer allocator.free(key);

    c.listeners.mutex.lock();
    defer c.listeners.mutex.unlock();

    const listener = try c.listeners.list.addOne(c.default_allocator);
    listener.* = .{
        .interface = &impl.interface,
        .allocator = allocator,
        .rule = rule,
        .c = c,
        .unique_id = c.next_listener_id.fetchAdd(1, .monotonic),
    };

    unique_id.* = listener.unique_id;

    logger.debug("Registering a new listener of type {s} with unqiue_id {}, match string \"{s}\"", .{ @typeName(@TypeOf(impl)), listener.unique_id, key });

    const promise = try c.dbus.AddMatch(key);
    promise.setupCallbacks(.{
        .timeout = null,
        .response = &listenerAdded,
        .@"error" = &listenerAddError,
    }, listener);

    return promise;
}

/// Look ar registerListenerAsync for details. Returns unique_id of listener.
pub fn registerListener(c: *Connection, impl: anytype, rule: MatchRule, allocator: mem.Allocator) !usize {
    var unique_id: usize = undefined;

    const promise = try c.registerListenerAsync(impl, rule, &unique_id, allocator);
    defer if (promise.release() == 1) promise.destroy();

    const value, _ = try promise.wait(null);
    switch (value) {
        .response => return unique_id,
        .@"error" => |err| return err.error_code,
    }
}

pub fn unregisterListener(c: *Connection, unique_id: usize) void {
    c.listeners.mutex.lock();
    defer c.listeners.mutex.unlock();

    for (c.listeners.list.items, 0..) |listener, i| {
        if (listener.unique_id != unique_id) continue;
        if (listener.interface.release() == 1) listener.interface.deinit(listener.allocator);
        _ = c.listeners.list.swapRemove(i);

        const rule_str = listener.rule.string(c.default_allocator) catch null;
        defer c.default_allocator.free(rule_str);

        if (rule_str) |rule| {
            const promise = c.dbus.RemoveMatch(rule) catch null;
            if (promise) |p| {
                if (p.release() == 1) p.deinit();
            }
        }

        logger.debug("[Listener:{}] Unregistered a listener with rule {?s}", .{ listener.unique_id, rule_str });
        break;
    }
    logger.warn("Unable to find listener with unique_id {}", .{unique_id});
}

/// Sends passed message down the handle.
pub fn sendMessage(c: *Connection, m: *Message) !void {
    var w = try transport.Writer.init(c.default_allocator, c.handle, 4096);
    defer w.deinit();

    const writer = &w.interface;
    
    var fds: []const i32 = undefined;
    try m.write(writer, &fds);
    
    if (m.fields.unix_fd_amount > 0) {
        try w.putFDs(fds);
    }

    try writer.flush();
    logger.debug("[Message:{}] Sent message: {?s} -> {?s} ({?s}@{?s}.{?s}())", .{
        m.serial,
        m.fields.sender,
        m.fields.destination,
        m.fields.path,
        m.fields.interface,
        m.fields.member,
    });
}

pub fn deinit(c: *Connection) void {
    {
        if (c.pending_message) |*m| m.deinit();
        // if (c.pending_arena) |a| {
        //     // a.deinit();
        //     // a.child_allocator.destroy(a);
        // }
        if (c.unique_name) |unique_name| c.default_allocator.free(unique_name);

        c.tracker_lock.lock();
        c.object_tree.mutex.lock();
        c.listeners.mutex.lock();

        defer c.tracker_lock.unlock();
        defer c.object_tree.mutex.unlock();
        defer c.listeners.mutex.unlock();

        {
            var it = c.tracker.iterator();
            while (it.next()) |kv| {
                const promise = kv.value_ptr.*;
                if (promise.vtable.release(promise) == 1) promise.vtable.destroy(promise);
            }
        }
        c.object_tree.tree.deinit(c.default_allocator);
        {
            for (c.listeners.list.items) |listener_managed| {
                if (listener_managed.interface.release() == 1) listener_managed.interface.deinit(listener_managed.allocator);
            }
        }

        for (c.fd_queue.items) |fd| (std.fs.File{ .handle = fd }).close();
        for (c.pidfd_queue.items) |pid_fd| (std.fs.File{ .handle = pid_fd }).close();
        c.fd_queue.deinit(c.default_allocator);
        c.pidfd_queue.deinit(c.default_allocator);
        c.ucreds_queue.deinit(c.default_allocator);

        c.reader.deinit();
        c.dbus.deinit();
    }
    posix.close(c.handle);
    c.listeners.list.deinit(c.default_allocator);
    c.object_tree.tree.deinit(c.default_allocator);
    c.tracker.deinit(c.default_allocator);
    c.default_allocator.destroy(c);
}

