
const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const atomic = std.atomic;

const Thread = std.Thread;

const dbuz = @import("../dbuz.zig");
const Message = dbuz.types.Message;

const isTypeSerializable = @import("dbus_types.zig").isTypeSerializable;
const isTypeDeserializable = @import("dbus_types.zig").isTypeDeserializable;

const State = enum {
    Pending,
    Completed,
    Invalid,
};

/// https://dbus.freedesktop.org/doc/api/html/group__DBusProtocol.html
pub const DBusError = error{
    Failed,
    OutOfMemory,
    ServiceUnknown,
    NameHasNoOwner,
    NoReply,
    IOError,
    BadAddress,
    NotSupported,
    LimitsExceeded,
    AccessDenied,
    AuthFailed,
    NoServer,
    Timeout,
    NoNetwork,
    AddressInUse,
    InvalidArgs,
    FileNotFound,
    FileExists,
    UnknownMethod,
    UnknownObject,
    UnknownInterface,
    UnknownProperty,
    PropertyReadOnly,
    TimedOut,
    MatchRuleNotFound,
    MatchRuleInvalid,
    UnixProcessIdUnknown,
    InvalidSignature,
    InvalidFileContent,
    SELinuxSecurityContextUnknown,
    ObjectPathInUse,
    InconsistentMessage,
    InteractiveAuthorizationRequired,
    NotContainer,

    Disconnected,
};

fn errorFromMessage(comptime E: type, message: *const Message) E {
    const e_info = @typeInfo(E).error_set.?;
    const namespaced_error = if (message.fields.error_name) |err| err else return DBusError.Failed;
    var err_iterator = mem.splitBackwardsScalar(u8, namespaced_error, '.');

    const err_name = err_iterator.next().?;

    inline for (e_info) |err| {
        if (!std.mem.eql(u8, err_name, err.name)) comptime continue;
        return @field(E, err.name);
    }
    return DBusError.Failed;
}

/// Create message response wrapper with expected return type T. Even if this type promises you to return T, it will return tuple of Promise(T).Value and *ArenaAllocator from .wait, to handle cases when error is arrived.
/// If passed T is equals to Message, Value's response type will be actually *Message, because reasons. It is possible to setup callbacks on promise, if you don't want block some thread with .wait()
pub fn Promise(comptime T: type, comptime E: type) type {
    if (!isTypeDeserializable(T) and T != void) @compileError(std.fmt.comptimePrint("Unable to construct promise type from {s}: T must be void or DBus-serializable type", .{@typeName(T)}));
    return struct {
        pub const Type = T;
        pub const Error = E;
        pub const Callback = *const fn (promise: *Self, result: Error!Type, arena: ?*std.heap.ArenaAllocator, userdata: ?*anyopaque) void;

        const Self = @This();

        state: State = .Pending,

        condition: Thread.Condition = .{},
        mutex: Thread.Mutex = .{},

        result_value:   ?Error!Type = null,
        result_arena:   ?*std.heap.ArenaAllocator = null,
        result_message: ?Message = null,

        callback: ?Callback = null,
        capture:   ?*anyopaque = null,

        refcounter: atomic.Value(isize) = .init(0),

        allocator: mem.Allocator,

        interface: PromiseOpaque = .{
            .vtable = &.{
                .received = &received,
                .errored = &errored,
                .timedout = &timedout,
                .reference = &vtable_reference,
                .release = &vtable_release,
                .destroy = &vtable_destroy,
            },
        },

        /// Create Promise(T) using gpa as allocator or fail miserably.
        pub fn create(gpa: mem.Allocator) !*@This() {
            const promise = try gpa.create(@This());
            promise.* = .{
                .refcounter = .init(1),
                .allocator = gpa,
            };
            return promise;
        }

        pub fn reference(p: *@This()) *@This() {
            _ = p.refcounter.fetchAdd(1, .seq_cst);
            return p;
        }

        fn vtable_reference(po: *PromiseOpaque) *PromiseOpaque {
            const p: *@This() = @fieldParentPtr("interface", po);
            return &p.reference().interface;
        }

        /// Releases reference to underlying data. If returned value is 1, caller MUST then call .destroy();
        pub fn release(p: *@This()) isize {
            return p.refcounter.fetchSub(1, .seq_cst);
        }

        fn vtable_release(po: *PromiseOpaque) isize {
            return @as(*@This(), @fieldParentPtr("interface", po)).release();
        }

        /// Destroys promise, including underlying message.
        pub fn destroy(p: *@This()) void {
            p.mutex.lock();
            switch (p.state) {
                .Completed => {
                    // Usually deinitializing arena is enough, but in case with file descriptors we need to close them manually.
                    if (p.result_message) |*msg| msg.deinit();
                    if (p.result_arena) |arena| {
                        arena.deinit();
                        arena.child_allocator.destroy(arena);
                    }
                },
                else => {},
            }
            p.state = .Invalid;
            p.mutex.unlock();
            p.allocator.destroy(p);
        }

        fn vtable_destroy(po: *PromiseOpaque) void {
            return @as(*@This(), @fieldParentPtr("interface", po)).destroy();
        }

        /// Blocks calling thread until reply arrives for timeout_ns nanoseconds (orelse for 90 seconds).
        /// On success, returns tuple of Promise(T).Value, *ArenaAllocator, else error. ArenaAllocator is allocator of T, if T requires allocation.
        /// Callbacks are guaranteed to fire before this method exits.
        /// 
        /// NOTE: NEVER CALL THIS METHOD FROM INSIDE OF ANOTHER PROMISE'S CALLBACK. THIS WILL CAUSE DEADLOCK.
        pub fn wait(p: *@This(), timeout_ns: ?u64) !struct {Error!Type, *std.heap.ArenaAllocator} {
            p.mutex.lock();
            defer p.mutex.unlock();
            state: switch (p.state) {
                .Completed => {
                    if (p.result_value == null) return error.TimedOut;
                    return .{p.result_value.?, p.result_arena.?};
                },
                .Pending => {
                    try p.condition.timedWait(&p.mutex, timeout_ns orelse 90 * std.time.ns_per_s);
                    continue :state p.state;
                },
                .Invalid => unreachable,
            }
            unreachable;
        }

        /// Takes ownership of message and arena.
        pub fn received(po: *PromiseOpaque, message: Message, arena: *std.heap.ArenaAllocator) void {
            const p: *@This() = @fieldParentPtr("interface", po);

            p.mutex.lock();
            defer p.mutex.unlock();

            if (p.state != .Pending) @panic("Message received on non-pending promise! Connection or promise is corrupted.");
            p.result_arena = arena;
            p.result_message = message;
            p.result_value = switch (message.type) {
                .@"error" => errorFromMessage(Error, &message),
                .method_response => r: {
                    const message_reader = p.result_message.?.reader() catch break :r Error.OutOfMemory;
                    const values = message_reader.read(T, arena.allocator()) catch break :r error.Failed;
                    break :r values; 
                },
                else => unreachable,
            };

            if (p.callback) |cb| 
                cb(p, p.result_value.?, p.result_arena, p.capture);

            p.state = .Completed;
            p.condition.broadcast();
        }

        pub fn errored(po: *PromiseOpaque, err: DBusError) void {
            const p: *@This() = @fieldParentPtr("interface", po);

            p.mutex.lock();
            defer p.mutex.unlock();
            
            switch (p.state) {
                .Pending => {
                    p.result_value = err;
                    p.state = .Completed;
                    p.condition.broadcast();
                },
                .Completed => {},
                .Invalid => unreachable,
            }
        }

        pub fn timedout(po: *PromiseOpaque) void {

            const p: *Self = @fieldParentPtr("interface", po);

            p.mutex.lock();
            defer p.mutex.unlock();

            if (p.state != .Pending) @panic("Timeout received on non-pending promise! Connection or promise is corrupted.");
            p.state = .Completed;

            if (p.callback) |cb|
                cb(p, error.TimedOut, null, p.capture);

            p.condition.broadcast();
        }

        /// Sets up callbacks for promise. If promise is completed, calls callback immediately 
        pub fn setupCallback(p: *Self, cb: Callback, userdata: ?*anyopaque) void {
            p.mutex.lock();
            defer p.mutex.unlock();

            p.callback = cb;
            p.capture = userdata;

            switch (p.state) {
                .Invalid => unreachable,
                .Completed => cb(p, p.result_value.?, p.result_arena, p.capture),
                .Pending => {},
            }
        }

    };
}

pub const PromiseOpaque = struct {
    pub const VTable = struct {
        received: *const fn (po: *PromiseOpaque, m: Message, arena: *std.heap.ArenaAllocator) void,
        errored:  *const fn (po: *PromiseOpaque, err: DBusError) void,
        timedout: *const fn (po: *PromiseOpaque) void,

        reference: *const fn (po: *PromiseOpaque) *PromiseOpaque,
        release: *const fn (po: *PromiseOpaque) isize,
        destroy: *const fn (po: *PromiseOpaque) void,
    };

    vtable: *const VTable,
};

const deinitRecursive = @import("dbus_types.zig").deinitValueRecursive;
