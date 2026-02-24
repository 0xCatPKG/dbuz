
const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const atomic = std.atomic;

const Thread = std.Thread;

const dbuz = @import("../dbuz.zig");
const Message = dbuz.types.Message;

const isTypeSerializable = @import("dbus_types.zig").isTypeSerializable;

const State = enum {
Pending,
    Completed,
    Invalid,
};

pub const ErrorData = struct {
    message: ?[]const u8,
    error_code: error{Failed},
};

pub fn Promise(comptime T: type) type {
    if (T != Message and !isTypeSerializable(T) and T != void) @compileError(std.fmt.comptimePrint("Unable to construct promise type from {s}: T must be Message or be DBus-serializable type", .{@typeName(T)}));
    return struct {
        pub const Storage = union (enum) {
            response: T,
            @"error": ErrorData,

            pub fn toValue(s: *Storage) Value {
                if (T != Message) return s.*
                else return switch (s) {
                    .response => Value{.response = &s.response},
                    .@"error" => Value{.@"error" = s.@"error"},
                };
            }
        };
        pub const Value = if (T == Message) union (enum) {
            response: *T,
            @"error": ErrorData,
        } else Storage;
        const Self = @This();

        state: State = .Pending,

        condition: Thread.Condition = .{},
        mutex: Thread.Mutex = .{},

        result: ?Storage = null,
        result_arena: ?*std.heap.ArenaAllocator = null,

        callbacks: ?PromiseCallbacks = null,
        capture: ?*anyopaque = null,

        refcounter: atomic.Value(isize) = .init(0),
        deadline_fd: ?posix.fd_t = null,

        allocator: mem.Allocator,

        interface: PromiseOpaque = .{
            .vtable = &.{
                .received = &received,
                .timedout = &timedout,
                .reference = &vtable_reference,
                .release = &vtable_release,
                .destroy = &vtable_destroy,
            },
        },

        pub const PromiseCallbacks = struct {
            response: *const fn (p: *Self, result: if (T == Message) *T else T, arena: *std.heap.ArenaAllocator, user_data: ?*anyopaque) void,
            @"error": *const fn (p: *Self, cause: ErrorData, user_data: ?*anyopaque) void,
            timeout: ?*const fn (p: *Self, user_data: ?*anyopaque) void,
        };

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

        pub fn release(p: *@This()) isize {
            return p.refcounter.fetchSub(1, .seq_cst);
        }

        fn vtable_release(po: *PromiseOpaque) isize {
            return @as(*@This(), @fieldParentPtr("interface", po)).release();
        }

        pub fn destroy(p: *@This()) void {
            p.mutex.lock();
            switch (p.state) {
                .Completed => {
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

        pub fn wait(p: *@This(), timeout_ns: ?u64) !struct {Value, *std.heap.ArenaAllocator} {
            p.mutex.lock();
            defer p.mutex.unlock();

            state: switch (p.state) {
                .Completed => {
                    if (p.result == null) return error.TimedOut;
                    return .{p.result.?.toValue(), p.result_arena.?};
                },
                .Pending => {
                    try p.condition.timedWait(&p.mutex, timeout_ns orelse 90 * std.time.ns_per_s);
                    continue :state p.state;
                },
                .Invalid => unreachable,
            }
            unreachable;
        }

        pub fn received(po: *PromiseOpaque, message: Message, arena: *std.heap.ArenaAllocator) void {

            const p: *@This() = @fieldParentPtr("interface", po);

            p.mutex.lock();
            defer p.mutex.unlock();

            if (p.state != .Pending) @panic("Message received on non-pending promise! Connection or promise is corrupted.");
            p.result_arena = arena;
            var m = message;
            p.result = switch (m.type) {
                .@"error" => e: {
                    if (m.fields.signature) |signature| {
                        if (signature[0] == 's') {
                            const message_reader = m.reader() catch break :e Storage{.@"error" = .{
                                .error_code = error.Failed,
                                .message = "Unable to read error from message: Reader creation failed",
                            }};
                            const error_message = message_reader.read(dbuz.types.String, arena.allocator()) catch break :e Storage{.@"error" = .{
                                .message = "Failed to read error from message: Reading failed",
                                .error_code = error.Failed,
                            }};
                        break :e Storage{.@"error" = .{
                                .error_code = error.Failed,
                                .message = error_message.value,
                            }};
                        }
                    } else break :e Storage{.@"error" = .{ .error_code = error.Failed, .message = null }};
                    unreachable;
                },
                .method_response => r: {
                    if (T == Message) {
                        break :r Storage{.response = m };
                    } else {
                        const message_reader = m.reader() catch break :r Storage{.@"error" = .{
                            .error_code = error.Failed,
                            .message = "Unable to read error from message: Reader creation failed",
                        }};
                        const values = message_reader.read(T, arena.allocator()) catch break :r Storage{ .@"error" = .{
                            .error_code = error.Failed,
                            .message = "Unable to read message: Reading failed",
                        }};
                        break :r Storage{.response = values};
                    }
                },
                else => unreachable,
            };

            if (p.callbacks) |cbs| {
                switch (p.result.?) {
                    .response => |v| cbs.response(p, v, p.result_arena.?, p.capture),
                    .@"error" => |e| cbs.@"error"(p, e, p.capture),
                }
            }

            p.state = .Completed;
            p.condition.broadcast();
        }

        pub fn timedout(po: *PromiseOpaque) void {

            const p: *@This() = @fieldParentPtr("interface", po);

            p.mutex.lock();
            defer p.mutex.unlock();

            if (p.state != .Pending) @panic("Timeout received on non-pending promise! Connection or promise is corrupted.");
            p.deadline_fd = null;
            p.state = .Completed;
            
            if (p.callbacks) |cbs| {
                if (cbs.timeout) |timeout| timeout(p, p.capture);
            }

            p.condition.broadcast();
        }

        pub fn setDeadline(p: *@This(), timeout_ns: u64) !posix.fd_t {
            const timerfd = try posix.timerfd_create(.REALTIME, .{ .NONBLOCK = true, .CLOEXEC = true });
            errdefer posix.close(timerfd);

            try posix.timerfd_settime(timerfd, .{}, &posix.system.itimerspec{
                .it_value = .{ .nsec = timeout_ns, .sec = 0 },
                .it_interval = .{ .nsec = 0, .sec = 0 },
            }, null);
            p.deadline_fd = timerfd;
            return timerfd;
        }

        pub fn setupCallbacks(p: *@This(), cbs: PromiseCallbacks, user_data: ?*anyopaque) void {
            p.callbacks = cbs;
            p.capture = user_data;
        }

    };
}

pub const PromiseOpaque = struct {
    pub const VTable = struct {
        received: *const fn (po: *PromiseOpaque, m: Message, arena: *std.heap.ArenaAllocator) void,
        timedout: *const fn (po: *PromiseOpaque) void,

        reference: *const fn (po: *PromiseOpaque) *PromiseOpaque,
        release: *const fn (po: *PromiseOpaque) isize,
        destroy: *const fn (po: *PromiseOpaque) void,
    };

    vtable: *const VTable,
};
