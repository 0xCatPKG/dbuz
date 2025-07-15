const std = @import("std");
const atomic = std.atomic;
const Condvar = std.Thread.Condition;
const Mutex = std.Thread.Mutex;

const DBusMessage = @import("DBusMessage.zig");
const DBusConnection = @import("DBusConnection.zig");

const Self = @This();
pub const Feedback = union (enum) {
    call: struct {
        method_reply: *const fn(*anyopaque, *DBusMessage) anyerror!void,
        method_error: *const fn(*anyopaque, *DBusMessage) anyerror!void,
        timeout: ?*const fn(*anyopaque) anyerror!void = null,

        userdata: *anyopaque,
        signaled: bool = false
    },
    store: ?*DBusMessage
};

allocator: std.mem.Allocator,

cv: Condvar = .{},
cv_mutex: Mutex = .{},

conn: *DBusConnection,
serial: u32,

feedback: Feedback,
refcounter: atomic.Value(u32),

pub fn init(conn: *DBusConnection, serial: u32, feedback: Feedback, allocator: std.mem.Allocator) !*Self {
    const self = try allocator.create(Self);
    self.* = .{ .conn = conn, .serial = serial, .feedback = feedback, .refcounter = .init(1), .allocator = allocator };
    return self;
}

const WaitOptions = struct {
    timeout_ns: ?u64 = null
};

/// Waits until remote peer responds to the method call. If returns error if timeout reached, else it is guaranteed that handlers were executed.
///
/// Call from the dispatcher is not allowed.
pub fn wait(self: *Self, options: WaitOptions) error{Timeout, DeadlockInDispatcher}!?*DBusMessage {
    if (self.conn.update_thread_id == std.Thread.getCurrentId()) return error.DeadlockInDispatcher;
    self.cv_mutex.lock();
    defer self.cv_mutex.unlock();

    switch (self.feedback) {
        .call => |handlers| {
            if (handlers.signaled) return null;
            try self.cv.timedWait(&self.cv_mutex, options.timeout_ns orelse self.conn.default_call_timeout);
        },
        .store => |msg| {
            if (msg) |v| return v;
            try self.cv.timedWait(&self.cv_mutex, options.timeout_ns orelse self.conn.default_call_timeout);
            return self.feedback.store;
        }
    }
    return null;
}

pub fn post(self: *Self, message: *DBusMessage) !void {
    self.cv_mutex.lock();
    defer self.cv_mutex.unlock();

    switch(self.feedback) {
        .call => |*handlers| {
            defer message.allocator.destroy(message);
            defer message.deinit();
            switch (message.message_type) {
                .METHOD_RETURN => handlers.method_reply(handlers.userdata, message) catch {},
                .ERROR => handlers.method_error(handlers.userdata, message) catch {},
                else => @panic("Unexpected message type in PendingResponse")
            }
            handlers.signaled = true;
        },
        .store => {
            self.feedback.store = message;
        }
    }

    self.cv.broadcast();
}

pub fn timeout(self: *Self) !void {
    self.cv_mutex.lock();
    defer self.cv_mutex.unlock();
    switch (self.feedback) {
        .call => |*handlers| {
            if (handlers.timeout) |timeout_handler| {
                try timeout_handler(handlers.userdata);
            }
            handlers.signaled = true;
        },
        else => {}
    }
    self.cv.broadcast();
}

pub fn deinit(self: *Self) void {
    const refs = self.refcounter.fetchSub(1, .release);
    if (refs == 1) {
        self.conn.clearPendingResponse(self.serial);
        switch (self.feedback) {
            .store => |msg| {
                if (msg != null) {
                    const allocator = msg.?.allocator;

                    msg.?.deinit();
                    allocator.destroy(msg.?);
                }
            },
            else => {}
        }

        self.allocator.destroy(self);
    }
}
