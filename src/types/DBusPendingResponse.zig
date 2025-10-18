const std = @import("std");
const atomic = std.atomic;
const Condvar = std.Thread.Condition;
const Mutex = std.Thread.Mutex;

const dbuz = @import("../dbuz.zig");

const DBusMessage = dbuz.types.DBusMessage;
const DBusConnection = dbuz.types.DBusConnection;
const DBusError = dbuz.errors.DBusError;

const Self = @This();
pub const Feedback = union(enum) { call: struct { method_reply: *const fn (*anyopaque, *DBusMessage) anyerror!void, method_error: *const fn (*anyopaque, *DBusMessage) anyerror!void, timeout: ?*const fn (*anyopaque) anyerror!void = null, userdata: *anyopaque, signaled: bool = false }, store: ?*DBusMessage };

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
    timeout_ns: ?u64 = null,

    /// If true, feedback is .store and received message is an error, method will return DBusError.
    check_error: bool = true,
};

/// Waits until remote peer responds to the method call. If returns error if timeout reached, else it is guaranteed that handlers were executed.
///
/// Call from the dispatcher is not allowed.
pub fn wait(self: *Self, options: WaitOptions) (DBusError || error{ Timeout, DeadlockInDispatcher })!?*DBusMessage {
    if (self.conn.update_thread_id == std.Thread.getCurrentId()) return error.DeadlockInDispatcher;
    self.cv_mutex.lock();
    defer self.cv_mutex.unlock();

    switch (self.feedback) {
        .call => |handlers| {
            if (handlers.signaled) return null;
            try self.cv.timedWait(&self.cv_mutex, options.timeout_ns orelse self.conn.default_call_timeout);
        },
        .store => |msg| {
            if (msg) |v| {
                if (options.check_error) try checkError(v);
                return v;
            }
            try self.cv.timedWait(&self.cv_mutex, options.timeout_ns orelse self.conn.default_call_timeout);
            if (self.feedback.store) |v| {
                if (options.check_error) try checkError(v);
            }
            return self.feedback.store;
        },
    }
    return null;
}

fn checkError(msg: *DBusMessage) DBusError!void {
    if (msg.message_type != .ERROR) return;
    const err_name = msg.error_name orelse "Failed";

    const errors: []const std.meta.Tuple(&.{ []const u8, DBusError }) = &.{
        .{ "org.freedesktop.DBus.Error.Failed", DBusError.Failed },
        .{ "org.freedesktop.DBus.Error.NoMemory", DBusError.NoMemory },
        .{ "org.freedesktop.DBus.Error.ServiceUnknown", DBusError.ServiceUnknown },
        .{ "org.freedesktop.DBus.Error.NameHasNoOwner", DBusError.NameHasNoOwner },
        .{ "org.freedesktop.DBus.Error.NoReply", DBusError.NoReply },
        .{ "org.freedesktop.DBus.Error.Timeout", DBusError.Timeout },
        .{ "org.freedesktop.DBus.Error.LimitsExceeded", DBusError.LimitsExceeded },
        .{ "org.freedesktop.DBus.Error.AccessDenied", DBusError.AccessDenied },
        .{ "org.freedesktop.DBus.Error.InvalidArgs", DBusError.InvalidArgs },
        .{ "org.freedesktop.DBus.Error.UnknownMethod", DBusError.UnknownMethod },
        .{ "org.freedesktop.DBus.Error.UnknownObject", DBusError.UnknownObject },
        .{ "org.freedesktop.DBus.Error.UnknownInterface", DBusError.UnknownInterface },
        .{ "org.freedesktop.DBus.Error.UnknownProperty", DBusError.UnknownProperty },
        .{ "org.freedesktop.DBus.Error.PropertyReadOnly", DBusError.PropertyReadOnly },
        .{ "org.freedesktop.DBus.Error.MatchRuleNotFound", DBusError.MatchRuleNotFound },
        .{ "org.freedesktop.DBus.Error.MatchRuleInvalid", DBusError.MatchRuleInvalid },
        .{ "org.freedesktop.DBus.Error.InconsistentMessage", DBusError.InconsistentMessage },
        .{ "org.freedesktop.DBus.Error.InvalidSignature", DBusError.InvalidSignature },
        .{ "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired", DBusError.InteractiveAuthorizationRequired },
    };

    const map = std.StaticStringMap(DBusError).initComptime(errors);
    if (map.get(err_name)) |e| return e;
}

/// Posts message to pending response, then wakeups waiters
pub fn post(self: *Self, message: *DBusMessage) !void {
    self.cv_mutex.lock();
    defer self.cv_mutex.unlock();

    switch (self.feedback) {
        .call => |*handlers| {
            defer message.allocator.destroy(message);
            defer message.deinit();
            switch (message.message_type) {
                .METHOD_RETURN => handlers.method_reply(handlers.userdata, message) catch {},
                .ERROR => handlers.method_error(handlers.userdata, message) catch {},
                else => @panic("Unexpected message type in PendingResponse"),
            }
            handlers.signaled = true;
        },
        .store => {
            self.feedback.store = message;
        },
    }

    self.cv.broadcast();
}

/// Change the feedback type for the pending response.
/// If original feedback was .call it was already signaled, returns error.AlreadySignaled
/// If original feedback was .store and new feedback is .call, if message already posted, immediately calls handlers
pub fn changeFeedback(self: *Self, new_feedback: Feedback) error{AlreadySignaled}!void {
    self.cv_mutex.lock();
    defer self.cv_mutex.unlock();
    switch (self.feedback) {
        .call => |handlers| {
            if (handlers.signaled) return error.AlreadySignaled;
            self.feedback = new_feedback;
        },
        .store => |msg| {
            self.feedback = new_feedback;
            if (msg) |message| {
                switch (self.feedback) {
                    .call => |*handlers| {
                        defer message.allocator.destroy(message);
                        defer message.deinit();
                        switch (message.message_type) {
                            .METHOD_RETURN => handlers.method_reply(handlers.userdata, message) catch {},
                            .ERROR => handlers.method_error(handlers.userdata, message) catch {},
                            else => @panic("Unexpected message type in PendingResponse"),
                        }
                        handlers.signaled = true;
                    },
                    .store => {
                        self.feedback.store = message;
                    },
                }
            }
        },
    }
}

/// Signals that pending response has timed out
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
        else => {},
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
            else => {},
        }

        self.allocator.destroy(self);
    }
}
