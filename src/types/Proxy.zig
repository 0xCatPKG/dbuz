
const Proxy = @This();

const std = @import("std");
const mem = std.mem;
const atomic = std.atomic;

const dbuz = @import("../dbuz.zig");
const types = @import("dbus_types.zig");

const Connection = dbuz.types.Connection;
const Message = dbuz.types.Message;

pub const Error = error{OutOfMemory, HandlingFailed};

pub const VTable = struct {
    handle_signal: *const fn (p: *Proxy, m: *Message, gpa: mem.Allocator) Error!void,

    destroy: *const fn (p: *Proxy, gpa: mem.Allocator) void,
};

name: []const u8,
object_path: ?[]const u8,
connection: ?*Connection,

vtable: *const VTable,

refcounter: atomic.Value(isize) = .init(1),

pub fn reference(p: *Proxy) *Proxy {
    _ = p.refcounter.fetchAdd(1, .seq_cst);
    return p;
}

pub fn release(p: *Proxy) isize {
    return p.refcounter.fetchSub(1, .seq_cst);
}

pub fn destroy(p: *Proxy, gpa: mem.Allocator) void {
    p.vtable.destroy(p, gpa);
}

pub fn handleSignal(p: *Proxy, m: *Message, gpa: mem.Allocator) Error!void {
    return p.vtable.handle_signal(p, m, gpa);
}
