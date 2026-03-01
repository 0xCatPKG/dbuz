const std = @import("std");
const testing = std.testing;
const net = std.net;

const dbuz = @import("dbuz.zig");
const transport = dbuz.transport;
const sasl = dbuz.auth;
const Message = dbuz.types.Message;
const Connection = dbuz.types.Connection;
const Interface = dbuz.types.Interface;

test "DBus Hello" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const conn = try dbuz.connect(allocator, .Session);
    defer conn.deinit();

    var cond: bool = false;
    const looper_thread = try dbuz.spawnLooperThread(testing.allocator, conn, &cond);

    try conn.hello();
    cond = true;

    looper_thread.join();
}

test "org.freedesktop.DBus get name test" {
    const alloc = testing.allocator;

    std.debug.print("Start of listener test!\n", .{});
    
    const conn = try dbuz.connect(alloc, .Session);
    defer conn.deinit();

    var exit_cond: bool = false;
    const looper_thread = try dbuz.spawnLooperThread(alloc, conn, &exit_cond);

    errdefer exit_cond = true;

    try conn.hello();

    const name_promise = try conn.dbus.RequestName("org.example.DBuzTest", .{.allow_replacement = true, .replace = true});
    defer if (name_promise.release() == 1) name_promise.destroy();
    const name_res, _ = try name_promise.wait(1 * std.time.ns_per_s);

    switch (name_res) {
        .response => |r| {
            try testing.expect(r == .primary_owner);
            exit_cond = true;
        },
        .@"error" => |e| return e.error_code
    }

    exit_cond = true;

    looper_thread.join();
}


