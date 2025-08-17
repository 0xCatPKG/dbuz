const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const dbuz = @import("dbuz.zig");

fn waitOnFD(fd: std.posix.fd_t, timeout_ms: i32) !void {
    var poll_fds = [_]std.posix.pollfd {
        .{
            .fd = fd,
            .events = std.posix.POLL.IN | std.posix.POLL.HUP,
            .revents = 0,
        }
    };
    const evcnt = try std.posix.poll(&poll_fds, timeout_ms);
    if (evcnt == 0) return error.Timeout;
    if (poll_fds[0].revents & std.posix.POLL.HUP != 0) return error.Hangup;
    if (poll_fds[0].revents & std.posix.POLL.IN != 0) return;
    unreachable;
}

test "dbuz_singlethreaded_session_connect" {
    const conn = dbuz.connect(testing.allocator, .{
        .bus = .Session,
        .enable_introspection = false,
        .config = .{}
    }) catch |err| switch (err) {
        error.ConnectionLost => return err,
        else => return error.SkipZigTest,
    };
    defer conn.deinit();

    try waitOnFD(conn.getFd(), std.time.ms_per_s);
    try conn.update(false);
    try testing.expect(conn.unique_name != null);
}

test "dbus_multithreaded_session_connect" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const conn = dbuz.connect(testing.allocator, .{
        .bus = .Session,
        .enable_introspection = false,
        .config = .{}
    }) catch |err| switch (err) {
        error.ConnectionLost => return err,
        else => return error.SkipZigTest,
    };
    defer conn.deinit();

    const run_cond, const thread = try dbuz.spawnPollingThread(conn, testing.allocator);
    defer testing.allocator.destroy(run_cond);
    defer thread.join();
    defer run_cond.* = false;

    std.posix.nanosleep(0, std.time.ns_per_ms * 25);
    try testing.expect(conn.unique_name != null);
}

test "dbuz_singlethreaded_system_connect" {
    const conn = dbuz.connect(testing.allocator, .{
        .bus = .System,
        .enable_introspection = false,
        .config = .{}
    }) catch |err| switch (err) {
        error.ConnectionLost => return err,
        else => return error.SkipZigTest,
    };
    defer conn.deinit();

    try waitOnFD(conn.getFd(), std.time.ms_per_s);
    try conn.update(false);
    try testing.expect(conn.unique_name != null);
}

test "dbus_multithreaded_system_connect" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const conn = dbuz.connect(testing.allocator, .{
        .bus = .System,
        .enable_introspection = false,
        .config = .{}
    }) catch |err| switch (err) {
        error.ConnectionLost => return err,
        else => return error.SkipZigTest,
    };
    defer conn.deinit();

    const run_cond, const thread = try dbuz.spawnPollingThread(conn, testing.allocator);
    defer testing.allocator.destroy(run_cond);
    defer thread.join();
    defer run_cond.* = false;

    std.posix.nanosleep(0, std.time.ns_per_ms * 25);
    try testing.expect(conn.unique_name != null);

}

test "evaluate all" {
    testing.refAllDeclsRecursive(dbuz);
    return;
}
