const std = @import("std");
const testing = std.testing;
const net = std.net;

const dbuz = @import("dbuz.zig");
const transport = dbuz.transport;
const sasl = dbuz.auth;
const Message = dbuz.types.Message;
const Connection = dbuz.types.Connection;
const Interface = dbuz.types.Interface;

fn name_owner_changed(name: dbuz.types.String, old_owner: dbuz.types.String, new_owner: dbuz.types.String, _: ?*anyopaque) void {
    std.debug.print("Name owner of \"{s}\" changed: {s} -> {s}\n", .{name.value, old_owner.value, new_owner.value});
}

test "DBus Hello" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const conn = try dbuz.connect(allocator, .Session);
    defer conn.deinit();

    var cond: bool = false;
    const looper_thread = try dbuz.spawnLooperThread(testing.allocator, conn, &cond);

    try conn.hello();
    std.debug.print("Bus unique name: {s}\n", .{conn.unique_name.?});
    cond = true;

    // const MyInterface = Interface.AutoInterface(struct {
    //     pub const interface_name: []const u8 = "my.system.Root";
    //
    //     pub const Echo = dbuz.types.Method(m_echo, .{ .argument_names = &.{ "text" }, .argument_types = &.{ null } });
    //     pub const Add = dbuz.types.Method(m_add, .{ .argument_names = &.{ "a", "b" }, .argument_types = &.{ null, null } });
    //     pub const Fail = dbuz.types.Method(m_fail, .{});
    //     pub const Void = dbuz.types.Method(m_void, .{});
    //     pub const SSH = dbuz.types.Method(ryr, .{});
    //
    //     pub const RequestName = dbuz.types.Method(req_name, .{});
    //
    //     pub const version = dbuz.types.Property(u32, &1, .{});
    //     pub const somestr = dbuz.types.Property(dbuz.types.String, null, .{ .mode = .Read });
    //
    //     pub const SignalX = dbuz.types.Signal(struct {}, .{});
    //     pub const SingalY = dbuz.types.Signal(u32, .{});
    //
    //     conn: *Connection = undefined,
    //
    //     fn m_echo(_: *@This(), msg: dbuz.types.String) dbuz.types.String {
    //         return msg;
    //     }
    //
    //     fn m_add(_: *@This(), a: i32, b: i32) i32 {
    //         return a + b;
    //     }
    //
    //     fn @"m_fail"(_: *@This()) !void {
    //         return error.Fucked;
    //     }
    //
    //     fn @"m_void"(_: *@This()) void {
    //         // do nothing
    //         std.debug.print("A\n", .{});
    //     }
    //
    //     fn ryr(_: *@This()) !void {
    //         return error.Unhandled;
    //     }
    //
    //     fn req_name(self: *@This(), name: dbuz.types.String) !void {
    //         const promise = try self.conn.dbus.RequestName(name.value, .{});
    //         if (promise.release() == 1) promise.destroy();
    //     }
    //
    //
    // }, null);
    //
    // try conn.dbus.NameOwnerChanged.subscribe(&name_owner_changed, null, .Persistent);
    //
    // const iface_impl = try MyInterface.create(allocator);
    // iface_impl.data.conn = conn;
    // iface_impl.properties = .{
    //     .somestr = .{ .value = "hui" }
    // };
    // try conn.registerInterface(iface_impl, "/org/example/MyObject", allocator);
    // defer _ = conn.unregisterInterface(iface_impl, "/org/example/MyObject");
    // defer if (iface_impl.interface.release() == 1) iface_impl.interface.deinit(allocator);
    looper_thread.join();
}

// test "Test Factory" {
//     const gpa = testing.allocator;
//     const MyInterface = Interface.AutoInterface(struct {
//         pub const interface_name: []const u8 = "my.system.SSH";
//
//         pub const Echo = dbuz.types.Method(m_echo);
//         pub const Add = dbuz.types.Method(m_add);
//         pub const Fail = dbuz.types.Method(m_fail);
//         pub const Void = dbuz.types.Method(m_void);
//         pub const Root = dbuz.types.Method(ryr);
//
//         pub const version = dbuz.types.Property(u32, &1, .ReadWrite);
//         pub const somestr = dbuz.types.Property(dbuz.types.String, null, .Read);
//
//         fn m_echo(_: *@This(), msg: dbuz.types.String) dbuz.types.String {
//             return msg;
//         }
//
//         fn m_add(_: *@This(), a: i32, b: i32) i32 {
//             return a + b;
//         }
//
//         fn @"m_fail"(_: *@This()) !void {
//             return error.Fucked;
//         }
//
//         fn @"m_void"(_: *@This()) void {
//             // do nothing
//         }
//
//         fn ryr(_: *@This()) !void {
//             return error.@"ыыр кщще";
//         }
//
//     }, null);
//
//     var obj = try MyInterface.create(gpa);
//     if (obj.interface.release() == 1) {
//         obj.interface.deinit(gpa);
//     }
// }

