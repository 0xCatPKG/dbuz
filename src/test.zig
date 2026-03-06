const std = @import("std");
const testing = std.testing;
const net = std.net;

const dbuz = @import("dbuz");
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

    const looper_thread = try dbuz.spawnLooperThread(testing.allocator, conn);

    try conn.hello();
    conn.disconnect();

    looper_thread.join();
}

// test "org.freedesktop.DBus get name test" {
//     const alloc = testing.allocator;
//
//     std.debug.print("Start of listener test!\n", .{});
//
//     const conn = try dbuz.connect(alloc, .Session);
//     defer conn.deinit();
//
//     var exit_cond: bool = false;
//     const looper_thread = try dbuz.spawnLooperThread(alloc, conn, &exit_cond);
//
//     errdefer exit_cond = true;
//
//     try conn.hello();
//
//     const name_promise = try conn.dbus.RequestName("org.example.DBuzTest", .{.allow_replacement = true, .replace = true});
//     defer if (name_promise.release() == 1) name_promise.destroy();
//     const name_res, _ = try name_promise.wait(1 * std.time.ns_per_s);
//
//     switch (name_res) {
//         .response => |r| {
//             try testing.expect(r == .primary_owner);
//             exit_cond = true;
//         },
//         .@"error" => |e| return e.error_code
//     }
//
//     exit_cond = true;
//
//     looper_thread.join();
// }


test "homemade proxy" {
    const alloc = testing.allocator;

    const conn = try dbuz.connect(alloc, .Session);
    defer conn.deinit();

    const looper_thread = try dbuz.spawnLooperThread(alloc, conn);

    try conn.hello();

    const Properties = struct {
        pub const activeEffects = dbuz.types.Property([]dbuz.types.String, &@as([]dbuz.types.String, &.{}), .{ .mode = .Read });
        pub const listOfEffects = dbuz.types.Property([]dbuz.types.String, &@as([]dbuz.types.String, &.{}), .{ .mode = .Read });
        pub const loadedEffects = dbuz.types.Property([]dbuz.types.String, &@as([]dbuz.types.String, &.{}), .{ .mode = .Read });
    };
    const PropertyStorage, const PropertyUnion, const PropertyEnum = dbuz.types.PropertyStorage(Properties);

    const Proxy = struct {
        const PropStorage = PropertyStorage;
        const PropUnion = PropertyUnion;
        const PropEnum = PropertyEnum;

        interface: dbuz.types.Proxy = .{
            .connection = null,
            .name = "org.kde.kwin.Effects",
            .object_path = null,
            .vtable = &.{
                .handle_signal = &dbuz.types.Proxy.noopSignalHandler,
                .destroy = &deinit,
            },
        },
        properties: PropStorage = .{},
        properties_iface: dbuz.proxies.Properties(PropStorage, PropUnion, PropEnum) = undefined,

        pub fn bind(p: *@This(), c: *Connection, remote: []const u8, object_path: []const u8, gpa: std.mem.Allocator) !void {
            p.interface.connection = c;
            p.interface.object_path = object_path;
            p.properties = .{};
            try p.properties_iface.bind(c, remote, "org.kde.kwin.Effects", object_path, &p.properties, gpa);
        }

        pub fn deinit(p: *dbuz.types.Proxy, gpa: std.mem.Allocator) void {
            const s: *@This() = @fieldParentPtr("interface", p);

            if (!s.properties._inited) return;
            s.properties._mutex.lock();
            defer s.properties._mutex.unlock();

            const st_info = @typeInfo(PropStorage).@"struct";
            inline for (st_info.fields) |field| {
                if (comptime std.mem.startsWith(u8, field.name, "_")) comptime continue;
                dbuz.utils.deinitValue(gpa, @field(s.properties, field.name));
            }
        }
    };

    testing.refAllDeclsRecursive(Proxy);

    var proxy: Proxy = undefined;
    try proxy.bind(conn, "org.kde.KWin", "/Effects", alloc);

    std.posix.nanosleep(1, 0);

    for (proxy.properties.activeEffects) |effect| {
        std.debug.print("Active Effect: {s}\n", .{effect.value});
    }
    for (proxy.properties.loadedEffects) |effect| {
        std.debug.print("Loaded Effect: {s}\n", .{effect.value});
    }
    for (proxy.properties.listOfEffects) |effect| {
        std.debug.print("Listed Effect: {s}\n", .{effect.value});
    }
    conn.disconnect();

    Proxy.deinit(&proxy.interface, alloc);

    looper_thread.join();
}

test "Introspectable" {
    const alloc = testing.allocator;

    const conn = try dbuz.connect(alloc, .Session);
    defer conn.deinit();

    const looper_thread = try dbuz.spawnLooperThread(alloc, conn);

    try conn.hello();

    const Introspectable = dbuz.proxies.Introspectable;

    const promise = try Introspectable.Introspect(
        conn,
        alloc,
        "org.unifiedpush.Distributor.kde",
        "/org/unifiedpush/Distributor"
    );
    defer if (promise.release() == 1) promise.destroy();

    const value, _ = try promise.wait(null);
    const intropsection = try value;
    const kde_distributor = intropsection.doc.node;

    try testing.expect(kde_distributor.implementsInterface("org.unifiedpush.Distributor2"));
    try testing.expect(!kde_distributor.implementsInterface("org.unifiedpush.Distributor3"));

    conn.disconnect();
    looper_thread.join();
}

test "recursive_decl" {
    testing.refAllDeclsRecursive(dbuz);
}
