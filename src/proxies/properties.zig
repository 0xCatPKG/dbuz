
pub fn Properties(comptime PropertiesStorage: type, comptime TypeUnion: type, comptime TypeEnum: type) type {
    const props_info = @typeInfo(PropertiesStorage).@"struct";
    return struct {
        const Self = @This();

        const PropertiesUnion = TypeUnion;
        const PropertiesEnum = TypeEnum;
        const Storage = PropertiesStorage;
        const Signals = struct {
            pub const PropertiesChanged = Signal(
                struct {
                    String,
                    Dict(String, PropertiesUnion),
                    []String
                },
                .{}
            );
        };

        interface: Proxy = .{
            .connection = null,
            .name = "org.freedesktop.DBus.Properties",
            .object_path = null,
            .vtable = &.{
                .handle_signal = &signal_handler,
                .destroy = &Proxy.noopDestroy,
            },
        },

        name: []const u8,
        path: []const u8,
        remote: []const u8,
        signals: SignalManager(Signals),
        properties: *Storage,

        allocator: std.mem.Allocator,

        fn signal_handler(p: *Proxy, m: *Message, gpa: std.mem.Allocator) !void {
            const s: *Self = @fieldParentPtr("interface", p);
            return s.signals.handle(m, gpa) catch error.HandlingFailed;
        }

        pub fn bind(s: *Self, c: *Connection, remote: []const u8, interface: []const u8, object_path: []const u8, prop_ptr: *Storage, gpa: std.mem.Allocator) !void {
            s.* = Self{
                .name = interface,
                .path = object_path,
                .remote = remote,
                .properties = prop_ptr,
                .signals = .init(.{
                    .PropertiesChanged = &properties_changed,
                    .userdata = s,
                }),
                .allocator = gpa,
            };
            s.interface.connection = c;
            s.interface.object_path = object_path;

            var unique_id: usize = undefined;

            const lp = try c.registerListenerAsync(
                s,
                .{
                    .interface = "org.freedesktop.DBus.Properties",
                    .path = object_path,
                    .args = &.{ interface },
                    .sender = remote,
                },
                &unique_id,
                gpa,
            );
            if (lp.release() == 1) lp.destroy();

            var get_all_call = try c.startMessage(gpa);
            defer get_all_call.deinit();

            get_all_call.type = .method_call;
            _ = get_all_call.setDestination(remote)
                        .setInterface("org.freedesktop.DBus.Properties")
                        .setPath(object_path)
                        .setMember("GetAll")
                        .setSignature("s");

            var w = get_all_call.writer();
            try w.write(String{ .value = interface });

            const promise = try c.trackResponse(get_all_call, Dict(String, PropertiesUnion));
            defer if (promise.release() == 1) promise.destroy();

            promise.setupCallbacks(.{
                .response = &get_all_response,
                .@"error" = &get_all_failed,
                .timeout = null
            }, s);

            try c.sendMessage(&get_all_call);
        }

        fn get_all_response(
            _: *Promise(Dict(String, PropertiesUnion)),
            response: Dict(String, PropertiesUnion),
            _: *std.heap.ArenaAllocator,
            userdata: ?*anyopaque,
        ) void {
            const s: *Self = @alignCast(@ptrCast(userdata));

            s.properties._mutex.lock();
            defer s.properties._mutex.unlock();

            var it = response.iterator();
            dict_loop: while (it.next()) |kv| {
                field_loop: inline for (props_info.fields) |field| {

                    const typesig = comptime guessSignature(field.type);

                    if (comptime std.mem.startsWith(u8, field.name, "_")) comptime continue :field_loop;
                    if (!std.mem.eql(u8, field.name, kv.key_ptr.value)) comptime continue :field_loop;
                    logger.warn("Setting field {s}:{s}", .{kv.key_ptr.value, field.name});
                    @field(s.properties.*, field.name) = dupeValue(s.allocator, @field(kv.value_ptr.*, typesig)) catch |err| {
                        std.debug.print("{s} at Properties proxy, attached to remote:{s}, interface:{s}, path:{s}", .{
                            @errorName(err),
                            s.remote,
                            s.name,
                            s.path,
                        });
                        continue :dict_loop;
                    };
                }
            }
            s.properties._inited = true;
        }

        fn get_all_failed(
            _: *Promise(Dict(String, PropertiesUnion)),
            err: PromiseError,
            userdata: ?*anyopaque
        ) void {
            const s: *Self = @alignCast(@ptrCast(userdata));
            logger.err("Properties(remote:{s}, interface:{s}, path:{s}).GetAll returned error: {s}", .{
                s.remote,
                s.name,
                s.path,
                err.message orelse @errorName(err.error_code)
            });
        }

        pub fn get(s: *Self, comptime property: PropertiesEnum) @FieldType(Storage, @tagName(property)) {
            s.properties._mutex.lock();
            defer s.properties._mutex.unlock();

            return @field(s.properties.*, @tagName(property));
        }

        pub fn set(
            s: *Self,
            comptime property: PropertiesEnum,
            v: anytype
        ) !void {
            var m = try s.interface.connection.?.startMessage(s.allocator);
            defer m.deinit();

            inline for (@typeInfo(Storage).@"struct".fields) |field| {
                if (!comptime std.mem.eql(u8, field.name, @tagName(property))) comptime continue;
                std.debug.assert(field.type == @TypeOf(v));
            }

            m.type = .method_call;
            _ = m.setDestination(s.remote)
             .setInterface("org.freedesktop.DBus.Properties")
             .setPath(s.path)
             .setMember("Set")
             .setSignature("ssv");

            const w = m.writer();
            try w.write(.{
                String{ .value = s.name },
                String{ .value = @tagName(property) },
                v
            });

            try s.interface.connection.?.sendMessage(&m);
        }

        fn properties_changed(interface_name: String, changed: Dict(String, PropertiesUnion), _: []String, userdata: ?*anyopaque) void {
            const s: *Self = @alignCast(@ptrCast(userdata));

            if (!std.mem.eql(u8, s.name, interface_name.value)) return;

            s.properties._mutex.lock();
            defer s.properties._mutex.unlock();

            if (!s.properties._inited) return;

            var it = changed.iterator();
            dict_loop: while (it.next()) |kv| {
                field_loop: inline for (props_info.fields) |field| {
                    const typesig = comptime guessSignature(field.type);

                    if (comptime std.mem.startsWith(u8, field.name, "_")) comptime continue :field_loop;
                    if (!std.mem.eql(u8, field.name, kv.key_ptr.value)) comptime continue :field_loop;

                    deinitValue(s.allocator, @field(s.properties.*, field.name));
                    @field(s.properties.*, field.name) = dupeValue(s.allocator, @field(kv.value_ptr.*, typesig)) catch continue :dict_loop;
                }
            }
        }
    };
}


const std = @import("std");
const dbuz = @import("../dbuz.zig");

const dupeValue = @import("../types/dbus_types.zig").dupeValue;
const deinitValue = @import("../types/dbus_types.zig").deinitValueRecursive;
const guessSignature = @import("../types/dbus_types.zig").guessSignature;

const String = dbuz.types.String;

const Proxy = dbuz.types.Proxy;
const Message = dbuz.types.Message;
const Connection = dbuz.types.Connection;

const Signal = dbuz.types.Signal;
const SignalManager = dbuz.types.SignalManager;
const Dict = dbuz.types.Dict;

const Promise = dbuz.types.Promise;
const PromiseError = dbuz.types.PromiseError;

const logger = std.log.scoped(.Properties);
