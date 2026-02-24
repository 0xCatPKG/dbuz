
const Interface = @This();

const std = @import("std");
const mem = std.mem;
const atomic = std.atomic;

const dbuz  = @import("../dbuz.zig");
const types = @import("dbus_types.zig");

const Connection = dbuz.types.Connection;
const Message    = dbuz.types.Message;

const BuiltinType = std.builtin.Type;

name:        []const u8,
description: []const u8,

connection:  ?*Connection = null,
object_path: ?[]const u8 = null,

vtable: *const VTable,
refcounter: atomic.Value(isize) = .init(1),

pub const Error = error {
    HandlingFailed,
};

pub const VTable = struct {
    method_call: ?*const fn (i: *Interface, message: *Message, allocator: mem.Allocator) Error!?Message,
    property_op: ?*const fn (i: *Interface, message: *Message, allocator: mem.Allocator) Error!?Message,
    signal: ?*const fn (i: *Interface, message: *Message, allocator: mem.Allocator) Error!void,

    destroy: *const fn (i: *Interface, allocator: mem.Allocator) void,
};

pub fn AutoInterface(comptime T: type, comptime desc: ?*const []const u8) type {
    if (!comptime @hasDecl(T, "interface_name"))
    @compileError("Unable to create Interface from " ++ @typeName(T) ++ ": interface prototype missing interface_name declaration");
    if (@TypeOf(T.interface_name) != []const u8)
    @compileError("Unable to create Interface from " ++ @typeName(T) ++ ": interface_name is not of type []const u8 (got " ++ @typeName(@TypeOf(T.interface_name)) ++ " instead)");

    const name = @field(T, "interface_name");
    const description = desc orelse types.introspect(T);

    const methods = methodList(T);
    const properties = propertyList(T);
    const signals = signalList(T);

    const Properties, const TypeUnion = PropertiesStorage(T);

    var enum_names: []const BuiltinType.EnumField = &.{};
    inline for (signals, 0..) |signal_name, i| {
        enum_names = enum_names ++ .{ BuiltinType.EnumField{ .name = signal_name, .value = i } };
    }

    const SignalNamesT = @Type(.{
        .@"enum" = .{
            .fields = enum_names,
            .decls = &.{},
            .is_exhaustive = true,
            .tag_type = u32,
        }
    });

    const Impl = struct {
        const Template = T;
        pub const PropertiesType = Properties;
        pub const PropertiesUnion = TypeUnion;
        pub const SignalNames = SignalNamesT;

        pub const interface_name = name;


        data: Template = .{},
        properties: Properties = undefined,
        interface: Interface = .{
            .name = name,
            .description = description,
            .vtable = &.{
                .method_call = method_call,
                .property_op = property_op,
                .signal = null,

                .destroy = destroy,
            },
        },

        pub fn emitSignal(impl: *@This(), signal_name: SignalNames, value: anyopaque, gpa: std.mem.Allocator) !void {

            const v = switch (@typeInfo(@TypeOf(value))) {
                .@"struct" => |st| if (!st.is_tuple) .{value} else value,
                else => value,
            };

            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();

            switch (signal_name) {
                inline else => |sn| {
                    if (!std.mem.eql(u8,types.guessSignature(v), types.getSignature(@field(Template, @tagName(sn).Signature)).?)) unreachable;
                    var sig = try impl.interface.connection.?.startMessage();
                    defer sig.deinit();

                    sig.type = .signal;
                    sig.setInterface(Template.interface_name)
                       .setPath(impl.interface.object_path.?)
                       .setMember(@tagName(sn))
                       .setSignature(types.guessSignature(v));

                    var w = sig.writer();
                    try w.write(v);

                    try impl.interface.connection.?.sendMessage(&sig);
                    return;
                }
            }
            unreachable;
        }

        fn method_call(iface: *Interface, message: *Message, allocator: mem.Allocator) Error!?Message {
            const impl: *@This() = @fieldParentPtr("interface", iface);
            inline for (methods) |method_name| {
                if (!mem.eql(u8, method_name, message.fields.member.?)) comptime continue;

                const Method = @field(Template, method_name);
                
                var reader = message.reader() catch return error.HandlingFailed;
                const args = reader.read(Method.Arguments, allocator) catch return error.HandlingFailed;
                const params = .{&impl.data} ++ args;

                const rt_info = @typeInfo(Method.ReturnType);
                const rval = ret: switch (rt_info) {
                    .error_union => |eu| {
                        const result = @call(.auto, Method.@"fn", params);
                        const res_data: eu.payload = result catch |err| {
                            var error_return = iface.connection.?.startMessage() catch return error.HandlingFailed;
                            error_return.type = .@"error";
                            error_return.fields = .{
                                .destination = message.fields.sender,
                                .reply_serial = message.serial,
                                .error_name = std.fmt.allocPrint(allocator, "{s}.Error.{s}", .{ iface.name, @errorName(err) }) catch return error.HandlingFailed,
                                .signature = "s"
                            };
                            const w = error_return.writer();
                            w.write(types.String{.value = "ыыр кщще"}) catch unreachable;
                            return error_return;
                        };
                        break :ret res_data;
                    },
                    else => @call(.auto, Method.@"fn", params),
                };

                if (message.flags.no_reply_expected) return null;
                var response = iface.connection.?.startMessage() catch return error.HandlingFailed;
                response.type = .method_response;
                response.fields = .{
                    .destination = message.fields.sender,
                    .reply_serial = message.serial,
                    .signature = types.getSignature(rval),
                };
                const w = response.writer();
                w.write(rval) catch return error.HandlingFailed;
                return response;
            }

            var unhandled = iface.connection.?.startMessage() catch return error.HandlingFailed;
            unhandled.type = .@"error";
            unhandled.fields = .{
                .destination = message.fields.sender,
                .reply_serial = message.serial,
                .error_name = "org.freedesktop.DBus.Error.UnknownMethod",
            };
            return unhandled;
        }

        fn property_op(iface: *Interface, message: *Message, allocator: mem.Allocator) Error!?Message {
            const impl: *@This() = @fieldParentPtr("interface", iface);

            const Op = enum(u32) {
                GetAll,
                Get,
                Set,
                NoOp,
            };

            const op: Op =
                if (mem.eql(u8, message.fields.member.?, "GetAll")) .GetAll
                else if (mem.eql(u8, message.fields.member.?, "Get")) .Get
                else if (mem.eql(u8, message.fields.member.?, "Set")) .Set
                else .NoOp;

            var reply = iface.connection.?.startMessage() catch return error.HandlingFailed;
            reply.type = .method_response;
            reply.fields = .{
                .destination = message.fields.sender,
                .reply_serial = message.serial
            };

            switch (op) {
                .GetAll => {
                    const ReplyDict = types.Dictionary(types.String, PropertiesUnion);

                    var values = ReplyDict.init(allocator);
                    inline for (properties) |property_name| {
                        if (@field(Template, property_name).mode == .Write) comptime continue;
                        values.put( .{ .value = property_name, .ownership = false }, 
                        @unionInit(PropertiesUnion, property_name, @field(impl.properties, property_name)) ) catch return error.HandlingFailed;
                    }

                    const w = reply.writer();
                    w.write(values) catch return error.HandlingFailed;
                    return reply;
                },
                .Get, .Set => {
                    const r = message.reader() catch unreachable;
                    const req = r.read(types.String, allocator) catch return error.HandlingFailed;
                    inline for (properties) |property_name| {
                        if (!mem.eql(u8, req.value, property_name)) comptime continue;
                        const mode = @field(Template, property_name).mode;
                        if (op == .Set) {
                            if (mode == .Read) {
                                reply.type = .@"error";
                                reply.fields.error_name = allocator.dupe(u8, "org.freedesktop.DBus.Properties.PropertyReadOnly") catch return error.HandlingFailed;
                                reply.fields.signature = "s";
                                const w = reply.writer();
                                w.write(types.String{
                                    .value = std.fmt.comptimePrint("Property named {s} is a read-only property.", .{property_name}),
                                }) catch return error.HandlingFailed;
                                return reply;
                            }
                            const value = (r.read(union (enum) {
                                    v: @FieldType(PropertiesType, property_name),
                                },
                                allocator
                            ) catch return error.HandlingFailed).v;
                            @field(impl.properties, property_name) = value;
                            return reply;
                        } else {
                            if (mode == .Write) {
                                reply.type = .@"error";
                                reply.fields.error_name = allocator.dupe(u8, "org.freedesktop.DBus.Properties.PropertyWriteOnly") catch return error.HandlingFailed;
                                reply.fields.signature = "s";
                                const w = reply.writer();
                                w.write(types.String{
                                    .value = std.fmt.comptimePrint("Property named {s} is a write-only property.", .{property_name}),
                                }) catch return error.HandlingFailed;
                                return reply;
                            }

                            const w = reply.writer();
                            const ValueUnion = union(enum) {
                                v: @FieldType(PropertiesType, property_name),
                            };
                            w.write(ValueUnion{.v = @field(impl.properties, property_name)}) catch return error.HandlingFailed;
                            reply.fields.signature = "v";
                            return reply;
                        }
                    }
                    var unhandled = iface.connection.?.startMessage() catch return error.HandlingFailed;
                    unhandled.type = .@"error";
                    unhandled.fields = .{
                        .destination = message.fields.sender,
                        .reply_serial = message.serial,
                        .error_name = "org.freedesktop.DBus.Error.UnknownProperty",
                    };
                    return unhandled;

                },
                else => {
                    var unhandled = iface.connection.?.startMessage() catch return error.HandlingFailed;
                    unhandled.type = .@"error";
                    unhandled.fields = .{
                        .destination = message.fields.sender,
                        .reply_serial = message.serial,
                        .error_name = "org.freedesktop.DBus.Error.UnknownMethod",
                    };
                    return unhandled;
                },
            }
            unreachable;
        }
        
        pub fn create(allocator: mem.Allocator) error{OutOfMemory}!*@This() {
            const impl = try allocator.create(@This());
            impl.* = @This(){};

            // We pass interface pointer to init, so downstream implementation gets some pointer of known type.
            // This is useful for some cases that piss me off (like for example org.freedesktop.DBus.Properties,
            // that requires or hardcoding implementation into library, or some way to get connection's state)
            if (std.meta.hasMethod(Template, "init")) try impl.data.init(&impl.interface, allocator);

            return impl;
        }

        pub fn destroy(i: *Interface, allocator: mem.Allocator) void {
            const impl: *@This() = @fieldParentPtr("interface", i);
            // We might want to free some resources here (for example if we taken reference to interface, we release it here)
            if (std.meta.hasMethod(Template, "deinit")) impl.data.deinit(allocator);
            allocator.destroy(impl);
        }

    };

    return Impl;
}

pub fn methodCall(i: *Interface, message: *Message, allocator: mem.Allocator) Error!?Message {
    return i.vtable.method_call(i, message, allocator);
}

pub fn reference(i: *Interface) *Interface {
    _ = i.refcounter.fetchAdd(1, .seq_cst);
    return i;
}

pub fn release(i: *Interface) isize {
    return i.refcounter.fetchSub(1, .seq_cst);
}

pub fn deinit(i: *Interface, allocator: mem.Allocator) void {
    i.vtable.destroy(i, allocator);
}

fn PropertiesStorage(comptime T: type) struct {type, type} {
    const properties = propertyList(T);

    var struct_fields: []const BuiltinType.StructField    = &.{};
    var type_enum_fields: []const BuiltinType.EnumField   = &.{};
    var type_union_fields: []const BuiltinType.UnionField = &.{};

    for (properties, 0..) |property_name, i| {
        const Property = @field(T, property_name);
        struct_fields = struct_fields ++ .{ BuiltinType.StructField{
            .name = property_name,
            .type = Property.Type,
            .alignment = @alignOf(Property.Type),
            .default_value_ptr = Property.default_value,
            .is_comptime = false,
        }};
        type_enum_fields = type_enum_fields ++ .{ BuiltinType.EnumField{
            .name = property_name,
            .value = i,
        }};
        type_union_fields = type_union_fields ++ .{BuiltinType.UnionField{
            .name = property_name,
            .alignment = @alignOf(Property.Type),
            .type = Property.Type,
        }};
    }

    const TypeEnum = @Type(.{
        .@"enum" = .{
            .decls = &.{},
            .fields = type_enum_fields,
            .is_exhaustive = false,
            .tag_type = u32,
        }
    });
    const TypeUnion = @Type(.{
        .@"union" = .{
            .decls = &.{},
            .fields = type_union_fields,
            .tag_type = TypeEnum,
            .layout = .auto,
        }
    });

    return .{@Type(.{
        .@"struct" = .{
            .decls = &.{},
            .fields = struct_fields,
            .layout = .auto,
            .is_tuple = false,
        }
    }), TypeUnion};
}

pub fn bind(i: *Interface, c: *Connection, path: []const u8) void {
    i.connection = c;
    i.object_path = path;
}

const methodList = types.methodList;
const propertyList = types.propertyList;
const signalList = types.signalList;
