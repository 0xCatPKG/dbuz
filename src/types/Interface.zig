const std = @import("std");

const Self = @This();

const dbuz = @import("../dbuz.zig");
const dbus_types = @import("dbus_types.zig");

const DBusMessage = dbuz.types.DBusMessage;
const DBusName = dbuz.types.DBusName;
const DBusConnection = dbuz.types.DBusConnection;
const DBusDictionary = dbuz.types.DBusDictionary;

const DBusProperties = dbuz.interfaces.DBusProperties;
const DBusIntrospectable = dbuz.interfaces.DBusIntrospectable;

const String = dbuz.types.DBusString;
const Signature = dbuz.types.DBusSignature;
const ObjectPath = dbuz.types.DBusObjectPath;

const Type = std.builtin.Type;

pub const Error = error {
    Unhandled
} || DBusConnection.Error;

ptr: *anyopaque, // Pointer to actual interface implementation
vtable: *const VTable,
path: []const u8,
interface: []const u8,
introspection: []const u8,
hidden: bool = false,

name: ?*DBusName,
conn: *DBusConnection,

pub const VTable = struct {
    /// Route a call to the interface implementation
    route_call: *const fn (*anyopaque, *DBusConnection, *DBusMessage) Error!void,
    /// org.freedesktop.DBus.Properties
    /// Property is defined as a function that receives interface prototype value pointer, may receive additional params, and may return an value
    /// If property has it's return value as nonvoid type, it considered readable
    /// If property has exactly 2 params, it considered writable
    /// It is illegal to have a property with no return and no input params
    property: *const fn (*anyopaque, *DBusConnection, *DBusMessage, []const u8, DBusProperties.Action) DBusProperties.Error!void,
    all_properties: *const fn (*anyopaque, *DBusConnection, *DBusMessage) DBusConnection.Error!void,

    deinit: *const fn (*anyopaque) void,
};

pub fn init(
    comptime InterfacePrototype: type, userdata: *anyopaque,
    alloc: std.mem.Allocator,
    object_path: []const u8,
    interface_name: []const u8,
    connection: *DBusConnection,
    name: ?*DBusName,
    /// Hide during dbus introspection
    hidden: bool,
) !Self {

    // Determine if the interface is valid
    if (@hasDecl(InterfacePrototype, "init")) {
        const initializer = @field(InterfacePrototype, "init");
        if (@TypeOf(initializer) != fn (*anyopaque, std.mem.Allocator) anyerror!InterfacePrototype) @compileError("Interface prototype of type " ++ @typeName(InterfacePrototype) ++ \\ has invalid signature for init function:
            \\ expected fn(*anyopaque, std.mem.Allocator) anyerror!InterfacePrototype, found
            ++ @typeName(@TypeOf(initializer)));
    } else {
        @compileError("Interface prototype of type " ++ @typeName(InterfacePrototype) ++ " does not have a init function");
    }

    if (@hasDecl(InterfacePrototype, "deinit")) {
        const initializer = @field(InterfacePrototype, "deinit");
        if (@TypeOf(initializer) != fn (*InterfacePrototype) void) @compileError("Interface prototype of type " ++ @typeName(InterfacePrototype) ++ \\ has invalid signature for deinit function:
            \\ expected fn(*InterfacePrototype) void, found
            ++ @typeName(@TypeOf(initializer)));
    }

    const S = struct {
        const IFaceSelf = @This();
        const IFaceProto: type = InterfacePrototype;

        allocator: std.mem.Allocator,
        iface_impl: InterfacePrototype,
        interface: []const u8,

        introspection: ?[]const u8 = null,

        pub fn init(allocator: std.mem.Allocator, udata: *anyopaque, interface: []const u8) !*IFaceSelf {
            const self = try allocator.create(IFaceSelf);
            errdefer allocator.destroy(self);
            self.* = .{
                .allocator = allocator,
                .iface_impl = try InterfacePrototype.init(udata, allocator),
                .interface = interface
            };
            return self;
        }

        pub fn deinit(erased_impl: *anyopaque) void {
            const self: *IFaceSelf = @alignCast(@ptrCast(erased_impl));
            if (@hasDecl(InterfacePrototype, "deinit")) {
                const deinitializer = @field(InterfacePrototype, "deinit");
                deinitializer(&self.iface_impl);
            }
            self.allocator.destroy(self);
        }

        pub fn route_call(erased_impl: *anyopaque, conn: *DBusConnection, msg: *DBusMessage) Error!void {
            const self: *IFaceSelf = @alignCast(@ptrCast(erased_impl));
            const typeinfo = @typeInfo(InterfacePrototype);

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            const allocator = arena.allocator();

            switch (typeinfo) {
                else => @compileError("Invalid container type"),
                .@"struct" => |s| {
                    inline for (s.decls) |decl_| {
                        const decl = @field(InterfacePrototype, decl_.name);
                        const decl_info = @typeInfo(@TypeOf(decl));
                        switch (decl_info) {
                            else => continue,
                            .@"fn" => |func| {
                                comptime if (!DBusIntrospectable.isMethodNameValid(decl_.name)) continue;
                                comptime if (func.params.len == 0) @compileError("Invalid method prototype for " ++ decl_.name ++ ": methods should take *" ++ @typeName(InterfacePrototype) ++ " as the first argument at least");
                                comptime if (func.params[0].type.? != *InterfacePrototype) @compileError("Invalid method prototype for " ++ @typeName(decl) ++ ": First argument should be *" ++ @typeName(InterfacePrototype));

                                comptime var has_message_arg: bool = false;

                                inline for (func.params[1..], 0..) |param, i| {
                                    if (param.type.? == *DBusMessage) {
                                        comptime if (has_message_arg) @compileError("Invalid method prototype for " ++ decl_.name ++ ": Duplicate *" ++ @typeName(DBusMessage) ++ " argument");
                                        if (i + 1 != func.params.len - 1) @compileError("Invalid method prototype for " ++ decl_.name ++ ": optional *DBusMessage argument must be the last argument, but is observed at position " ++ std.fmt.comptimePrint("{d} (from {d})", .{i, func.params.len - 1}));
                                        has_message_arg = true;
                                    }
                                    comptime if (!dbus_types.isTypeSerializable(param.type.?) and param.type.? != *DBusMessage) @compileError("Unserializable type " ++ @typeName(param.type.?) ++ " in method " ++ decl_.name ++  "at position " ++ std.fmt.comptimePrint("{d}", .{i}));
                                }

                                if (std.mem.eql(u8, DBusIntrospectable.methodName(decl_.name), msg.member.?)) {
                                    comptime var read_args_slice: [func.params.len-1-(if (has_message_arg) 1 else 0)]type = undefined;
                                    inline for (func.params[1..], 0..) |param, i| {
                                        comptime if (param.type.? == *DBusMessage) continue;
                                        read_args_slice[i] = param.type.?;
                                    }

                                    const args = .{&self.iface_impl} ++ (msg.read(std.meta.Tuple(&read_args_slice), allocator) catch {
                                        const fmt = try std.fmt.allocPrint(allocator, "{s}.Error.ParsingError", .{self.interface});
                                        try conn.replyError(msg, fmt, "Unable to parse", allocator);
                                        return;
                                    }) ++ (if (has_message_arg) .{msg} else .{});

                                    const ret = @call(.auto, decl, args);
                                    if ((msg.flags & DBusMessage.Flags.NO_REPLY_EXPECTED) != 0) return;

                                    if (isReturnTypeErrorUnion(func.return_type.?)) {
                                        const unwrapped = ret catch |err| {
                                            const error_name = try std.fmt.allocPrint(allocator, "{s}.{s}", .{self.interface, @errorName(err)});

                                            const error_desc = if (std.meta.hasFn(InterfacePrototype, "errorDesc")) blk: {
                                                const error_getter = @field(InterfacePrototype, "errorDesc");
                                                if (@TypeOf(error_getter) != fn (anyerror) []const u8) @compileError("errorDesc must be fn (anyerror) []const u8 but currently is has type " ++ @typeName(@TypeOf(error_getter)));
                                                break :blk error_getter(err);
                                            } else "";
                                            return try conn.replyError(msg, error_name, error_desc, allocator);
                                        };
                                        return try conn.replyToCall(msg, unwrapped, allocator);
                                    } else return try conn.replyToCall(msg, ret, allocator);
                                }
                            }
                        }
                    }
                }
            }
        }

        pub fn property(erased_impl: *anyopaque, conn: *DBusConnection, msg: *DBusMessage, property_name: []const u8, action: DBusProperties.Action) DBusProperties.Error!void {
            const self: *IFaceSelf = @alignCast(@ptrCast(erased_impl));
            const typeinfo = @typeInfo(InterfacePrototype);
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();

            const allocator = arena.allocator();

            switch (typeinfo) {
                else => @compileError("Invalid container type"),
                .@"struct" => |s| {

                    inline for (s.decls) |decl_| {
                        const decl = @field(InterfacePrototype, decl_.name);
                        const decl_info = @typeInfo(@TypeOf(decl));

                        comptime if (!DBusIntrospectable.isPropertyNameValid(decl_.name)) continue;

                        switch (decl_info) {
                            else => @compileError("Property candidate " ++ decl_.name ++ " expected to be a function, but is " ++ @typeName(decl_info)),
                            .@"fn" => |func| {
                                const return_type = unwrapReturnType(func.return_type.?);
                                const error_set = unwrapErrorSet(func.return_type.?);
                                const param1 = if (func.params.len == 2) unwrapOptional(func.params[1].type.?) else void;

                                comptime if (func.params.len == 0) @compileError("Invalid property prototype for " ++ decl_.name ++ ": properties should take *" ++ @typeName(InterfacePrototype) ++ " as the first argument at least");
                                comptime if (func.params[0].type.? != *InterfacePrototype) @compileError("Invalid property prototype for " ++ decl_.name ++ ": First argument should be *" ++ @typeName(InterfacePrototype));
                                comptime if (func.params.len == 2) {
                                    if (!dbus_types.isTypeSerializable(param1)) @compileError("Unserializable type " ++ @typeName(param1) ++ " for property " ++ decl_.name);
                                };
                                comptime if (!dbus_types.isTypeSerializable(return_type)) @compileError("Unserializable type " ++ @typeName(return_type) ++ " for property " ++ decl_.name);
                                comptime if (func.params.len == 2 and return_type != void) {
                                    if (return_type != param1) @compileError("Read-Write property " ++ decl_.name ++ " should have same type for params[1] and return_type, but " ++ @typeName(param1) ++ " and " ++ @typeName(return_type));
                                };
                                comptime if (func.params.len == 1 and return_type == void) @compileError("Property candidate " ++ decl_.name ++ " has no input or output");

                                if (std.mem.eql(u8, DBusIntrospectable.propertyName(decl_.name), property_name)) {
                                    switch (action) {
                                        .Get => {
                                            const ret = blk: {
                                                if (error_set == error{}) {
                                                    break :blk if (param1 == void) decl(&self.iface_impl)
                                                    else decl(&self.iface_impl, null);
                                                } else {
                                                    break :blk if (param1 == void) try decl(&self.iface_impl)
                                                    else try decl(&self.iface_impl, null);
                                                }
                                            };

                                            const ValueUnion = union(enum) {
                                                v: @TypeOf(ret)
                                            };

                                            return try conn.replyToCall(msg, ValueUnion{ .v = ret }, allocator);
                                        },
                                        .Set => {
                                            if (param1 == void) return try conn.replyError(msg, "org.freedesktop.DBus.Properties.Error.ReadOnlyProperty", "Property " ++ decl_.name ++ " is read-only", allocator);

                                            const value = try msg.read(param1, allocator);
                                            _ = blk: {
                                                if (error_set == error{}) {
                                                    break :blk decl(&self.iface_impl, value);
                                                } else {
                                                    break :blk try decl(&self.iface_impl, value);
                                                }
                                            };

                                            return try conn.replyToCall(msg, .{}, allocator);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return DBusProperties.Error.NoSuchProperty;
        }

        pub fn all_properties(erased_impl: *anyopaque, conn: *DBusConnection, msg: *DBusMessage) DBusConnection.Error!void {

            const self: *IFaceSelf = @alignCast(@ptrCast(erased_impl));
            const typeinfo = @typeInfo(InterfacePrototype).@"struct";

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();

            const allocator = arena.allocator();

            comptime var fields_count: usize = 0;
            comptime for (typeinfo.decls) |decl| {
                if (DBusIntrospectable.isPropertyNameValid(decl.name)) fields_count += 1;
            };

            comptime var enum_fields: [fields_count]Type.EnumField = undefined;
            comptime var union_fields: [fields_count]Type.UnionField = undefined;

            comptime var i: usize = 0;
            inline for (typeinfo.decls) |decl| {
                comptime if (!DBusIntrospectable.isPropertyNameValid(decl.name)) continue;
                defer i += 1;
                const func_decl = @field(InterfacePrototype, decl.name);
                switch (@typeInfo(@TypeOf(func_decl))) {
                    else => @compileError("Invalid type for prototype candidate " ++ decl.name ++ ": expected function, but got " ++ @typeName(func_decl)),
                    .@"fn" => |func| {
                        const return_type = unwrapReturnType(func.return_type.?);
                        if (!dbus_types.isTypeSerializable(return_type)) @compileError("Return type of " ++ decl.name ++ " is not serializable");
                        enum_fields[i] = Type.EnumField{
                            .name = std.fmt.comptimePrint("type_{s}", .{DBusIntrospectable.propertyName(decl.name)}),
                            .value = i
                        };
                        union_fields[i] = Type.UnionField{
                            .name = std.fmt.comptimePrint("type_{s}", .{DBusIntrospectable.propertyName(decl.name)}),
                            .type = return_type,
                            .alignment = @alignOf(return_type),
                        };
                    }
                }
            }

            const VariantEnum = @Type(.{
                .@"enum" = Type.Enum{
                    .tag_type = u32,
                    .is_exhaustive = true,
                    .decls = &.{},
                    .fields = enum_fields[0..fields_count]
                }
            });
            const VariantUnion = @Type(.{
                .@"union" = Type.Union{
                    .decls = &.{},
                    .fields = union_fields[0..fields_count],
                    .tag_type = VariantEnum,
                    .layout = .auto
                }
            });

            const PropertyHashmap = DBusDictionary.from(String, VariantUnion);
            var properties = PropertyHashmap.init(allocator);

            if (std.meta.fields(VariantUnion).len > 0) {
                inline for (typeinfo.decls) |decl| {
                    comptime if (!DBusIntrospectable.isPropertyNameValid(decl.name)) continue;
                    const func_decl = @field(InterfacePrototype, decl.name);
                    switch (@typeInfo(@TypeOf(func_decl))) {
                        else => @compileError("Invalid type for prototype candidate " ++ decl.name ++ ": expected function, but got " ++ @typeName(func_decl)),
                        .@"fn" => |func| {
                            const return_type = unwrapReturnType(func.return_type.?);
                            const error_set = unwrapErrorSet(func.return_type.?);
                            const param1 = if (func.params.len == 2) unwrapOptional(func.params[1].type.?) else void;

                            if (!dbus_types.isTypeSerializable(return_type)) @compileError("Return type of " ++ decl.name ++ " is not serializable");
                            const ret = blk: {
                                if (error_set == error{}) {
                                    break :blk if (param1 == void) func_decl(&self.iface_impl)
                                    else func_decl(&self.iface_impl, null);
                                } else {
                                    break :blk if (param1 == void) try func_decl(&self.iface_impl)
                                    else try func_decl(&self.iface_impl, null);
                                }
                            };

                            const v = @unionInit(VariantUnion, std.fmt.comptimePrint("type_{s}", .{DBusIntrospectable.propertyName(decl.name)}), ret);
                            try properties.put(.{.value = DBusIntrospectable.propertyName(decl.name)}, v);
                        }
                    }
                }
            }
            try conn.replyToCall(msg, .{properties}, allocator);
        }
    };
    const iface_impl = try S.init(alloc, userdata, interface_name);
    errdefer S.deinit(iface_impl);
    return .{
        .ptr = iface_impl,
        .vtable = &.{
            .route_call = S.route_call,
            .property = S.property,
            .all_properties = S.all_properties,
            .deinit = S.deinit,
        },
        .path = try alloc.dupe(u8, object_path),
        .interface = try alloc.dupe(u8, interface_name),
        .introspection = if (hidden) "" else comptime DBusIntrospectable.introspectInterface(InterfacePrototype),
        .conn = connection,
        .name = name,
        .hidden = hidden,
    };
}

pub inline fn setIntrospectable(self: *Self, xml: ?[]const u8) void {
    self.introspectable = xml;
}

pub fn broadcast(self: Self, path: []const u8, signal_name: []const u8, data: anytype, allocator: std.mem.Allocator) !void {
    return self.conn.broadcast(.{
        .interface = self.interface,
        .member = signal_name,
        .path = path,
    }, data, allocator);
}

/// Unpublishes interface and releases any associated resources.
pub fn destroy(self: Self) void {
    if (self.name != null) self.name.?.unregisterInterface(self) else self.conn.unregisterInterface(self);
    self.conn.allocator.free(self.interface);
    self.conn.allocator.free(self.path);
    self.vtable.deinit(self.ptr);
}

/// Methods should start with "method@", everything after @ should follow DBus member naming rules.

inline fn isReturnTypeErrorUnion(comptime T: type) bool {
const typeinfo = @typeInfo(T);
    return switch (typeinfo) {
        .error_union => true,
        else => false,
    };
}

inline fn unwrapReturnType(comptime T: type) type {
    const typeinfo = @typeInfo(T);
    switch (typeinfo) {
        else => return T,
        .error_union => |error_union| return error_union.payload
    }
    unreachable;
}

inline fn unwrapErrorSet(comptime T: type) type {
    const typeinfo = @typeInfo(T);
    switch (typeinfo) {
        else => return error{},
        .error_union => |error_union| return error_union.error_set
    }
    unreachable;
}

inline fn unwrapOptional(comptime T: type) type {
    const typeinfo = @typeInfo(T);
    switch (typeinfo) {
        else => return T,
        .optional => |optional| return optional.child
    }
    unreachable;
}
