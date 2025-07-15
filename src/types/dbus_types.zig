const std = @import("std");
const DBusIntrospectable = @import("../interfaces/DBusIntrospectable.zig");
const DBusMessage = @import("DBusMessage.zig");

pub const String = struct {
    value: []const u8,
    ownership: bool = false,

    pub fn deinit(self: String, allocator: std.mem.Allocator) void {
        if (!self.ownership) @panic("String is not owned");
        allocator.free(self.value);
    }
};
pub const ObjectPath = struct {
    value: []const u8,
    ownership: bool = false,

    pub fn deinit(self: ObjectPath, allocator: std.mem.Allocator) void {
        if (!self.ownership) @panic("ObjectPath is not owned");
        allocator.free(self.value);
    }
};
pub const Signature = struct {
    value: []const u8,
    ownership: bool = false,

    pub fn deinit(self: Signature, allocator: std.mem.Allocator) void {
        if (!self.ownership) @panic("Signature is not owned");
        allocator.free(self.value);
    }
};

pub inline fn isDict(comptime T: type) bool {
    if (
        @hasDecl(T, "put") and @hasDecl(T, "getOrPut")
        and @hasDecl(T, "getOrPutAdapted") and @hasDecl(T, "get")
        and @hasDecl(T, "iterator") and @hasDecl(T, "KV")
    ) return true;
    return false;
}

pub fn deinitValueRecursive(value: anytype, allocator: std.mem.Allocator) void {
    const T = @TypeOf(value);
    const typeinfo = @typeInfo(T);

    switch (T) {
        String, ObjectPath, Signature => value.deinit(allocator),
        else => switch (typeinfo) {
            else => {},
            .pointer => {
                for (value) |child| deinitValueRecursive(child, allocator);
                allocator.free(value);
            },
            .@"struct" => |st| {
                if (isDict(value)) {
                    value.deinit();
                } else for (st.fields) |field| {
                    deinitValueRecursive(@field(value, field.name), allocator);
                }
            },
            .@"union" => |un| {
                const active_tag = @tagName(value);
                inline for (un.fields) |field| {
                    if (std.mem.eql(u8, active_tag, field.name)) {
                        deinitValueRecursive(@field(value, field.name), allocator);
                    }
                }
            },
        }
    }
}

pub inline fn isTypeSerializable(comptime T: type) bool {
    const typeinfo = @typeInfo(T);
    return switch (typeinfo) {
        else => false,
        .bool => true,
        .int => |intinfo| if (intinfo.bits > 64) false else true,
        .float => |floatinfo| if (floatinfo.bits > 64) false else true,
        .pointer => |pointerinfo| blk: {
            if (pointerinfo.size != .slice) break :blk false;
            break :blk isTypeSerializable(pointerinfo.child);
        },
        .@"struct" => |structinfo| blk: {
            if (isDict(T)) return guessSignature(T).len != 0;
            for (structinfo.fields) |field| {
                if (!isTypeSerializable(field.type)) break :blk false;
            }
            break :blk true;
        },
        .@"union" => |unioninfo| blk: {
            if (unioninfo.tag_type == null) break :blk false;
            for (unioninfo.fields) |field| {
                if (!isTypeSerializable(field.type)) break :blk false;
            }
            break :blk true;
        },
    };
}

pub inline fn introspectInterface(comptime Interface: type) []const u8 {
    comptime var data: []const u8 = "";
    const iface_info = @typeInfo(Interface).@"struct";

    for (iface_info.decls) |decl_| {
        data = data ++ if (DBusIntrospectable.isMethodNameValid(decl_.name)) introspectMethodCall(Interface, decl_.name, @field(Interface, decl_.name))
        else if (DBusIntrospectable.isSignalNameValid(decl_.name)) introspectSignal(Interface, decl_.name, @field(Interface, decl_.name))
        else if (DBusIntrospectable.isPropertyNameValid(decl_.name)) introspectProperty(Interface, decl_.name, @field(Interface, decl_.name))
        else "";
    }

    return data;
}

inline fn introspectMethodCall(comptime Interface: type, comptime name: []const u8, func: anytype) []const u8 {
    const fntype = @TypeOf(func);
    const typeinfo = @typeInfo(fntype);

    comptime var data: []const u8 = "";

    switch (typeinfo) {
        else => {},
        .@"fn" => |fninfo| {
            comptime if (fninfo.params.len == 0) return "";
            comptime if (fninfo.params[0].type.? != *Interface) return "";

            inline for (fninfo.params[1..]) |param| {
                comptime if (!isTypeSerializable(param.type.?) and param.type.? != *DBusMessage) return "";
            }

            data = data ++ "<method name=\"" ++ DBusIntrospectable.methodName(name) ++ "\">\n";
            for (fninfo.params[1..]) |param| {
                if (param.type.? == *DBusMessage) continue;
                data = data ++ "<arg name=\"arg_" ++ DBusMessage.guessSignature(param.type.?) ++ "\" type=\"" ++ DBusMessage.guessSignature(param.type.?) ++ "\" direction=\"in\"/>\n";
            }
            const retinfo = @typeInfo(fninfo.return_type.?);

            switch (retinfo) {
                else => {
                    switch (retinfo) {
                        else => {
                            if (!isTypeSerializable(fninfo.return_type.?)) return "";
                            data = data ++ "<arg name=\"out_" ++ DBusMessage.guessSignature(fninfo.return_type.?) ++ "\" type=\"" ++ DBusMessage.guessSignature(fninfo.return_type.?) ++ "\" direction=\"out\"/>\n";
                        },
                        .@"struct" => |structinfo| {
                            if (!isTypeSerializable(fninfo.return_type.?)) return "";
                            if (structinfo.is_tuple) {
                                for (structinfo.fields) |field| {
                                    data = data ++ "<arg name=\"" ++ field.name ++ "\" type=\"" ++ DBusMessage.guessSignature(field.type.?) ++ "\" direction=\"out\"/>\n";
                                }
                            }
                            else data = data ++ "<arg name=\"out_" ++ DBusMessage.guessSignature(fninfo.return_type.?) ++ "\" type=\"" ++ DBusMessage.guessSignature(fninfo.return_type.?) ++ "\" direction=\"out\"/>\n";
                        },
                        .void => {}
                    }
                },
                .error_union => |errorinfo| {
                    const payloadinfo = @typeInfo(errorinfo.payload);
                    switch (payloadinfo) {
                        else => {
                            if (!isTypeSerializable(errorinfo.payload)) return "";
                            data = data ++ "<arg name=\"out_" ++ DBusMessage.guessSignature(errorinfo.payload) ++ "\" type=\"" ++ DBusMessage.guessSignature(errorinfo.payload) ++ "\" direction=\"out\"/>\n";
                        },
                        .@"struct" => |structinfo| {
                            if (!isTypeSerializable(errorinfo.payload)) return "";
                            if (structinfo.is_tuple) {
                                for (structinfo.fields) |field| {
                                    data = data ++ "<arg name=\"" ++ field.name ++ "\" type=\"" ++ DBusMessage.guessSignature(field.type.?) ++ "\" direction=\"out\"/>\n";
                                }
                            }
                            else data = data ++ "<arg name=\"out_" ++ DBusMessage.guessSignature(errorinfo.payload) ++ "\" type=\"" ++ DBusMessage.guessSignature(errorinfo.payload) ++ "\" direction=\"out\"/>\n";
                        },
                        .void => {}
                    }
                }
            }

            data = data ++ "</method>\n";
        },
    }
    return data;
}

inline fn introspectSignal(comptime _: type, comptime name: []const u8, func: anytype) []const u8 {
    if (!DBusIntrospectable.validMemberName(name[7..])) return "";
    const fntype = @TypeOf(func);
    const typeinfo = @typeInfo(fntype);

    comptime var data: []const u8 = "";

    switch (typeinfo) {
        else => {},
        .@"fn" => |fninfo| {
            inline for (fninfo.params[0..]) |param| {
                comptime if (!isTypeSerializable(param.type.?)) return "";
            }
            data = data ++ "<signal name=\"" ++ DBusIntrospectable.signalName(name) ++ "\">\n";
            for (fninfo.params[0..]) |param| {
                data = data ++ "<arg name=\"arg_" ++ DBusMessage.guessSignature(param.type.?) ++ "\" type=\"" ++ DBusMessage.guessSignature(param.type.?) ++ "\" direction=\"out\"/>\n";
            }

            data = data ++ "</signal>\n";
        },
    }
    return data;
}

inline fn introspectProperty(comptime Interface: type, comptime name: []const u8, func: anytype) []const u8 {
    const fntype = @TypeOf(func);
    const typeinfo = @typeInfo(fntype);

    comptime var data: []const u8 = "";

    switch (typeinfo) {
        else => {},
        .@"fn" => |fninfo| {
            comptime if (fninfo.params.len == 0) return "";
            comptime if (fninfo.params[0].type.? != *Interface) return "";

            const readwrite = fninfo.params.len == 2;

            data = data ++ "<property name=\"" ++ DBusIntrospectable.propertyName(name) ++ "\"";
            const retinfo = @typeInfo(fninfo.return_type.?);

            switch (retinfo) {
                else => {
                    if (readwrite) {
                        if (fninfo.return_type.? != DBusIntrospectable.unwrapOptional(fninfo.params[1].type.?)) return "";
                    }
                    switch (retinfo) {
                        else => {
                            if (!isTypeSerializable(fninfo.return_type.?)) return "";
                            data = data ++ " type=\"" ++ DBusMessage.guessSignature(fninfo.return_type.?) ++ "\"";
                        },
                        .void => {}
                    }
                },
                .error_union => |errorinfo| {
                    const payloadinfo = @typeInfo(errorinfo.payload);
                    if (readwrite) {
                        if (errorinfo.payload != fninfo.params[1].type.?) return "";
                    }
                    switch (payloadinfo) {
                        else => {
                            if (!isTypeSerializable(errorinfo.payload)) return "";
                            data = data ++ " type=\"" ++ DBusMessage.guessSignature(errorinfo.payload) ++ "\"";
                        },
                        .void => {}
                    }
                }
            }
            data = data ++ " access=\"" ++ (if (readwrite) "readwrite" else "read") ++ "\"/>\n";
        },
    }
    return data;
}

pub fn getSignature(value: anytype) []const u8 {
    comptime var signature: []const u8 = "";

    const typeinfo = @typeInfo(@TypeOf(value));

    switch (typeinfo) {
        .@"struct" => |structinfo| {
            if (structinfo.is_tuple) {
                inline for (value) |el| {
                    signature = signature ++ guessSignature(@TypeOf(el));
                }
                return signature;
            }
        },
        else => {},
    }
    signature = signature ++ guessSignature(@TypeOf(value));
    return signature;
}

pub inline fn guessSignature(T: type) [:0]const u8 {
    comptime var signature: [:0]const u8 = "";
    const typeinfo = @typeInfo(T);

    signature = blk: switch (T) {
        String => signature ++ "s",
        ObjectPath => signature ++ "o",
        Signature => signature ++ "g",
        std.fs.File => signature ++ "h",
        std.fs.Dir => signature ++ "h",
        else => {
            switch (typeinfo) {
                .int => |intinfo| {
                    if (intinfo.bits <= 8) break :blk signature ++ "y";
                    if (intinfo.bits <= 16) break :blk (if (intinfo.signedness == .signed) signature ++ "n" else signature ++ "q");
                    if (intinfo.bits <= 32) break :blk (if (intinfo.signedness == .signed) signature ++ "i" else signature ++ "u");
                    if (intinfo.bits <= 64) break :blk (if (intinfo.signedness == .signed) signature ++ "x" else signature ++ "t");
                },
                .float => |floatinfo| {
                    if (floatinfo.bits <= 64) break :blk signature ++ "d";
                },
                .array => |arrayinfo| {
                    break :blk signature ++ "a" ++ guessSignature(arrayinfo.child);
                },
                .vector => |vectorinfo| {
                    break :blk signature ++ "a" ++ guessSignature(vectorinfo.child);
                },
                .bool => break :blk signature ++ "b",
                .pointer => |ptrinfo| {
                    if (ptrinfo.size == .slice) break :blk signature ++ "a" ++ guessSignature(ptrinfo.child) else @compileError("Only slice-type pointers are supported, but get pointer of size " ++ @tagName(ptrinfo.size));
                },
                .@"struct" => |structinfo| {
                    if (isDict(T)) break :blk signature ++ dictSignature(T);
                    signature = signature ++ "(";
                    inline for (structinfo.fields) |field| {
                        signature = signature ++ guessSignature(field.type);
                    }
                    signature = signature ++ ")";
                },
                .@"union" => {
                    signature = signature ++ "v";
                },
                else => @compileError("Unknown type " ++ @typeName(T) ++ " during signature generation"),
            }
            return signature;
        },
    };

    return signature;
}

pub inline fn dictSignature(comptime T: type) []const u8 {
    const KV = @field(T, "KV");
    const K = @FieldType(KV, "key");
    const V = @FieldType(KV, "value");
    return "a{" ++ guessSignature(K) ++ guessSignature(V) ++ "}";
}
