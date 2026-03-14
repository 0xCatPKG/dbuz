const std = @import("std");
// const DBusIntrospectable = @import("../interfaces/DBusIntrospectable.zig");
// const DBusMessage = @import("DBusMessage.zig");

/// Wrapper for []const u8 for distinguishing between byte arrays and strings.
pub const String = struct {
    value: []const u8,
    ownership: bool = false,

    pub fn deinit(self: String, allocator: std.mem.Allocator) void {
        if (!self.ownership) @panic("String is not owned");
        allocator.free(self.value);
    }
};

/// Wrapper for []const u8 for distinguishing between byte arrays and object paths.
pub const ObjectPath = struct {
    value: []const u8,
    ownership: bool = false,

    pub fn deinit(self: ObjectPath, allocator: std.mem.Allocator) void {
        if (!self.ownership) @panic("ObjectPath is not owned");
        allocator.free(self.value);
    }
};

/// Wrapper for []const u8 for distinguishing between byte arrays and signatures.
pub const Signature = struct {
    value: []const u8,
    ownership: bool = false,

    pub fn deinit(self: Signature, allocator: std.mem.Allocator) void {
        if (!self.ownership) @panic("Signature is not owned");
        allocator.free(self.value);
    }
};

pub inline fn isDict(comptime T: type) bool {
    if (@hasDecl(T, "put") and @hasDecl(T, "getOrPut") and @hasDecl(T, "getOrPutAdapted") and @hasDecl(T, "get") and @hasDecl(T, "iterator") and @hasDecl(T, "KV")) return true;
    return false;
}

pub fn deinitValueRecursive(allocator: std.mem.Allocator, value: anytype) void {
    const T = @TypeOf(value);
    const typeinfo = @typeInfo(T);

    switch (T) {
        String, ObjectPath, Signature => value.deinit(allocator),
        else => switch (typeinfo) {
            else => {},
            .pointer => {
                for (value) |child| deinitValueRecursive(allocator, child);
                allocator.free(value);
            },
            .@"struct" => |st| {
                if (comptime isDict(T)) {
                    const unmanaged = &value.unmanaged;
                    @constCast(unmanaged).deinit(value.allocator);
                } else
                if (comptime isFileHandle(T)) {
                    std.posix.close(value.handle);
                } else inline for (st.fields) |field| {
                    deinitValueRecursive(allocator, @field(value, field.name));
                }
            },
            .@"union" => |un| {
                const active_tag = @tagName(value);
                inline for (un.fields) |field| {
                    if (std.mem.eql(u8, active_tag, field.name)) {
                        deinitValueRecursive(allocator, @field(value, field.name));
                    }
                }
            },
        },
    }
}

/// Check if type T can be serialized using dbuz.
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
            if (std.meta.hasMethod(T, "toDBus")) break :blk true
            else if (isDict(T)) return guessSignature(T).len != 0;
            for (structinfo.fields) |field| {
                if (!isTypeSerializable(field.type)) break :blk false;
            }
            break :blk true;
        },
        .@"union" => |unioninfo| blk: {
            if (std.meta.hasMethod(T, "toDBus")) break :blk true;
            if (unioninfo.tag_type == null) break :blk false;
            for (unioninfo.fields) |field| {
                if (!isTypeSerializable(field.type)) break :blk false;
            }
            break :blk true;
        },
        .@"enum" => |enuminfo| if (std.meta.hasMethod(T, "toDBus")) true else isTypeSerializable(enuminfo.tag_type),
    };
}
pub inline fn isTypeDeserializable(comptime T: type) bool {
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
            if (std.meta.hasMethod(T, "fromDBus")) break :blk true
            else if (isDict(T)) return guessSignature(T).len != 0;
            for (structinfo.fields) |field| {
                if (!isTypeSerializable(field.type)) break :blk false;
            }
            break :blk true;
        },
        .@"union" => |unioninfo| blk: {
            if (std.meta.hasMethod(T, "fromDBus")) break :blk true;
            if (unioninfo.tag_type == null) break :blk false;
            for (unioninfo.fields) |field| {
                if (!isTypeSerializable(field.type)) break :blk false;
            }
            break :blk true;
        },
        .@"enum" => |enuminfo| if (std.meta.hasMethod(T, "fromDBus")) true else isTypeSerializable(enuminfo.tag_type),
    };
}

/// Get signature from value of any type. If type is void, returns null
pub fn getSignature(value: anytype) ?[]const u8 {
    comptime var signature: []const u8 = "";

    if (@TypeOf(value) == void) return null;

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

/// Guess DBus signature based on provided type
pub inline fn guessSignature(T: type) [:0]const u8 {
    comptime var signature: [:0]const u8 = "";
    const typeinfo = @typeInfo(T);
    signature = blk: switch (T) {
        String => signature ++ "s",
        ObjectPath => signature ++ "o",
        Signature => signature ++ "g",
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
                    if (ptrinfo.size == .slice) break :blk signature ++ "a" ++ comptime guessSignature(ptrinfo.child) else @compileError("Only slice-type pointers are supported, but get pointer of size " ++ @tagName(ptrinfo.size));
                },
                .@"struct" => |structinfo| {
                    if (@hasDecl(T, "dbus_signature")) break :blk signature ++ T.dbus_signature;
                    if (isDict(T)) break :blk signature ++ dictSignature(T);
                    if (isFileHandle(T)) break :blk signature ++ "h";
                    if (!structinfo.is_tuple) signature = signature ++ "(";
                    inline for (structinfo.fields) |field| {
                        signature = signature ++ guessSignature(field.type);
                    }
                    if (!structinfo.is_tuple) signature = signature ++ ")";
                },
                .@"union" => {
                    if (@hasDecl(T, "dbus_signature")) break :blk signature ++ T.dbus_signature;
                    signature = signature ++ "v";
                },
                .@"enum" => |en| {
                    if (@hasDecl(T, "dbus_signature")) break :blk signature ++ T.dbus_signature;
                    signature = signature ++ guessSignature(en.tag_type);
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

pub fn isFileHandle(comptime T: type) bool {
    if (@hasField(T, "handle")) {
        const handle_type = @FieldType(T, "handle");
        if (handle_type == std.fs.File.Handle) {
            return true;
        }
    }
    return false;
}

const PropertyMode = enum {
    Read,
    Write,
    ReadWrite,
};
const PropertyChangedSignal = enum {
    true,
    false,
    invalidates,
    @"const",
};
const PropertyOpts = struct {
    /// Access mode
    mode: PropertyMode = .ReadWrite,
    signal: ?PropertyChangedSignal = null,
    deprecated: ?bool = null,
};

/// Generate property declaration for Interface.AutoInterface based on type T, with specified default value and specified options.
/// Resulting property will reside in AutoInterface's type result, field .properties. with same name as declaration name.
pub fn Property(comptime T: type, default: ?*const T, comptime opts: PropertyOpts) type {
    if (!isTypeSerializable(T)) @compileError(std.fmt.comptimePrint("Unable to make property type: {s} is not DBus-serializable", .{@typeName(T)}));
    return packed struct (u0) {
        pub const @".metadata_DBUZ_PROPERTY" = {};
        pub const Type: type = T;
        pub const default_value: ?*const anyopaque = @ptrCast(default);
        pub const mode = opts.mode;
        pub const signal = opts.signal;
        pub const deprecated = opts.deprecated;
    };
}

const MethodOpts = struct {
    /// Argument names that should be shown during introspection. Make sense only with Interface.AutoInterface(..., null). Must match count of function params (excluding impl pointer)
    argument_names: ?[]const []const u8 = null,
    /// Same as with argument_names, but null means that guessSignature will be used on type. Used for annotation generation, not very useful currently.
    argument_types: ?[]const ?[]const u8 = null,
    deprecated: bool = false,
    no_reply_expected: bool = false,
};

/// Generate method declaration for Interface.AutoInterface based on passed function F and options.
/// AutoInterface will generate glue code for calling passed function when message with .member set to declaration's name arrives.
pub fn Method(F: anytype, comptime opts: MethodOpts) type {
    const Fn = @TypeOf(F);
    const fn_info = switch (@typeInfo(Fn)) {
        .@"fn" => |func| func,
        else => @compileError("Unable to create method from " ++ @typeName(Fn) ++ ": not a function")
    };

    if (fn_info.params.len == 0) @compileError(std.fmt.comptimePrint("Unable to create method from {s}: function must contain at least 1 argument", .{@typeName(Fn)}));

    if (opts.argument_names) |anames| {
        if (anames.len != fn_info.params.len - 1) @compileError(std.fmt.comptimePrint("MethodOpts.argument_names length must be equal to function param count minus one ({} != {})", .{anames.len, fn_info.params.len - 1}));
    }

    if (opts.argument_types) |atypes| {
        if (atypes.len != fn_info.params.len - 1) @compileError(std.fmt.comptimePrint("MethodOpts.argument_types length must be equal to function param count minus one ({} != {})", .{atypes.len, fn_info.params.len - 1}));

    }

    var read_params: []const type = &.{};
    inline for (fn_info.params[1..], 1..) |param, i| {
        if (param.type.? == *Message or param.type.? == *const Message) continue;
        if (!isTypeSerializable(param.type.?)) @compileError(std.fmt.comptimePrint("Unable to create method from {s}: parameter {} of type {s} is not DBus-serializable.", .{
            @typeName(Fn), i, @typeName(param.type.?)
        }));
        read_params = read_params ++ .{param.type.?};
    }

    const param_tuple = std.meta.ArgsTuple(Fn);
    const param_readable_tuple = std.meta.Tuple(read_params);

    return packed struct (u0) {
        pub const @".metadata_DBUZ_METHOD" = {};
        pub const Signature = param_tuple;
        pub const Arguments = param_readable_tuple;
        pub const ReturnType = fn_info.return_type.?;
        pub const @"fn" = F;
        pub const argument_names = opts.argument_names;
        pub const argument_types = opts.argument_types;
        pub const deprecated = opts.deprecated;
        pub const no_reply_expected = opts.no_reply_expected;
    };
}

const SignalOpts = struct {
    deprecated: bool = false,
    param_names: ?[]const []const u8 = null,
    param_types: ?[]const ?[]const u8 = null,
};
/// Generate signal declaration for Interface.AutoInterface's dbus intorspection and .emit_signal's glue code.
pub fn Signal(comptime T: type, opts: SignalOpts) type {
    if (!isTypeSerializable(T)) @compileError(@typeName(T) ++ "is not DBus-serializable. Signal must have a serializable signature.");
    const SignalT = switch(@typeInfo(T)) {
        .@"struct" => |st| if (st.is_tuple) T else struct {T},
        else => struct {T}
    };

    const sigt_info = @typeInfo(SignalT).@"struct";

    if (opts.param_names) |names| {
        if (sigt_info.fields.len != names.len) @compileError("opts.param_names.len != sigt_info.fields.len");
    }

    if (opts.param_types) |types| {
        if (sigt_info.fields.len != types.len) @compileError("opts.param_types.len != sigt_info.fields.len");
    }

    return packed struct (u0) {
        pub const @".metadata_DBUZ_SIGNAL" = {};
        pub const Signature = SignalT;
        pub const deprecated = opts.deprecated;
        pub const param_names = opts.param_names;
        pub const param_types = opts.param_types;
    };
}

/// Generate type for signal handling. type will have methods .subscribe and .unsubscribe that can be used to attach any callback to remote signal.
pub fn SignalProxy(comptime T: type) type {
    if (!isTypeSerializable(T)) @compileError(@typeName(T) ++ "is not DBus-serializable. Signal must have a serializable signature.");
    const SignalT = switch(@typeInfo(T)) {
        .@"struct" => |st| if (st.is_tuple) T else struct {T},
        else => struct {T}
    };
    var fn_sig_params: []const std.builtin.Type.Fn.Param = &.{};
    inline for (TupleFieldTypeSlice(SignalT)) |Type| {
        fn_sig_params = fn_sig_params ++ .{
            std.builtin.Type.Fn.Param{
                .type = Type,
                .is_generic = false,
                .is_noalias = false,
            }
        };
    }
    const fnSig = @Type(.{
        .@"fn" = .{
            .calling_convention = .auto,
            .is_generic = false,
            .is_var_args = false,
            .return_type = void,
            .params = fn_sig_params ++ .{ std.builtin.Type.Fn.Param{
                .type = ?*anyopaque,
                .is_generic = false,
                .is_noalias = false,
            }},
        }
    });
    return struct {
        pub const Signature = SignalT;
        pub const FnSignature = fnSig;

        const Self = @This();
        const Subscriber = struct {
            receiver: *const FnSignature,
            userdata: ?*anyopaque,
            subtype: SubType = .Persistent,
        };

        const SubType = enum {
            Persistent,
            OneShot,
        };

        subscribers: std.AutoArrayHashMap(usize, Subscriber),

        pub fn init(gpa: std.mem.Allocator) Self {
            return .{
                .subscribers = .init(gpa),
            };
        }

        /// Subscribe receiver to that signal with userdata.
        pub fn subscribe(self: *Self, receiver: *const FnSignature, userdata: ?*anyopaque, subtype: SubType) !void {
            const key = if (userdata) |u| @intFromPtr(u) else @intFromPtr(receiver);
            try self.subscribers.putNoClobber(key, .{
                .receiver = receiver,
                .subtype = subtype,
                .userdata = userdata,
            });
        }

        /// Unsubscribe receiver from that signal
        pub fn unsubscribe(self: *Self, receiver: *const FnSignature, userdata: ?*anyopaque) bool {
            const key = if (userdata) |u| @intFromPtr(u) else @intFromPtr(receiver);
            return self.subscribers.swapRemove(key);
        }

        pub fn receive(self: *Self, m: *Message, a: std.mem.Allocator) !void {
            const r = m.reader() catch return error.OutOfMemory;
            const vals = try r.read(SignalT, a);
            var it = self.subscribers.iterator();
            while (it.next()) |subscriber| {
                const params = vals ++ .{subscriber.value_ptr.userdata};
                @call(.auto, subscriber.value_ptr.receiver, params);
            }
        }

        pub fn deinit(self: *Self) void {
            self.subscribers.deinit();
        }
    };
}


const Interface = @import("Interface.zig");
const Message   = @import("Message.zig");

pub const Dictionary = @import("dict.zig").from;

fn TupleFieldTypeSlice(comptime T: type) []const type {
    if (!@typeInfo(T).@"struct".is_tuple) @compileError("TupleFieldTypeSlice must be only called on tuples.");
    var types: []const type = &.{};
    inline for (@typeInfo(T).@"struct".fields) |field| {
        if (!isTypeSerializable(field.type)) @compileError("Tuple fields must be DBus-serializable, but got unserializable type " ++ @typeName(field.type));
        types = types ++ .{field.type};
    }
    return types;
}

pub fn introspect(comptime T: type) []const u8 {
    var xml: []const u8 = std.fmt.comptimePrint("    <interface name=\"{s}\">\n", .{@field(T, "interface_name")});
    const t_info = @typeInfo(T);
    inline for (t_info.@"struct".decls) |decl| {
        const f = @field(T, decl.name);
        const F = @TypeOf(f);

        if (F != type) continue;

        switch (@typeInfo(f)) {
            .@"struct" => {},
            else => continue,
        }
        if      (@hasDecl(f, ".metadata_DBUZ_METHOD"))   xml = xml ++ introspectMethod(decl.name, f)
        else if (@hasDecl(f, ".metadata_DBUZ_PROPERTY")) xml = xml ++ introspectProperty(decl.name, f)
        else if (@hasDecl(f, ".metadata_DBUZ_SIGNAL"))   xml = xml ++ introspectSignal(decl.name, f);
    }
    xml = xml ++ "    </interface>\n";
    return xml;
}

pub fn introspectMethod(comptime name: []const u8, comptime T: type) []const u8 {
    var xml: []const u8 = std.fmt.comptimePrint((" " ** 8) ++ "<method name=\"{s}\">\n", .{name});
    const Arguments = T.Arguments;
    const ReturnType = T.ReturnType;
    const param_names = T.argument_names;
    const param_types = T.argument_types;

    const params_info = @typeInfo(Arguments).@"struct";
    // const return_info = @typeInfo(ReturnType);

    // TODO: Refine compile error messages.
    if (param_names) |names| {
        if (names.len != params_info.fields.len) @compileError("Invalid fields len to names len.");
    }

    if (param_types) |types| {
        if (types.len != params_info.fields.len) @compileError("Invalid fields len to types len.");
    }

    inline for (params_info.fields, 0..) |param, i| {
        const argname = if (param_names) |names| names[i] else std.fmt.comptimePrint("in{}", .{i});
        const argtype = guessSignature(param.type);
        xml = xml ++ (" " ** 12) ++ std.fmt.comptimePrint("<arg name=\"{s}\" type=\"{s}\" direction=\"in\"/>\n", .{argname, argtype});
    }

    if (param_types) |types| {
        var typehint: []const u8 = "";
        inline for (params_info.fields, 0..) |param, i| {
            const typename = if (types[i]) |t| t else @typeName(param.type);
            typehint = typehint ++ "," ++ typename;
        }
        xml = xml ++ (" " ** 12) ++ std.fmt.comptimePrint("<annotation name=\"com.github.0xCatPKG.DBuz.TypeHint\" value=\"{s}\"/>\n", .{if (typehint.len > 0) typehint[1..] else ""});
    }

    if (ReturnType != void) {
        const outtype: ?[]const u8 = switch (@typeInfo(ReturnType)) {
            .@"error_union" => |eu| if (eu.payload == void) null else guessSignature(eu.payload),
            else => guessSignature(ReturnType),
        };
        if (outtype) |outsig| xml = xml ++ (" " ** 12) ++ std.fmt.comptimePrint("<arg name=\"out0\" type=\"{s}\" direction=\"out\"/>\n", .{outsig});
    }

    if (T.deprecated)
        xml = xml ++ (" " ** 12) ++ "<annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"true\"/>\n";

    if (T.no_reply_expected)
        xml = xml ++ (" " ** 12) ++ "<annotation name=\"org.freedesktop.DBus.Method.NoReply\" value=\"true\"/>\n";

    return xml ++ (" " ** 8) ++ "</method>\n";
}

pub fn introspectProperty(comptime name: []const u8, comptime T: type) []const u8 {
    const proptype = guessSignature(T.Type);
    const access = switch (T.mode) {
        .Read => "read",
        .Write => "write",
        .ReadWrite => "readwrite",
    };

    const has_annotation = T.deprecated != null or T.signal != null;

    var annotations: []const u8 = "";
    if (T.deprecated) |deprecated| annotations += (" " ** 12) ++ std.fmt.comptimePrint("<annotation name=\"org.freedesktop.DBus.Deprecated\" value=\"{}\"/>\n", .{deprecated});
    if (T.signal) |signal| annotations += (" " ** 12) ++ std.fmt.comptimePrint("<annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"{s}\"/>\n", .{@tagName(signal)});

    return (" " ** 8) ++ std.fmt.comptimePrint("<property name=\"{s}\" type=\"{s}\" access=\"{s}\"{s}{s}{s}", .{
        name,
        proptype,
        access,
        if (has_annotation) ">\n" else "/>\n",
        annotations,
        if (has_annotation) (" " ** 8) ++ "</property>\n" else ""
    });
}

pub fn introspectSignal(comptime name: []const u8, comptime T: type) []const u8 {
    const SignalT = T.Signature;
    const param_names = T.param_names;
    const param_types = T.param_types;
    
    const sigt_info = @typeInfo(SignalT).@"struct";

    if (param_names) |names| {
        if (names.len != sigt_info.fields.len) @compileError("names.len != sigt_info.fields.len.");
    }

    if (param_types) |types| {
        if (types.len != sigt_info.fields.len) @compileError("types.len != sigt_info.fields.len.");
    }


    var xml: []const u8 = (" " ** 8) ++ std.fmt.comptimePrint("<signal name=\"{s}\">\n", .{name});
    inline for (sigt_info.fields, 0..) |param, i| {
        const argname = if (param_names) |names| names[i] else std.fmt.comptimePrint("value{}", .{i});
        const argtype = guessSignature(param.type);
        xml = xml ++ (" " ** 12) ++ std.fmt.comptimePrint("<arg name=\"{s}\" type=\"{s}\"/>\n", .{argname, argtype});
    }

    if (param_types) |types| {
        var typehint: []const u8 = "";
        inline for (sigt_info.fields, 0..) |param, i| {
            const typename = if (types[i]) |t| t else @typeName(param.type);
            typehint = typehint ++ "," ++ typename;
        }
        xml ++ (" " ** 12) ++ std.fmt.comptimePrint("<annotation name=\"com.github.0xCatPKG.DBuz.TypeHint\" value=\"{s}\"/>\n", .{if (typehint.len > 0) typehint[1..] else ""});
    }

    return xml ++ (" " ** 8) ++ "</signal>\n";
}

pub inline fn methodList(comptime T: type) []const [:0]const u8 {
    var list: []const [:0]const u8 = &.{};
    
    const template_info = @typeInfo(T);

    inline for (template_info.@"struct".decls) |declaration| {
        const decl = @field(T, declaration.name);

        if (@TypeOf(decl) != type) continue;

        const DeclarationType = decl;

        if (!@hasDecl(DeclarationType, ".metadata_DBUZ_METHOD")) continue;
        const FunctionType = @TypeOf(@field(DeclarationType, "fn"));
        const fntype = @typeInfo(FunctionType).@"fn";

        if (fntype.params.len == 0) @compileError(std.fmt.comptimePrint("public method {s}.{s} has empty signature. Interface expects method prototypes contain at least one parameter of type *<const> Interface", .{
            @typeName(T), declaration.name
        }));    
        list = list ++ .{declaration.name};
    }

    return list;
}

pub inline fn propertyList(comptime T: type) []const [:0]const u8 {
    var list: []const [:0]const u8 = &.{};

    const template_info = @typeInfo(T);
    inline for (template_info.@"struct".decls) |declaration| {
        const decl = @field(T, declaration.name);

        if (@TypeOf(decl) != type) continue;

        const DeclarationType = decl;

        if (!@hasDecl(DeclarationType, ".metadata_DBUZ_PROPERTY")) continue;
        const PropertyType = DeclarationType.Type;

        if (!isTypeSerializable(PropertyType)) @compileError(std.fmt.comptimePrint("dbuz property {s}.{s} has unserializable type {s}. Please make sure to NOT construct dbuz properties manually, use dbuz.types.Property helper instead!", .{@typeName(T), declaration.name, @typeName(PropertyType)}));

        list = list ++ .{declaration.name};
    }

    return list;
}

pub inline fn signalList(comptime T: type) []const [:0]const u8 {
    var list: []const [:0]const u8 = &.{};

    const template_info = @typeInfo(T);
    inline for (template_info.@"struct".decls) |declaration| {
        const decl = @field(T, declaration.name);

        if (@TypeOf(decl) != type) continue;

        const DeclarationType = decl;

        if (!@hasDecl(DeclarationType, ".metadata_DBUZ_SIGNAL")) continue;
        const SignalType = DeclarationType.Signature;

        if (!isTypeSerializable(SignalType)) @compileError(std.fmt.comptimePrint("dbuz signal {s}.{s} has unserializable type {s}. Please make sure to NOT construct dbuz signals manually, use dbuz.types.Signal helper instead!", .{@typeName(T), declaration.name, @typeName(SignalType)}));

        list = list ++ .{declaration.name};
    }

    return list;
}

inline fn sliceContains(comptime T: type, haystack: []const T, needle: T) bool {
    for (haystack) |el| {
        switch (@typeInfo(T)) {
            .pointer => |ptr| {
                if (ptr.size == .slice) if (std.mem.eql(ptr.child, el, needle)) return true;
            },
            else => if (el == needle) return true,
        }
    }
    return false;
}

pub fn PropertiesStorage(comptime T: type) struct {type, type, type} {
    const properties = propertyList(T);

    var struct_fields: []const BuiltinType.StructField    = &.{};
    var type_enum_fields: []const BuiltinType.EnumField   = &.{};
    var name_enum_fields: []const BuiltinType.EnumField   = &.{};
    var type_union_fields: []const BuiltinType.UnionField = &.{};

    var added_sigs: []const []const u8 = &.{};

    for (properties, 0..) |property_name, i| {
        const Prop = @field(T, property_name);
        const propsig = guessSignature(Prop.Type);

        struct_fields = struct_fields ++ .{ BuiltinType.StructField{
            .name = property_name,
            .type = Prop.Type,
            .alignment = @alignOf(Prop.Type),
            .default_value_ptr = Prop.default_value,
            .is_comptime = false,
        }};

        if (!sliceContains([]const u8, added_sigs, propsig)) {
            type_enum_fields = type_enum_fields ++ .{ BuiltinType.EnumField{
                .name = propsig,
                .value = type_enum_fields.len,
            }};
            type_union_fields = type_union_fields ++ .{BuiltinType.UnionField{
                .name = propsig,
                .alignment = @alignOf(Prop.Type),
                .type = Prop.Type,
            }};
            added_sigs = added_sigs ++ .{ propsig };
        }

        name_enum_fields = name_enum_fields ++ .{
            BuiltinType.EnumField{
                .name = property_name,
                .value = i,
            }
        };
    }

    struct_fields = struct_fields ++ .{
        BuiltinType.StructField{
            .name = "_mutex",
            .type = std.Thread.Mutex,
            .alignment = @alignOf(std.Thread.Mutex),
            .default_value_ptr = &std.Thread.Mutex{},
            .is_comptime = false,
        },
        BuiltinType.StructField{
            .name = "_inited",
            .type = bool,
            .alignment = @alignOf(bool),
            .default_value_ptr = &false,
            .is_comptime = false,
        }
    };

    const TypeEnum = @Type(.{
        .@"enum" = .{
            .decls = &.{},
            .fields = type_enum_fields,
            .is_exhaustive = true,
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
    const NameEnum = @Type(.{
        .@"enum" = .{
            .decls = &.{},
            .fields = name_enum_fields,
            .tag_type = u32,
            .is_exhaustive = true,
        }
    });

    return .{@Type(.{
        .@"struct" = .{
            .decls = &.{},
            .fields = struct_fields,
            .layout = .auto,
            .is_tuple = false,
        }
    }), TypeUnion, NameEnum};
}

pub fn SignalListener(comptime T: type) type {
    const signals = signalList(T);

    var sfields: []const BuiltinType.StructField = &.{};
    for (signals) |signame| {
        const S = @field(T, signame);
        var params: []const BuiltinType.Fn.Param = &.{};

        const sig_info = @typeInfo(S.Signature).@"struct";
        for (sig_info.fields) |field| {
            params = params ++ .{ BuiltinType.Fn.Param{ 
                .type = field.type,
                .is_noalias = false,
                .is_generic = false,
            } };
        }
        params = params ++ .{ BuiltinType.Fn.Param{
            .type = ?*anyopaque,
            .is_noalias = false,
            .is_generic = false,
        } };

        const SigFn = @Type(.{
            .@"fn" = .{
                .calling_convention = .auto,
                .is_generic = false,
                .is_var_args = false,
                .return_type = void,
                .params = params
            }
        });

        sfields = sfields ++ .{ BuiltinType.StructField{
            .name = signame,
            .type = ?*const SigFn,
            .alignment = @alignOf(?*const SigFn),
            .default_value_ptr = null,
            .is_comptime = false
        } };
    }

    sfields = sfields ++ .{ BuiltinType.StructField{
        .name = "userdata",
        .type = ?*anyopaque,
        .alignment = @alignOf(?*anyopaque),
        .default_value_ptr = null,
        .is_comptime = false
    } };
    return @Type(.{
        .@"struct" = .{
            .backing_integer = null,
            .decls = &.{},
            .fields = sfields,
            .is_tuple = false,
            .layout = .auto
        }
    });
}

pub const SignalListenerPersistance = enum (u8) {
    Persistent,
    OneShot,
};

pub fn SignalManager(comptime T: type) type {
    const signals = signalList(T);
    const SignalListenerT = SignalListener(T);

    return struct {
        const Self = @This();

        pub const Template = T;
        pub const Listener = SignalListenerT;

        listener: Listener,

        pub fn init(listener: Listener) Self {
            return .{ .listener = listener };
        }

        pub fn handle(s: *Self, m: *Message, gpa: std.mem.Allocator) error{Unhandled,HandlingFailed}!void {
            const r = m.reader() catch return error.HandlingFailed;
            inline for (signals) |signame| {
                if (!std.mem.eql(u8, m.fields.member.?, signame)) comptime continue;
                if (@field(s.listener, signame)) |handler| {
                    const v = r.read(@field(T, signame).Signature, gpa) catch return error.HandlingFailed;
                    const call_params = v ++ .{ s.listener.userdata };
                    return @call(.auto, handler, call_params);
                }
            }
            return error.Unhandled;
        }
    };
}

pub fn dupeValue(gpa: std.mem.Allocator, v: anytype) !@TypeOf(v) {
    const T = @TypeOf(v);
    const t_info = @typeInfo(T);

    switch (T) {
        String, ObjectPath, Signature => {
            return T{ .value = try gpa.dupe(u8, v.value), .ownership = true };
        },
        else => {},
    }

    return switch (t_info) {
        .pointer => |ptr| slice: {
            std.debug.assert(ptr.size == .slice);
            const aSlice = try gpa.alloc(ptr.child, v.len);
            var trackedSlice: []ptr.child = aSlice[0..0];

            errdefer {
                for (trackedSlice) |el| {
                    deinitValueRecursive(gpa, el);
                }
                gpa.free(aSlice);
            }

            for (0..v.len) |i| {
                aSlice[i] = try dupeValue(gpa, v[i]);
                trackedSlice.len += 1;
            }

            break :slice aSlice;
        },
        .@"struct" => |st| st_blk: {
            if (comptime isDict(T)) {
                var dict = T.init(gpa);
                errdefer dict.deinit();

                errdefer {
                    var it = dict.iterator();
                    while (it.next()) |kv| {
                        deinitValueRecursive(gpa, kv.key_ptr.*);
                        deinitValueRecursive(gpa, kv.value_ptr.*);
                    }
                }

                var it = v.iterator();
                while (it.next()) |kv| {
                    const key = try dupeValue(gpa, kv.key_ptr.*);
                    errdefer deinitValueRecursive(gpa, key);

                    const value = try dupeValue(gpa, kv.value_ptr.*);
                    errdefer deinitValueRecursive(gpa, value);

                    try dict.putNoClobber(key, value);
                }

                break :st_blk dict;
            }
            else if (comptime isFileHandle(T)) {
                const handle: T = .{ .handle = try std.posix.dup(v.handle) };
                break :st_blk handle;
            }
            else {
                var res: T = undefined;
                var filled_fields: usize = 0;
                errdefer for (0..filled_fields) |i| deinitValueRecursive(gpa, @field(res, st.fields[i]));

                inline for (st.fields) |field| {
                    @field(res, field.name) = try dupeValue(gpa, @field(v, field.name));
                    filled_fields += 1;
                }

                break :st_blk res;
            }
        },
        .@"union" => |un| un_blk: {
            inline for (un.fields) |field| {
                if (!std.mem.eql(u8, field.name, @tagName(v))) comptime continue;
                break :un_blk @unionInit(T, field.name, try dupeValue(gpa, @field(v, field.name)));
            }
            unreachable;
        },
        else => v,
    };
}

pub fn Variant(comptime types: []const type) type {
    @setEvalBranchQuota(10000);
    var variant_enum_fields: []const BuiltinType.EnumField = &.{};
    var variant_union_fields: []const BuiltinType.UnionField = &.{};
    var added_signatures: []const []const u8 = &.{};

    for (types) |T| {
        if (!isTypeSerializable(T)) @compileError(std.fmt.comptimePrint("Type {s} is not DBus-serializable.", .{T}));
        const signature = guessSignature(T);

        if (sliceContains([]const u8, added_signatures, signature)) continue;

        variant_enum_fields = variant_enum_fields ++ .{
            BuiltinType.EnumField{
                .name = signature,
                .value = variant_enum_fields.len,
            }
        };
        variant_union_fields = variant_union_fields ++ .{
            BuiltinType.UnionField{
                .name = signature,
                .type = T,
                .alignment = @alignOf(T),
            }
        };
        added_signatures = added_signatures ++ .{ signature };
    }

    const TypeEnum = @Type(.{
        .@"enum" = .{
            .fields = variant_enum_fields,
            .decls = &.{},
            .is_exhaustive = true,
            .tag_type = u32,
        }
    });
    return @Type(.{
        .@"union" = .{
            .decls = &.{},
            .fields = variant_union_fields,
            .tag_type = TypeEnum,
            .layout = .auto,
        }
    });
}

const BuiltinType = std.builtin.Type;
