const std = @import("std");
// const config = @import("dbus_encoder_config");

const config = struct {
    pub const primitive_lowering: enum { strict, expanded } = .expanded;
};

const encoding = @import("../encoding.zig");
const serialization = @import("serialization.zig");

pub const ContainerType = enum {
    @"struct",
    dict,
};

inline fn lowerPrimitiveExpanded(comptime T: type) ?type {
    const tinfo = @typeInfo(T);
    switch (tinfo) {
        .@"anyframe", .@"fn", .optional, .@"opaque", .@"union", .error_set, .error_union, .enum_literal, .@"struct", .frame, .@"enum", .noreturn, .null, .comptime_int, .pointer, .array, .type, .vector, .void, .undefined => return null,

        .comptime_float => return f64,
        .bool => return bool,
        .float => return f64,
        .int => |info| {
            const signedness = info.signedness;
            return if (info.bits <= 8) u8 else if (info.bits <= 16) @Int(signedness, 16) else if (info.bits <= 32) @Int(signedness, 32) else if (info.bits <= 64) @Int(signedness, 64) else @panic("Passed integer is too high for dbus serialization");
        },
    }
    return null;
}

inline fn lowerPrimitiveStrict(comptime T: type) ?type {
    const tinfo = @typeInfo(T);
    switch (tinfo) {
        .@"anyframe", .@"fn", .optional, .@"opaque", .@"union", .error_set, .error_union, .enum_literal, .@"struct", .frame, .@"enum", .noreturn, .null, .comptime_int, .pointer, .array, .type, .vector, .void, .undefined => return null,
        .comptime_float => null,
        .bool => return bool,
        .float => |info| return if (info.bits == 64) return f64 else null,
        .int => {
            inline for ([_]type{ u8, u16, i16, u32, i32, u64, i64 }) |t| if (t == T) return T;
            return null;
        },
    }
    return null;
}

pub const lowerPrimitive: fn (comptime T: type) callconv(.@"inline") ?type = if (config.primitive_lowering == .strict) lowerPrimitiveStrict else lowerPrimitiveExpanded;

const TypeAlignmentPair = struct { type, []const u8, std.mem.Alignment };
const TYPE_MAP = [_]TypeAlignmentPair{
    .{ u8, "y", .of(u8) },
    .{ u16, "q", .of(u16) },
    .{ i16, "n", .of(i16) },
    .{ u32, "u", .of(u32) },
    .{ i32, "i", .of(i32) },
    .{ u64, "t", .of(u64) },
    .{ i64, "q", .of(i64) },
    .{ f64, "d", .of(f64) },
    .{ bool, "b", .of(u32) },
};

pub inline fn typeCode(comptime T: type) ?struct { []const u8, std.mem.Alignment } {
    inline for (TYPE_MAP) |entry| {
        const t, const code, const alignment = entry;
        comptime if (T == t) return .{ code, alignment };
    }
    return null;
}

const TypeDiagnostics = struct {
    type_stack: []const type = &.{},
    field_stack: []const []const u8 = &.{},

    pub fn panic(comptime td: *const TypeDiagnostics, comptime T: type, comptime fmt: []const u8, args: anytype) noreturn {
        if (!@inComptime()) unreachable;
        comptime var message: []const u8 = std.fmt.comptimePrint("type {s} could not be used for dbus serialization: " ++ fmt, .{@typeName(T)} ++ args);
        if (td.type_stack.len != 0) {
            message = message ++ "\n";
            message = message ++ std.fmt.comptimePrint("error caused by field in following field chain: {{root}}", .{});
            inline for (td.field_stack) |field_name| {
                message = message ++ std.fmt.comptimePrint("->{f}", .{std.zig.fmtId(field_name)});
            }
            message = message ++ " <<<\n(note: type chain view: ";
            inline for (td.type_stack[0 .. td.type_stack.len - 1]) |FieldT| {
                message = message ++ std.fmt.comptimePrint("{s}->", .{@typeName(FieldT)});
            }
            message = message ++ std.fmt.comptimePrint("{s})", .{@typeName(T)});
        }
        @compileError(message);
    }

    pub fn push(
        comptime td: *TypeDiagnostics,
        comptime T: type,
        comptime field: []const u8,
    ) void {
        if (!@inComptime()) unreachable;
        td.type_stack = td.type_stack ++ .{T};
        td.field_stack = td.field_stack ++ .{field};
    }

    pub fn pop(comptime td: *TypeDiagnostics) void {
        if (!@inComptime()) unreachable;
        td.type_stack = td.type_stack[0 .. td.type_stack.len - 1];
        td.field_stack = td.field_stack[0 .. td.field_stack.len - 1];
    }
};

pub inline fn analyzeTypeChain(comptime T: type, comptime diagnostics: ?*TypeDiagnostics) void {
    comptime var td: TypeDiagnostics = .{};
    comptime var tdp = diagnostics orelse &td;

    const tinfo = @typeInfo(T);
    return switch (tinfo) {
        .int, .float, .bool => _ = lowerPrimitive(T) orelse comptime tdp.panic(T, "{t} could not be lowered to dbus primitive", .{tinfo}),
        .array => |info| {
            comptime tdp.push(T, "typeInfo.child");
            analyzeTypeChain(info.child, tdp);
            comptime tdp.pop();
        },
        .comptime_float => if (config.primitive_lowering != .expanded) comptime tdp.panic(T, "comptime_float could not be lowered on strict primitive_lowering build option", .{}),
        .@"enum" => |info| _ = lowerPrimitive(info.tag_type) orelse comptime tdp.panic(T, "enum's tag type could not be lowered to integer type allowed by dbus"),
        .@"opaque" => if (!@hasDecl(T, "dbus_signature")) comptime tdp.panic(T, "opaque type requires dbus_signature declaration in order to be dbus serializable", .{}),
        .vector => |info| {
            comptime tdp.push(T, "typeInfo.child");
            analyzeTypeChain(info.child, tdp);
            comptime tdp.pop();
        },
        .@"struct" => |info| {
            if (@hasDecl(T, "dbus_signature")) return;
            if (info.layout == .@"packed")
                _ = lowerPrimitive(info.backing_integer.?) orelse comptime tdp.panic(T, "struct's backing integer could not be lowered to integer type allowed by dbus", .{});
            @setEvalBranchQuota(info.fields.len * 1000);
            inline for (info.fields) |field| {
                comptime tdp.push(T, field.name);
                analyzeTypeChain(field.type, tdp);
                comptime tdp.pop();
            }
        },
        .void => {},
        .pointer => |info| {
            if (info.size != .slice and switch (@typeInfo(info.child)) {
                .@"opaque" => true,
                else => false,
            }) {
                comptime tdp.push(T, "typeInfo.child");
                analyzeTypeChain(info.child, tdp);
                comptime tdp.pop();
            }
            if (info.size == .slice) {
                comptime tdp.push(T, "typeInfo.child");
                analyzeTypeChain(info.child, tdp);
                comptime tdp.pop();
            }
        },
        .@"union" => |info| {
            if (@hasDecl(T, "dbus_signature")) return;
            if (info.tag_type == null) comptime tdp.panic(T, "dbus serialization only supports tagged unions, but tag type is null", .{});
            @setEvalBranchQuota(info.fields.len * 1000);
            inline for (info.fields) |field| {
                comptime tdp.push(T, field.name);
                analyzeTypeChain(field.type, tdp);
                comptime tdp.pop();
            }
        },
        else => comptime tdp.panic(T, "type is not mappable to any dbus serializable type", .{}),
    };
}

pub const ObjectPath = struct {
    pub const dbus_signature = "o";
    pub const dbus_alignment: std.mem.Alignment = .of(u32);

    slice: [:0]const u8,

    pub const Error = error{InvalidPath};
    pub fn as(s: [:0]const u8) Error!ObjectPath {
        if (s.len == 0) return error.InvalidPath else if (s[0] != '/') return error.InvalidPath else if (blk: {
            for (s) |c|
                switch (c) {
                    'a'...'z', 'A'...'Z', '0'...'9', '_', '/' => continue,
                    else => break :blk true,
                }
            else
                break :blk false;
        }) return error.InvalidPath else if (std.mem.find(u8, s, "//") != null) return error.InvalidPath else if (s.len != 1 and s[s.len - 1] == '/') return error.InvalidPath else {
            @branchHint(.likely);
            return .{ .slice = s };
        }
    }

    pub inline fn write(self: ?*const ObjectPath, w: *std.Io.Writer, endian: std.builtin.Endian) serialization.Error!struct { bool, usize } {
        if (serialization.inSizeCheck(self)) return .{ true, 5 };
        return .{ true, try serialization.writeSliceSentinel([:0]const u8, w, &self.?.slice, endian, null) };
    }
};

pub const Signature = struct {
    pub const dbus_signature = "g";
    pub const dbus_alignment: std.mem.Alignment = .of(u8);

    slice: [:0]const u8,

    pub const Error = error{ SliceTooLarge, InvalidTypeCodeEncountered };
    pub fn as(s: [:0]const u8) Error!Signature {
        if (s.len > 255) return error.SliceTooLarge;
        for (s) |c| if (std.mem.findScalar(u8, "aybnqiuxtdhsog(){}", c) == null) return error.InvalidTypeCodeEncountered;
        return .{ .slice = s };
    }

    pub inline fn write(self: ?*const Signature, w: *std.Io.Writer, _: std.builtin.Endian) serialization.Error!struct { bool, usize } {
        if (serialization.inSizeCheck(self)) return .{ true, 2 };
        try w.writeByte(@truncate(self.?.slice.len));
        const sentinel = std.mem.absorbSentinel(self.?.slice);
        return .{ true, try w.write(sentinel) };
    }
};

pub const ResolvedT = struct {
    T: type,
    signature: []const u8,
    alignment: comptime_int,
};

pub const DBusTypeMetadata = struct {
    source_type: type,
    maybe_lowered: ?type,
    signature: []const u8,
    alignment: std.mem.Alignment,

    pub inline fn custom(comptime T: type) DBusTypeMetadata {
        return .{
            .source_type = T,
            .maybe_lowered = null,
            .signature = T.dbus_signature,
            .alignment = if (@hasDecl(T, "dbus_alignment")) T.dbus_alignment else .of(u8),
        };
    }
};

pub fn coerceUnsafe(comptime T: type, value: anytype) T {
    if (@TypeOf(value) == T) return value;

    const dst_info = @typeInfo(T);
    const src_info = @typeInfo(@TypeOf(value));
    return switch (dst_info) {
        .int => |info| switch (src_info) {
            .int => |sinfo| blk: {
                if (sinfo.bits == info.bits) break :blk @bitCast(value);
                const CoercableT = if (sinfo.signedness != info.signedness) @Int(sinfo.signedness, info.bits) else T;
                const new_int = if (sinfo.bits > info.bits)
                    @as(CoercableT, @truncate(value))
                else if (sinfo.bits < info.bits)
                    @as(CoercableT, @intCast(value))
                else
                    @as(CoercableT, value);
                break :blk @bitCast(new_int);
            },
            .@"struct" => |sinfo| blk: {
                if (sinfo.layout != .@"packed")
                    compileFmtError("Could not coerce value of type {s} to {s}: Source value is not a packed struct", .{ @typeName(@TypeOf(value)), @typeName(T) });

                const int_info = @typeInfo(sinfo.backing_integer.?).int;
                if (int_info.bits == info.bits) break :blk @bitCast(value);
                if (int_info.bits > info.bits) compileFmtError("Could not coerce value of type {s} to {s}; Backing integer expresses more values than destination can fit.", .{ @typeName(@TypeOf(value)), @typeName(T) });
                const val: sinfo.backing_integer.? = @bitCast(value);
                break :blk @intCast(val);
            },
            .@"enum" => @intFromEnum(value),
            .undefined => undefined,
            else => compileFmtError("Value of type {t} could not be coerced into integer of any length; Only enums, packed structs and integers itself are allowed", .{src_info}),
        },
        .float => @floatCast(value),
        .bool => value,
        .@"enum" => |info| blk: {
            const tag_info = @typeInfo(info.tag_type).int;
            switch (src_info) {
                .int => |iinfo| if (tag_info.bits < iinfo.bits) compileFmtError("Unable to coerce integer of type {s} to shorter enum", .{@typeName(@TypeOf(value))}),
                else => |t| compileFmtError("Value of type {t} could not be coerced to enum, only integers are supported", .{t}),
            }
            break :blk @enumFromInt(value);
        },
        .@"struct" => |info| blk: {
            if (info.layout != .@"packed") compileFmtError("No value can be coerced to struct {s}: Only packed structs are supported", .{@typeName(T)});
            const backing_info = @typeInfo(info.backing_integer.?).int;
            switch (src_info) {
                .int => |iinfo| {
                    if (iinfo.bits != backing_info.bits) compileFmtError("Could not coerce any value to struct {s}: source and destination bit length differs", .{@typeName(T)});
                },
                else => |t| compileFmtError("Value of type {t} could not be coerced to the packed struct", .{t}),
            }
            break :blk @bitCast(value);
        },
        .optional => |info| coerce(info.child, value),
        .void => {},
        .pointer => blk: {
            const SrcT = @TypeOf(value);
            if (T == [:0]const u8) switch (SrcT) {
                Signature, ObjectPath => break :blk value.slice,
                else => {},
            };
            compileFmtError("Unable to coerce value of type {s} to {s}: Unsupported", .{ @typeName(SrcT), @typeName(T) });
        },

        else => compileFmtError("Unable to coerce source value of type {t} to the {t}", .{ src_info, dst_info }),
    };
}

inline fn isDBusString(comptime T: type) bool {
    const t_info = @typeInfo(T);
    return switch (t_info) {
        .array => |info| if (info.child == u8) info.sentinel() == 0 else false,
        .pointer => |info| if (info.size == .slice and info.child == u8) info.sentinel() == 0 else false,
        else => unreachable,
    };
}

pub fn resolveTypeMetadata(comptime T: type) DBusTypeMetadata {
    const typeinfo = @typeInfo(T);
    switch (typeinfo) {
        .int, .comptime_float, .float, .bool => {
            const Primitive = lowerPrimitive(T) orelse unreachable;
            const type_code, const alignment = typeCode(Primitive) orelse unreachable;
            return .{ .source_type = T, .maybe_lowered = Primitive, .signature = type_code, .alignment = alignment };
        },
        .@"enum" => |info| {
            if (@hasDecl(T, "dbus_signature")) return .custom(T);
            const Primitive = lowerPrimitive(info.tag_type) orelse compileFmtError("Unable to lower enum {s} to dbus serializable primitive", .{@typeName(T)});
            const type_code, const alignment = typeCode(Primitive) orelse unreachable;
            return .{ .source_type = T, .maybe_lowered = Primitive, .signature = type_code, .alignment = alignment };
        },
        .@"struct" => |info| {
            if (@hasDecl(T, "dbus_signature")) return .custom(T);
            if (info.layout != .@"packed") return .{ .source_type = T, .maybe_lowered = null, .signature = "", .alignment = .of(u64) };
            const Primitive = lowerPrimitive(info.backing_integer.?) orelse unreachable;
            const type_code, const alignment = typeCode(Primitive) orelse unreachable;
            return .{ .source_type = T, .maybe_lowered = Primitive, .signature = type_code, .alignment = alignment };
        },
        .@"union" => return .{
            .source_type = T,
            .maybe_lowered = null,
            .signature = if (@hasDecl(T, "dbus_signature")) T.dbus_signature else "v",
            .alignment = if (@hasDecl(T, "dbus_alignment")) T.dbus_alignment else .of(u8),
        },
        .@"opaque" => return .custom(T),
        .array => |info| {
            comptime if (isDBusString(T)) return .{ .source_type = T, .maybe_lowered = null, .signature = "s", .alignment = .of(u32) };
            const child_meta = resolveTypeMetadata(info.child);
            if (child_meta.maybe_lowered) |Primitive| {
                return .{ .source_type = T, .maybe_lowered = if (info.sentinel()) |sentinel| [info.len:coerce(Primitive, sentinel)]Primitive else [info.len]Primitive, .signature = "a", .alignment = .of(u32) };
            }
            return .{ .source_type = T, .maybe_lowered = null, .signature = "a", .alignment = .of(u32) };
        },
        .pointer => |info| {
            comptime if (info.size != .slice) compileFmtError("Non-slice pointer {s} is not allowed for dbus serialization", .{@typeName(T)});
            comptime if (isDBusString(T)) return .{ .source_type = T, .maybe_lowered = null, .signature = "s", .alignment = .of(u32) };
            const child_metadata = resolveTypeMetadata(info.child);
            if (child_metadata.maybe_lowered) |Primitive| {
                return .{ .source_type = T, .maybe_lowered = if (info.sentinel()) |sentinel| [:coerce(Primitive, sentinel)]const Primitive else []const Primitive, .signature = "a", .alignment = .of(u32) };
            }
            return .{ .source_type = T, .maybe_lowered = null, .signature = "", .alignment = .of(u8) };
        },
        .vector => |info| {
            const child_metadata = resolveTypeMetadata(info.child);
            if (child_metadata.maybe_lowered) |Primitive| {
                return .{ .source_type = T, .maybe_lowered = @Vector(info.len, Primitive), .signature = "a", .alignment = .of(u32) };
            }
            compileFmtError("Vector of type {s} is Unsupported", .{@typeName(info.child)});
        },
        .void => return .{ .source_type = void, .maybe_lowered = null, .signature = "", .alignment = .of(u8) },
        .undefined, .@"fn", .@"anyframe", .enum_literal, .error_set, .error_union, .frame, .noreturn, .null, .type, .optional => compileFmtError("Unable to resolve type {s}: Not supported by encoder", .{@typeName(T)}),
        .comptime_int => unreachable,
    }
    unreachable;
}

test coerceUnsafe {
    const v = 1.0;
    _ = coerce(lowerPrimitive(@TypeOf(v)) orelse @panic("Uncastable"), v);

    const PackedStruct = packed struct(u32) { someval: u3, _: u29 = 0 };

    const Enum = enum(u64) {
        a = 6,
        b = 7,
        c = 2 << 33,
    };

    _ = coerce(u33, PackedStruct{ .someval = 2 });
    _ = coerce(u64, Enum.c);
    _ = coerce(bool, true);
    _ = coerce(void, "hello");
    _ = coerce(PackedStruct, @as(u32, 2));
    _ = coerce(Enum, @as(u64, 6));
}

pub const coerce: fn (comptime as: type, value: anytype) type = coerceUnsafe;

comptime {
    const assert = std.debug.assert;
    assert(@sizeOf(ObjectPath) <= 16);
    assert(@sizeOf(Signature) <= 16);
}

inline fn compileFmtError(comptime fmt: []const u8, args: anytype) noreturn {
    @compileError(std.fmt.comptimePrint(fmt, args));
}

test resolveTypeMetadata {
    _ = comptime resolveTypeMetadata(union(enum) {
        @" ",
        u: u32,
        s: [:0]const u8,
    });
}

test ObjectPath {
    _ = try ObjectPath.as("/");
    _ = try ObjectPath.as("/hi");
    _ = try ObjectPath.as("/Hello/123");
    _ = try ObjectPath.as("/org/freedesktop/DBus");
    _ = try ObjectPath.as("/some/under_score");
    try std.testing.expect(ObjectPath.as("") == error.InvalidPath);
    try std.testing.expect(ObjectPath.as("/a//b") == error.InvalidPath);
    try std.testing.expect(ObjectPath.as("/c/") == error.InvalidPath);
    try std.testing.expect(ObjectPath.as("./") == error.InvalidPath);
    try std.testing.expect(ObjectPath.as("buhbus") == error.InvalidPath);
}

test Signature {
    _ = try Signature.as("");
    _ = try Signature.as("aabb");
    try std.testing.expect(Signature.as("code") == Signature.Error.InvalidTypeCodeEncountered);
    try std.testing.expect(Signature.as("a" ** 256) == Signature.Error.SliceTooLarge);
}

test analyzeTypeChain {
    comptime analyzeTypeChain(i13, null);
    comptime analyzeTypeChain(bool, null);
    comptime analyzeTypeChain(struct {}, null);
    comptime analyzeTypeChain(struct { fuck: i1 }, null);
    comptime analyzeTypeChain([]const u8, null);
    comptime analyzeTypeChain([:0]const u8, null);
    comptime analyzeTypeChain([]const u2, null);
    comptime analyzeTypeChain([:1]const i7, null);
    comptime analyzeTypeChain([]const ObjectPath, null);
}
