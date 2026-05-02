const std = @import("std");
const mem = std.mem;
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const Endian = std.builtin.Endian;
const Io = std.Io;

pub const Error = error{SignatureTooLong} || Io.Writer.Error;

const assert = std.debug.assert;

pub fn getSerializer(comptime T: type) type {
    types.analyzeTypeChain(T, null);
    return struct {
        pub const DataType = T;
        const Serializer = @This();

        pub const attrs: struct {
            size: usize,
            pure: bool,
        } = blk: {
            var counting_discarder = Io.Writer.Discarding.init(&.{});
            const w = &counting_discarder.writer;

            const tainted, const size = write(w, null, .native, null) catch unreachable;
            break :blk .{
                .size = @max(size, counting_discarder.fullCount()),
                .pure = !tainted,
            };
        };

        pub fn write(w: *Io.Writer, value: ?*const DataType, endian: Endian, signature_writer: ?*Io.Writer) Error!struct { bool, usize } {
            const taints, const written = try writeType(DataType, w, value, endian, signature_writer);
            return .{ taints, written };
        }
    };
}

pub inline fn writeType(comptime T: type, w: *Io.Writer, value: ?*const T, endian: Endian, signature_writer: ?*Io.Writer) Error!struct { bool, usize } {
    const type_info = @typeInfo(T);
    const metadata = types.resolveTypeMetadata(T);

    const sw_end = if (signature_writer) |sw| sw.end else 0;
    errdefer if (signature_writer) |sw| {
        sw.end = sw_end;
    };
    if (signature_writer) |sw| _ = sw.write(metadata.signature) catch return Error.SignatureTooLong;

    return switch (type_info) {
        .int, .float, .comptime_float => .{ false, try writePrimitive(metadata.maybe_lowered.?, w, if (inSizeCheck(value)) undefined else types.coerce(metadata.maybe_lowered.?, value.?.*), endian) },
        .bool => .{ false, try writePrimitive(bool, w, if (inSizeCheck(value)) undefined else value.?.*, endian) },
        .@"enum" => try writeMaybeCustom(T, w, value, endian) orelse .{ false, try writePrimitive(metadata.maybe_lowered.?, w, if (inSizeCheck(value)) undefined else types.coerce(metadata.maybe_lowered.?, value.?.*), endian) },
        .@"opaque" => try writeMaybeCustom(T, w, value, endian) orelse unreachable,
        .@"struct" => try writeMaybeCustom(T, w, value, endian) orelse
            if (metadata.maybe_lowered) |Primitive| .{ false, try writePrimitive(Primitive, w, types.coerce(Primitive, if (inSizeCheck(value)) undefined else value.?.*), endian) } else writeContainer(T, .@"struct", w, value, endian, signature_writer),
        .@"union" => try writeMaybeCustom(T, w, value, endian) orelse writeVariant(T, w, value, endian),
        .array => try writeArray(T, w, value, endian, signature_writer),
        .pointer => |info| {
            if (info.child == anyopaque and info.size == .one) return try writeMaybeCustom(T, w, value, endian) orelse unreachable;
            assert(info.size == .slice);

            return .{ true, if (info.sentinel() != null)
                try writeSliceSentinel(T, w, value, endian, signature_writer)
            else
                try writeSlice(T, w, value, endian, signature_writer) };
        },
        .void => return .{ false, 0 },
        else => unreachable,
    };
}

pub inline fn writeContainer(comptime T: type, comptime container_type: types.ContainerType, w: *Io.Writer, value: ?*const T, endian: Endian, signature_writer: ?*Io.Writer) Error!struct { bool, usize } {
    const s_info = @typeInfo(T).@"struct";
    comptime if (container_type == .dict) assert(s_info.fields.len == 2);

    @setEvalBranchQuota(1000 * s_info.fields.len);

    var written: usize = try alignWriter(w, .of(u64));
    var tainted: bool = false;

    var discarding: Io.Writer.Discarding = .init(&.{});
    const sw = signature_writer orelse &discarding.writer;

    sw.writeByte(switch (container_type) {
        .@"struct" => '(',
        .dict => "{",
    }) catch return Error.SignatureTooLong;

    inline for (s_info.fields) |field| {
        const taints, const field_size = try writeType(field.type, w, if (value) |data| &@field(data.*, field.name) else null, endian, sw);
        if (taints) tainted = true;
        written += field_size;
    }

    sw.writeByte(switch (container_type) {
        .@"struct" => ')',
        .dict => ')',
    }) catch return Error.SignatureTooLong;

    return .{ tainted, written };
}

pub inline fn writeVariant(comptime T: type, w: *Io.Writer, value: ?*const T, endian: Endian) Error!struct { bool, usize } {
    const u_info = @typeInfo(T).@"union";

    const max_payload_size: usize, const max_sig_size: usize, const max_alignment: Alignment, const taints: bool =
        comptime blk: {
            var sizes: @Vector(u_info.fields.len, usize) = @splat(0);
            var sigsizes: @Vector(u_info.fields.len, usize) = @splat(0);
            var alignments: @Vector(u_info.fields.len, u8) = @splat(1);
            var tainters: @Vector(u_info.fields.len, bool) = @splat(false);

            for (u_info.fields, 0..) |field, i| {
                var counting: Io.Writer.Discarding = .init(&.{});
                var sigcounter: Io.Writer.Discarding = .init(&.{});

                const field_meta = types.resolveTypeMetadata(field.type);

                const tainter, _ = writeType(field.type, &counting.writer, null, .native, &sigcounter.writer) catch unreachable;

                if (sigcounter.fullCount() > 255) return Error.SignatureTooLong;
                sizes[i] = counting.fullCount();
                sigsizes[i] = sigcounter.fullCount();
                alignments[i] = @intFromEnum(field_meta.alignment);
                tainters[i] = tainter;
            }

            break :blk .{
                @reduce(.Max, sizes),
                @reduce(.Max, sigsizes),
                @as(Alignment, @enumFromInt(@reduce(.Max, alignments))),
                @reduce(.And, tainters),
            };
        };

    if (@inComptime()) {
        var written: usize = 1;
        try w.writeByte(@truncate(max_sig_size));
        written += try w.splatByte(0, max_sig_size + 1);
        written += try alignWriter(w, max_alignment);
        written += try w.splatByte(0, max_payload_size);
        return .{ taints, written };
    }

    var discarding: Io.Writer.Discarding = .init(&.{});

    var written: usize = 0;

    const active_tag = @tagName(if (inSizeCheck(value)) undefined else value.?.*);
    inline for (u_info.fields) |field| {
        if (!mem.eql(u8, field.name, active_tag)) comptime continue;

        var sigbuf: [max_sig_size:0]u8 = @splat(0);
        var sigw: Io.Writer = .fixed(&sigbuf);
        _ = writeType(field.type, &discarding.writer, &@field(value.?, field.name), endian, &sigw) catch unreachable;

        const sig = types.Signature.as(@ptrCast(sigbuf[0..sigw.end])) catch unreachable;

        _, written = try sig.write(w, endian);
        _, const size = try writeType(field.type, w, &@field(value.?, field.name), endian, null);
        written += size;
        return .{ taints, written };
    }
    unreachable;
}

pub inline fn writePrimitive(comptime T: type, w: *Io.Writer, value: T, endian: Endian) Error!usize {
    switch (T) {
        u8, i16, u16, i32, u32, i64, u64 => {
            const written = try alignWriter(w, .of(T)) + @sizeOf(T);
            try w.writeInt(T, value, endian);
            return written;
        },
        f64 => {
            const written = try alignWriter(w, .of(u64)) + 8;
            try w.writeInt(u64, @bitCast(value), endian);
            return written;
        },
        bool => {
            const written = try alignWriter(w, .of(u32)) + 4;
            try w.writeInt(u32, @intFromBool(value), endian);
            return written;
        },
        else => unreachable,
    }
}

pub inline fn alignWriter(w: *Io.Writer, alignment: Alignment) Error!usize {
    const end = if (@inComptime() and w.vtable == Io.Writer.Discarding.init(&.{}).writer.vtable)
        @as(*Io.Writer.Discarding, @alignCast(@fieldParentPtr("writer", w))).fullCount()
    else
        w.end;
    return w.splatByte(0, alignment.forward(end) - end);
}

pub inline fn writeMaybeCustom(comptime T: type, w: *Io.Writer, value: ?*const T, endian: Endian) Error!?struct { bool, usize } {
    if (@hasDecl(T, "dbus_signature"))
        return try T.write(value, w, endian);
    return null;
}

pub inline fn inSizeCheck(value: anytype) bool {
    return @inComptime() and value == null;
}

pub inline fn writeSlice(comptime T: type, w: *Io.Writer, value: ?*const T, endian: Endian, signature_writer: ?*Io.Writer) Error!usize {
    const slice_info = @typeInfo(T).pointer;
    assert(slice_info.size == .slice);

    const child_metadata = types.resolveTypeMetadata(slice_info.child);

    var written: usize = try alignWriter(w, .of(u32));
    const size_offset = w.end;

    written += try w.splatByte(0, 4);
    written += try alignWriter(w, child_metadata.alignment);

    if (signature_writer) |sw| _ = sw.write(child_metadata.signature) catch return Error.SignatureTooLong;
    if (child_metadata.maybe_lowered) |Primitive| {
        if (inSizeCheck(value)) return written + if (Primitive == bool) 4 else @sizeOf(Primitive);
        if (child_metadata.source_type == Primitive and child_metadata.source_type != bool and endian == Endian.native) {
            @branchHint(.likely);
            const destination = try w.writableSlice(value.?.*.len * @sizeOf(Primitive));
            @memcpy(destination, mem.sliceAsBytes(value.?.*));

            mem.writeInt(u32, w.buffer[size_offset..][0..4], @truncate(destination.len), endian);
            return written + destination.len;
        }
        const requested_size = if (Primitive == bool) value.*.len * 4 else @sizeOf(Primitive) * value.?.*.len;
        const destination = try w.writableSlice(requested_size);
        var fw: Io.Writer = .fixed(destination);
        for (value.?.*) |el| {
            const cast_site = types.coerce(Primitive, el);
            _ = try writeType(Primitive, &fw, &cast_site, endian, null);
        }

        mem.writeInt(u32, w.buffer[size_offset..][0..4], @truncate(destination.len), endian);
        return written + destination.len;
    }

    var payload_size: usize = 0;
    comptime var counting: Io.Writer.Discarding = .init(&.{});

    if (inSizeCheck(value)) {
        @branchHint(.unlikely);
        _ = writeType(slice_info.child, &counting.writer, null, endian, signature_writer);
        return written + counting.fullCount();
    }

    for (value.*, 0..) |*el, i| {
        // Suboptimal codepath
        _, const sz = writeType(slice_info.child, w, el, endian, if (i == 0) signature_writer else null);
        payload_size += sz;
    }

    mem.writeInt(u32, w.buffer[size_offset..][0..4], payload_size, endian);
    return written;
}

pub inline fn writeSliceSentinel(comptime T: type, w: *Io.Writer, value: ?*const T, endian: Endian, signature_writer: ?*Io.Writer) Error!usize {
    const slice_info = @typeInfo(T).pointer;
    assert(slice_info.size == .slice);
    assert(slice_info.sentinel() != null);

    const child_metadata = types.resolveTypeMetadata(slice_info.child);

    var written: usize = try alignWriter(w, .of(u32));
    const size_offset = w.end;

    written += try w.splatByte(0, 4);
    written += try alignWriter(w, child_metadata.alignment);

    if (T == [:0]const u8 or T == [:0]u8) {
        if (inSizeCheck(value)) {
            @branchHint(.unlikely);
            try w.writeByte(1);
            written += 1;
            return written;
        } else {
            @branchHint(.likely);
            const sentinel = mem.absorbSentinel(value.?.*);
            written += try w.write(sentinel);
            mem.writeInt(u32, w.buffer[size_offset..][0..4], @truncate(sentinel.len), endian);
            return written;
        }
    }
    const sentinel = mem.absorbSentinel(value.*);

    if (signature_writer) |sw| _ = sw.write(child_metadata.signature) catch return Error.SignatureTooLong;
    if (child_metadata.maybe_lowered) |Primitive| {
        if (inSizeCheck(value)) return written + if (Primitive == bool) 4 else @sizeOf(Primitive);
        if (child_metadata.source_type == Primitive and child_metadata.source_type != bool and endian == Endian.native) {
            @branchHint(.likely);
            const destination = try w.writableSlice(sentinel.len * @sizeOf(Primitive));
            @memcpy(destination, mem.sliceAsBytes(sentinel));

            mem.writeInt(u32, w.buffer[size_offset..][0..4], @truncate(destination.len), endian);
            return written + destination.len;
        }
        const requested_size = if (Primitive == bool) sentinel.len * 4 else @sizeOf(Primitive) * sentinel.len;
        const destination = try w.writableSlice(requested_size);
        var fw: Io.Writer = .fixed(destination);
        for (value.*) |el| {
            const cast_site = types.coerce(Primitive, el);
            _ = try writeType(Primitive, &fw, &cast_site, endian, null);
        }

        mem.writeInt(u32, w.buffer[size_offset..][0..4], @truncate(destination.len), endian);
        return written + destination.len;
    }

    var payload_size: usize = 0;
    comptime var counting: Io.Writer.Discarding = .init(&.{});

    if (inSizeCheck(value)) {
        @branchHint(.unlikely);
        _ = writeType(slice_info.child, &counting.writer, null, endian, signature_writer);
        return written + counting.fullCount();
    }

    for (sentinel, 0..) |*el, i| {
        // Suboptimal codepath
        _, const sz = writeType(slice_info.child, w, el, endian, if (i == 0) signature_writer else null);
        payload_size += sz;
    }

    mem.writeInt(u32, w.buffer[size_offset..][0..4], payload_size, endian);
    return written;
}

pub inline fn writeArray(comptime T: type, w: *Io.Writer, value: ?*const T, endian: Endian, signature_writer: ?*Io.Writer) Error!struct { bool, usize } {
    const array_info = @typeInfo(T).array;

    const tainted, const alignment, const required_space = comptime blk: {
        const child_metadata = types.resolveTypeMetadata(array_info.child);
        var counting: Io.Writer.Discarding = .init(&.{});

        const taints, _ = writeType(child_metadata.maybe_lowered orelse child_metadata.source_type, &counting.writer, null, .native, null) catch unreachable;
        counting = .init(&.{});

        _ = writeType(child_metadata.maybe_lowered orelse child_metadata.source_type, &counting.writer, null, .native, null) catch unreachable;
        const element_size = counting.fullCount();
        const padding = child_metadata.alignment.forward(counting.fullCount()) - element_size;

        break :blk .{ taints, child_metadata.alignment, (array_info.len * element_size) + (@max(array_info.len - 1, 0) * padding) };
    };

    if (inSizeCheck(value)) {
        @branchHint(.unlikely);
        var written = try writePrimitive(u32, w, 0, .native);
        written += try alignWriter(w, alignment);
        written += try w.splatByte(0, required_space);

        return .{ tainted, written };
    }

    const slice_to_write: if (array_info.sentinel() == null) []const array_info.child else [:array_info.sentinel().?]const array_info.child = value.?;

    return if (array_info.sentinel() == null) .{ tainted, try writeSlice([]const array_info.child, w, &slice_to_write, endian, signature_writer) }
        else .{ tainted, try writeSliceSentinel([:array_info.sentinel().?]const array_info.child, w, &slice_to_write, endian, signature_writer) };
}

pub fn Encoder(comptime T: type) type {
    var buffer_size: usize = 0;
    var pure: bool = true;

    const arg_info = @typeInfo(T).@"struct";
    assert(arg_info.is_tuple);

    var szs: []const type = &.{};

    inline for (arg_info.fields) |arg| {
        const Serializer = getSerializer(arg.type);
        const arg_meta = types.resolveTypeMetadata(arg.type);

        buffer_size = arg_meta.alignment.forward(buffer_size) + Serializer.attrs.size;
        if (!Serializer.attrs.pure) pure = false;
        szs = szs ++ .{Serializer};
    }

    const is_pure = pure;
    const size = buffer_size;
    const serializers = szs;

    return struct {
        pub const Args = T;
        const Self = @This();

        buffer: if (is_pure) [size]u8 else void = if (is_pure) @splat(0) else {},

        gpa: if (is_pure) void else Allocator,
        writer: if (is_pure) Io.Writer else Io.Writer.Allocating,

        pub const Error = (if (is_pure) error{} else Allocator.Error) || error{SignatureTooLong};

        pub fn init(self: *Self, gpa: Allocator) Allocator.Error!void {
            self.* = .{
                .gpa = if (is_pure) {} else gpa,
                .writer = if (is_pure) .fixed(&self.buffer) else try .initCapacity(gpa, size),
            };
        }

        pub fn deinit(self: *Self) void {
            if (!is_pure) {
                self.writer.deinit();
            }
        }

        pub fn interface(self: *Self) *Io.Writer {
            return if (is_pure) &self.writer else &self.writer.writer;
        }

        pub fn buffered(self: *Self) []const u8 {
            return self.interface().buffered();
        }

        pub fn encode(self: *Self, args: Args, endian: Endian, signature_writer: ?*Io.Writer) Self.Error!usize {
            return self.encodeFromPtr(&args, endian, signature_writer);
        }

        pub inline fn encodeFromPtr(self: *Self, args: *const Args, endian: Endian, signature_writer: ?*Io.Writer) Self.Error!usize {
            var written: usize = 0;
            inline for (serializers, args) |Serializer, *arg| {
                _, const data_size = Serializer.write(self.interface(), arg, endian, signature_writer) catch |err| switch (err) {
                    error.WriteFailed => if (!is_pure) return error.OutOfMemory else unreachable,
                    else => |e| return e,
                };
                written += data_size;
            }
            return written;
        }
    };
}

test getSerializer {
    const TypeList: []const type = &.{
        i8, u8,
        i16, u16,
        i32, u32,
        i64, u64,
        f16, f32, f64, f80, f128,
        bool,
        [:0]const u8,
        []const u8,
        [64:0]u8,
        [64]u8,
        types.ObjectPath,
        types.Signature,
        struct { void },
        struct { u8, u16, u32, u64 },
        enum (u8) { x = 0, y = 1, z = 2 },
        union (enum) { x: u8, y: u32, z: u64 },
    };
    inline for (TypeList) |T| {
        const Serializer = getSerializer(T);
        std.testing.refAllDecls(Serializer);
    }
}

test Encoder {
    const AllTypesStruct = struct {
        i8, u8,
        i16, u16,
        i32, u32,
        i64, u64,
        f16, f32, f64, f80, f128,
        bool,
        [:0]const u8,
        []const u8,
        [64:0]u8,
        [64]u8,
        types.ObjectPath,
        types.Signature,
        struct { void },
        struct { u8, u16, u32, u64 },
        enum (u8) { x = 0, y = 1, z = 2 },
        union (enum) { x: u8, y: u32, z: u64 },
    };

    const AllTypes = @Tuple(&.{
        i8, u8,
        i16, u16,
        i32, u32,
        i64, u64,
        f16, f32, f64, f80, f128,
        bool,
        [:0]const u8,
        []const u8,
        [64:0]u8,
        [64]u8,
        types.ObjectPath,
        types.Signature,
        struct { void },
        struct { u8, u16, u32, u64 },
        enum (u8) { x = 0, y = 1, z = 2 },
        union (enum) { x: u8, y: u32, z: u64 },
        AllTypesStruct,
    });

    const Enc = Encoder( AllTypes );
    std.testing.refAllDecls(Enc);
}
