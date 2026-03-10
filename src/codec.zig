//! DBus encoder/decoder
const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const builtin = @import("builtin");

const comptimePrint = std.fmt.comptimePrint;

const types = @import("types/dbus_types.zig");
const String = types.String;
const ObjectPath = types.ObjectPath;
const Signature = types.Signature;

pub const Writer = struct {
    allocator: mem.Allocator,

    position: usize = 0,
    depth: u8 = 0,

    w: *Io.Writer,
    fdlist: ?*std.ArrayList(i32) = null,

    endian: std.builtin.Endian = builtin.target.cpu.arch.endian(),

    pub fn from(allocator: mem.Allocator, writer: *Io.Writer, fdlist: ?*std.ArrayList(i32)) Writer {
        return .{ .allocator = allocator, .w = writer, .fdlist = fdlist };
    }

    pub fn write(self: *Writer, in: anytype) !void {
        const T = @TypeOf(in);
        const tinfo = @typeInfo(T);
        comptime if (!types.isTypeSerializable(T)) @compileError(comptimePrint("Unable to serialize value of type {s}, type doesn't supports dbus serialization", .{ @typeName(T) }));
        switch (T) {
            Signature => {
                try self.w.writeByte(@truncate(in.value.len));
                self.position += 1;

                try self.w.writeAll(in.value);
                self.position += in.value.len;

                try self.w.writeByte(0);
                self.position += 1;
            },
            String, ObjectPath => {
                self.position += try alignBuffer(self.w, 4, self.position);

                try self.w.writeInt(u32, @truncate(in.value.len), self.endian);
                self.position += 4;

                try self.w.writeAll(in.value);
                self.position += in.value.len;

                try self.w.writeByte(0);
                self.position += 1;
            },
            else => {
                switch (tinfo) {
                    .int => |integer| {
                        if (integer.bits <= 8) {
                            try self.w.writeByte(in);
                            self.position += 1;
                        } else if (integer.bits <= 16) {
                            // We don't care about signness of integer, as signed types can be stored in unsigned counterpart without loss of information
                            self.position += try alignBuffer(self.w, 2, self.position);
                            try self.w.writeInt(u16, @bitCast(in), self.endian);
                            self.position += 2;
                        } else if (integer.bits <= 32) {
                            self.position += try alignBuffer(self.w, 4, self.position);
                            try self.w.writeInt(u32, @bitCast(in), self.endian);
                            self.position += 4;
                        } else if (integer.bits <= 64) {
                            self.position += try alignBuffer(self.w, 8, self.position);
                            try self.w.writeInt(u64, @bitCast(in), self.endian);
                            self.position += 8;
                        } else @compileError(comptimePrint("{s} is too wide for DBus. DBus supports integers up to 64 bits", .{@typeName(T)}));
                    },
                    .float => |float| {
                        if (float.bits > 64) @compileError(comptimePrint("DBus supports only doubles. Please use float type with precision lower or equal to 64 bits."));
                        const d: f64 = @floatCast(in);
                        const d_opaque: u64 = @bitCast(d);

                        self.position += try alignBuffer(self.w, 8, self.position);
                        try self.w.writeInt(u64, d_opaque, self.endian);
                        self.position += 8;
                    },
                    .bool => {
                        self.position += try alignBuffer(self.w, 4, self.position);
                        try self.w.writeInt(u32, if (in) 1 else 0, self.endian);
                        self.position += 4;
                    },
                    .comptime_int, .comptime_float => @compileError("Please do not pass comptime_int or comptime_float values directly to writer, use @as to give it a type first."),
                    .pointer => |ptr| {
                        if (ptr.size != .slice) @compileError(comptimePrint("Pointers of type {s} are not supported.", .{@tagName(ptr.size)}));

                        if (self.depth == 63) return error.DepthLimitReached;

                        var container = try Io.Writer.Allocating.initCapacity(self.allocator, @sizeOf(ptr.child) * in.len);
                        defer container.deinit();

                        var w = Writer.from(self.allocator, &container.writer, self.fdlist);
                        w.depth = self.depth + 1;

                        for (in) |child| {
                            try w.write(child);
                        }

                        const container_buffer = container.written();

                        self.position += try alignBuffer(self.w, 4, self.position);
                        try self.w.writeInt(u32, @truncate(container_buffer.len), self.endian);
                        self.position += 4;
                        self.position += try alignBuffer(self.w, typeAlignment(ptr.child), self.position);
                        try self.w.writeAll(container_buffer);
                        self.position += container_buffer.len;
                    },
                    .@"struct" => |st| {
                        if (comptime std.meta.hasMethod(T, "toDBus"))
                            return in.toDBus(self)
                        else if (comptime types.isDict(T)) {
                            if (self.depth == 63) return error.DepthLimitReached;

                            var container = try Io.Writer.Allocating.initCapacity(self.allocator, @sizeOf(T.KV) * in.count());
                            defer container.deinit();

                            var w = Writer.from(self.allocator, &container.writer, self.fdlist);
                            w.depth = self.depth + 1;

                            var it = in.iterator();
                            while (it.next()) |pair| {
                                w.position += try alignBuffer(w.w, 8, w.position);
                                try w.write(pair.key_ptr.*);
                                try w.write(pair.value_ptr.*);
                            }

                            const container_buffer = container.written();

                            self.position += try alignBuffer(self.w, 4, self.position);
                            try self.w.writeInt(u32, @truncate(container_buffer.len), self.endian);
                            self.position += 4;
                            try self.w.writeAll(container_buffer);
                            self.position += container_buffer.len;
                        } else if (comptime types.isFileHandle(T)) {
                            if (self.fdlist == null) return error.UnixFDPassingNotSupported;
                            const index = mem.indexOf(i32, self.fdlist.?.items, &.{in.handle}) orelse blk: {
                                self.fdlist.?.appendBounded(in.handle) catch return error.TooManyFDs;
                                break :blk self.fdlist.?.items.len - 1;
                            };

                            self.position += try alignBuffer(self.w, 4, self.position);
                            try self.w.writeInt(u32, @truncate(index), self.endian);
                            self.position += 1;
                        } else {
                            if (!st.is_tuple) self.position += try alignBuffer(self.w, 8, self.position);
                            inline for (st.fields) |field| {
                                try self.write(@field(in, field.name));
                            }
                        }
                    },
                    .@"union" => |un| {
                        if (comptime std.meta.hasMethod(T, "toDBus"))
                            return in.toDBus(self)
                        else {
                            if (un.tag_type == null) @compileError("Untagged unions are not supported");
                            if (un.fields.len == 0) return;
                            const tag = @tagName(in);
                            inline for (un.fields) |ufield| {
                                if (std.mem.eql(u8, ufield.name, tag)) {
                                    const field_sig = types.guessSignature(ufield.type);
                                    try self.write(Signature{
                                        .value = field_sig,
                                    });
                                    try self.write(@field(in, ufield.name));
                                    return;
                                }
                            }
                            unreachable;
                        }
                    },
                    .@"enum" => |en| {
                        if (comptime std.meta.hasMethod(T, "toDBus"))
                            return in.toDBus(self)
                        else {
                            const val: en.tag_type = @intFromEnum(in);
                            self.write(val);
                        }
                    },
                    .void => {},
                    else => @compileError(comptimePrint("Type {s} is not supported for serialization.", .{@typeName(T)})),
                }
            },
        }
    }

    pub const Container = struct {
        parent: *Writer,
        writer: Writer,
        buffer: Io.Writer.Allocating,

        pub fn init(parent: *Writer, allocator: mem.Allocator, fdlist: ?*std.ArrayList(i32)) !Container {
            var c: Container = .{
                .parent = parent,
                .buffer = try Io.Writer.Allocating.initCapacity(allocator, 256),
                .writer = undefined
            };
            c.writer = Writer.from(allocator, &c.buffer.writer, fdlist);
            c.writer.depth = parent.depth + 1;
            c.writer.endian = parent.endian;
            return c;
        }

        pub fn finish(c: *Container, comptime T: type) !void {
            const container_buffer = c.buffer.written();
            const alignment = typeAlignment(T);
            const type_signature = types.guessSignature(T);

            if (c.parent.sw) |swriter| {
                try swriter.writeAll(type_signature);
            }

            c.parent.position += try alignBuffer(c.parent.w, 4, c.parent.position);
            try c.parent.w.writeInt(u32, @truncate(container_buffer.len), c.parent.endian);
            c.parent.position += 4;
            c.parent.position += try alignBuffer(c.parent.w, alignment, c.parent.position);
            try c.parent.w.writeAll(container_buffer);
            c.parent.position += container_buffer.len;

            c.buffer.deinit();
        }
    };

    pub fn startContainer(self: *Writer) !Container {
        return Container.init(self, self.allocator, self.fdlist);
    }

    pub fn alignWriter(self: *Writer, alignment: usize) !void {
        self.position += try alignBuffer(self.w, alignment, self.position);
    }
};

pub const Reader = struct {
    allocator: mem.Allocator,

    position: usize = 0,
    depth: usize = 0,

    r: *Io.Reader,
    fdlist: ?*std.ArrayList(i32) = null,

    endian: std.builtin.Endian = .little,

    pub fn from(allocator: mem.Allocator, r: *Io.Reader, fdlist: ?*std.ArrayList(i32), byteorder: std.builtin.Endian) Reader {
        return .{ .allocator = allocator, .r = r, .fdlist = fdlist, .endian = byteorder };
    }

    pub fn reset(r: *Reader) void {
        r.* = .from(r.allocator, r.r, r.fdlist, r.endian);
    }

    pub fn read(self: *Reader, T: type, allocator: ?mem.Allocator) !T {
        const a = allocator orelse self.allocator;
        const tinfo = @typeInfo(T);
        if (comptime (T == void)) return {};
        comptime if (!types.isTypeDeserializable(T)) @compileError(comptimePrint("Requested type {s} is not DBus-deserializable", .{ @typeName(T) }));
        switch (T) {
            Signature => {
                const siglen: u8 = try self.r.takeByte();
                self.position += 1;

                const signature: Signature = .{ .value = try a.alloc(u8, siglen), .ownership = true };
                errdefer signature.deinit(a);

                try self.r.readSliceAll(@constCast(signature.value));
                self.position += siglen;

                _ = try self.r.discardShort(1);
                self.position += 1;

                return signature;
            },
            String => {
                self.position += try alignBuffer(self.r, 4, self.position);

                const strlen: u32 = try self.r.takeInt(u32, self.endian);
                self.position += 4;

                const string: String = .{ .value = try a.alloc(u8, strlen), .ownership = true };
                errdefer string.deinit(a);

                try self.r.readSliceAll(@constCast(string.value));
                self.position += strlen;

                _ = try self.r.discardShort(1);
                self.position += 1;

                return string;
            },
            ObjectPath => {
                self.position += try alignBuffer(self.r, 4, self.position);

                const pathlen: u32 = try self.r.takeInt(u32, self.endian);
                self.position += 4;

                const path: ObjectPath = .{ .value = try a.alloc(u8, pathlen), .ownership = true };
                errdefer path.deinit(a);

                try self.r.readSliceAll(@constCast(path.value));
                self.position += pathlen;

                _ = try self.r.discardShort(1);
                self.position += 1;

                return path;
            },
            else => {
                switch (tinfo) {
                    .int => |integer| {
                        if (integer.bits <= 8) {
                            const value: u8 = try self.r.takeByte();
                            self.position += 1;
                            return @bitCast(value);
                        } else if (integer.bits <= 16) {
                            self.position += try alignBuffer(self.r, 2, self.position);
                            const value: u16 = try self.r.takeInt(u16, self.endian);
                            self.position += 2;
                            return @bitCast(value);
                        } else if (integer.bits <= 32) {
                            self.position += try alignBuffer(self.r, 4, self.position);
                            const value: u32 = try self.r.takeInt(u32, self.endian);
                            self.position += 4;
                            return @bitCast(value);
                        } else if (integer.bits <= 64) {
                            self.position += try alignBuffer(self.r, 8, self.position);
                            const value: u64 = try self.r.takeInt(u64, self.endian);
                            self.position += 8;
                            return @bitCast(value);
                        } else @compileError(comptimePrint("{s} is too wide for DBus. DBus supports integers up to 64 bits", .{@typeName(T)}));
                    },
                    .float => |float| {
                        if (float.bits > 64) @compileError(comptimePrint("DBus supports only doubles. Please use float type with precision lower or equal to 64 bits."));
                        self.position += try alignBuffer(self.r, 8, self.position);
                        const d_opaque: u64 = try self.r.takeInt(u64, self.endian);
                        self.position += 8;
                        const d: f64 = @bitCast(d_opaque);
                        return @floatCast(d);
                    },
                    .bool => {
                        self.position += try alignBuffer(self.r, 4, self.position);
                        const value: u32 = try self.r.takeInt(u32, self.endian);
                        self.position += 4;
                        return if (value == 1) true else if (value == 0) false else return error.InvalidBooleanValue;
                    },
                    .comptime_int, .comptime_float => @compileError("Please do not pass comptime_int or comptime_float types directly to reader, use @as to give it a type first."),
                    .pointer => |ptr| {
                        if (ptr.size != .slice) @compileError(comptimePrint("Pointers of type {s} are not supported.", .{@tagName(ptr.size)}));

                        if (self.depth == 63) return error.DepthLimitReached;

                        self.position += try alignBuffer(self.r, 4, self.position);
                        const container_len: u32 = try self.r.takeInt(u32, self.endian);
                        self.position += 4;

                        self.position += try alignBuffer(self.r, typeAlignment(ptr.child), self.position);
                        const container_data: []u8 = try a.alloc(u8, container_len);
                        defer a.free(container_data);

                        try self.r.readSliceAll(container_data);
                        self.position += container_len;

                        var container = Io.Reader.fixed(container_data);
                        var r = Reader.from(self.allocator, &container, self.fdlist, self.endian);
                        r.depth = self.depth + 1;

                        var result = std.ArrayList(ptr.child){};
                        errdefer result.deinit(a);

                        var i: usize = 0;
                        while (container.end - container.seek > 0) : (i += 1) {
                            const item = try r.read(ptr.child, a);
                            try result.append(a, item);
                        }

                        return try result.toOwnedSlice(a);
                    },
                    .@"struct" => |st| {
                        if (comptime std.meta.hasMethod(T, "fromDBus"))
                            return T.fromDBus(a, self)
                        else if (comptime types.isDict(T)) {
                            const KV = T.KV;

                            var tmp_arena = std.heap.ArenaAllocator.init(a);
                            errdefer tmp_arena.deinit();

                            const kv_slice = try self.read([]KV, tmp_arena.allocator());

                            var dict = T.init(tmp_arena.allocator());

                            for (kv_slice) |kv| {
                                const entry = try dict.getOrPut(kv.key);
                                entry.key_ptr.* = kv.key;
                                entry.value_ptr.* = kv.value;
                            }
                            return dict;
                        } else if (comptime types.isFileHandle(T)) {
                            if (self.fdlist == null) return error.UnixFDPassingNotSupported;

                            self.position += try alignBuffer(self.r, 4, self.position);
                            const index: u32 = try self.r.takeInt(u32, self.endian);
                            self.position += 4;

                            if (index >= @as(u32, @truncate(self.fdlist.?.items.len))) return error.InvalidFDIndex;

                            // Ensure that fd is usable even after message deinit (needed by Promise)
                            const fd = try std.posix.dup(self.fdlist.?.items[index]);

                            return T{
                                .handle = fd,
                            };
                        } else {
                            var result: T = undefined;

                            if (!st.is_tuple) self.position += try alignBuffer(self.r, 8, self.position);
                            inline for (st.fields) |field| {
                                @field(result, field.name) = try self.read(field.type, a);
                            }
                            return result;
                        }
                    },
                    .@"union" => |un| {
                        if (comptime std.meta.hasMethod(T, "fromDBus"))
                            return T.fromDBus(a, self)
                        else {
                            if (un.tag_type == null) @compileError("Untagged unions are not supported");
                            const sig: Signature = try self.read(Signature, a);
                            defer sig.deinit(a);

                            var result: T = undefined;

                            var matched = false;
                            inline for (un.fields) |ufield| {
                                const field_sig = types.guessSignature(ufield.type);
                                if (!std.mem.eql(u8, sig.value, field_sig)) comptime continue;
                                result = @unionInit(T, ufield.name, try self.read(ufield.type, a));
                                matched = true;
                                break;
                            }
                            if (!matched) return error.UnionVariantNotFound;
                            return result;
                        }
                    },
                    .@"enum" => |en| {
                        if (comptime std.meta.hasMethod(T, "fromDBus"))
                            return T.fromDBus(a, self)
                        else {
                            if (en.is_exhaustive) @compileError(std.fmt.comptimePrint("{s} cannot be deserialized: Only not exhaustive enums available for deserialization, as we can get any value in range from DBus", .{@typeName(T)}));
                            const val = try self.read(en.tag_type, a);
                            return @as(T, @enumFromInt(val));
                        }
                    },
                    .void => return {},
                    else => @compileError(comptimePrint("Type {s} is not supported for deserialization.", .{@typeName(T)})),
                }
            },
        }
        unreachable;
    }

    pub const Container = struct {
        parent: *Reader,
        reader: Reader,
        buffer: []const u8,
        fixed: Io.Reader,
        allocator: mem.Allocator,

        pub fn init(parent: *Reader, allocator: mem.Allocator, alignment: usize, byteorder: std.builtin.Endian, fdlist: ?*std.ArrayList(i32)) !Container {
            parent.position += try alignBuffer(parent.r, 4, parent.position);
            const container_len: u32 = try parent.r.takeInt(u32, parent.endian);
            parent.position += 4;
            parent.position += try alignBuffer(parent.r,  alignment, parent.position);
            const container_data: []u8 = try allocator.alloc(u8, container_len);
            errdefer allocator.free(container_data);
            try parent.r.readSliceAll(container_data);
            parent.position += container_len;
            var c: Container = .{
                .parent = parent,
                .buffer = container_data,
                .fixed = Io.Reader.fixed(container_data),
                .allocator = allocator,
                .reader = undefined
            };
            c.reader = Reader.from(allocator, &c.fixed, fdlist, byteorder);
            c.reader.depth = parent.depth + 1;
            return c;
        }

        pub fn finish(c: *Container) !void {
            c.allocator.free(c.buffer);
        }
    };

    pub fn startContainer(self: *Reader, allocator: mem.Allocator, alignment: usize) !Container {
        return Container.init(self, allocator, alignment, self.endian, self.fdlist);
    }

    pub fn alignReader(self: *Reader, alignment: usize) !void {
        self.position += try alignBuffer(self.r, alignment, self.position);
    }
};

fn alignBuffer(interface: anytype, alignment: usize, position: usize) !usize {
    if (position == 0) return 0;
    const padding = mem.alignForward(usize, position, alignment) - position;
    switch (@TypeOf(interface)) {
        *Io.Writer => {
            try interface.splatByteAll(0, padding);
            return padding;
        },
        *Io.Reader => {
            try interface.discardAll(padding);
            return padding;
        },
        else => @compileError(comptimePrint("align() expects Io.Writer or Io.Reader, but {s} is observed instead.", .{@typeName(@TypeOf(interface))})),
    }
    unreachable;
}

fn typeAlignment(T: type) usize {
    const type_info = @typeInfo(T);

    switch (T) {
        Signature => return 1,
        ObjectPath, String => return 4,
        else => {
            switch (type_info) {
                .int => |integer| {
                    if (integer.bits <= 8) return 1 else if (integer.bits <= 16) return 2 else if (integer.bits <= 32) return 4 else if (integer.bits <= 64) return 8 else @compileError("Unsupported integer size");
                },
                .float => |float| {
                    if (float.bits == 32 or float.bits == 64) return 8 else @compileError("Unsupported float size");
                },
                .bool => return 4,
                .@"struct" => {
                    if (types.isFileHandle(T)) return 1 else return 8;
                },
                .pointer => |ptrinfo| {
                    switch (ptrinfo.size) {
                        .slice => return 4,
                        else => @compileError("Unsupported pointer size"),
                    }
                },
                .@"union" => return 1,
                else => return 1,
            }
        },
    }
}

// TODO: Add tests for reader and writer
