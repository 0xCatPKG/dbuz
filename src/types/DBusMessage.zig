//! DBus Message implementation

const std = @import("std");
const dbus_types = @import("dbus_types.zig");
const String = dbus_types.String;
const ObjectPath = dbus_types.ObjectPath;
const Signature = dbus_types.Signature;
const guessSignature = dbus_types.guessSignature;
const getSignature = dbus_types.getSignature;
const isDict = dbus_types.isDict;
const dictSignature = dbus_types.dictSig;

const AllocatorError = std.mem.Allocator.Error;
const NoEofError = error{EndOfStream};

pub const SerializationError = error{
    DepthLimitReached,
    MessageTooLarge,
    SignatureTooLarge,
} || AllocatorError;

pub const DeserializationError = error{
    DepthLimitReached,
    SignatureMismatch,
    MessageTooShort,
    VariantUnexpectedSignature,
} || AllocatorError;

const Self = @This();
const ArrayListBuffer = std.ArrayList(u8);

/// DBus Message Header, that is serialized as part of the header section of the message.
/// Not accounted for in the message size.
const Header = struct {
    name: u8,
    value: ValueType,

    /// All possible header value types.
    pub const ValueType = union(enum) {
        object_path: ObjectPath,
        string: String,
        uint32: u32,
        signature: Signature,
    };

    pub const Name = enum(u8) {
        INVALID = 0,
        PATH = 1,
        INTERFACE = 2,
        MEMBER = 3,
        ERROR_NAME = 4,
        REPLY_SERIAL = 5,
        DESTINATION = 6,
        SENDER = 7,
        SIGNATURE = 8,
        UNIX_FDS = 9,
    };
};

pub const Flags = struct {
    pub const NO_REPLY_EXPECTED: u8 = 0x01;
    pub const NO_AUTO_START: u8 = 0x02;
    pub const ALLOW_INTERACTIVE_AUTHORIZATION: u8 = 0x04;
};

pub const Type = enum(u8) {
    INVALID = 0,
    METHOD_CALL = 1,
    METHOD_RETURN = 2,
    ERROR = 3,
    SIGNAL = 4,
};

allocator: std.mem.Allocator,

/// Message headers, should not be modified directly, use addHeader instead.
headers: std.ArrayList(Header),

payload: ArrayListBuffer,
unix_fds: std.ArrayList(i32),
signature: ArrayListBuffer,

message_type: Type = .INVALID,

/// ORed value from Flags enum
flags: u8 = 0,

/// It's a Safety-checked Illegal behavior to have serial set to zero during finalization
serial: u32 = 0,

// Optional header fields
path: ?[]const u8 = null,
interface: ?[]const u8 = null,
member: ?[]const u8 = null,
error_name: ?[]const u8 = null,
reply_serial: ?u32 = null, // Reply serial, if set, header will be generated automatically
destination: ?[]const u8 = null,
sender: ?[]const u8 = null, // Set by bus daemon

/// State for reading message, should be null for messages that are not being read
_reader: ?struct {
    signature_stream: std.io.FixedBufferStream([]u8),
    payload_stream: std.io.FixedBufferStream([]u8),
    byteorder: std.builtin.Endian = .little,

    pub fn reset(self: *@This()) void {
        self.signature_stream.reset();
        self.payload_stream.reset();
    }

} = null,

/// Is it not recommended to call this function directly.
///
/// `flags` is a ORDer u8 from values of Flags enum
pub fn init(allocator: std.mem.Allocator, flags: u8, message_type: Type, serial: u32) AllocatorError!Self {
    return Self{
        .allocator = allocator,
        .headers = try std.ArrayList(Header).initCapacity(allocator, 4),
        .payload = try ArrayListBuffer.initCapacity(allocator, 512),
        .unix_fds = try std.ArrayList(i32).initCapacity(allocator, 100),
        .message_type = message_type,
        .flags = flags,
        .signature = try ArrayListBuffer.initCapacity(allocator, 255),
        .serial = serial,
    };
}

/// Parse a DBus message from bytes and fds readers
/// file descriptors must outlive the message.
///
/// It's a caller's responsibility to close the file descriptors after `.deinit()`.
///
/// See `.write()` for Serialization Rules.
///
/// Passing an tagged union with multiple fields that share the same type is an **Unchecked Illegal Behavior**. First defined field will be used during deserialization in that case.
pub fn parseFromReader(allocator: std.mem.Allocator, bytes_reader: anytype, unix_fds_alist: *std.ArrayList(i32)) DeserializationError!Self {
    // Messages received from DBus is aligned to the start of the message, not to the start of the buffer
    const message_start_offset = readerGetPos(bytes_reader);
    errdefer {
        readerSetPos(bytes_reader, message_start_offset);
    }

    var headers_list = try std.ArrayList(Header).initCapacity(allocator, 4);
    var signature_buf = try ArrayListBuffer.initCapacity(allocator, 255);
    errdefer {
        headers_list.deinit();
        signature_buf.deinit();
    }

    var self: Self = .{ .allocator = allocator, .headers = headers_list, .payload = ArrayListBuffer.init(allocator), .unix_fds = std.ArrayList(i32).init(allocator), .signature = signature_buf };

    // Create signature streams for deserialization process
    // It is splitted to two streams, because we don't know endianess of the message before reading first byte.
    // However we already know that first 4 bytes are single bytes, so it can be read without any endianness.
    var header_signature_stream = std.io.fixedBufferStream("yyyy");
    var header_signature_stream_2 = std.io.fixedBufferStream("uua(yv)");

    const byteorder, const message_type, const flags, _ = try self.deserializeValues(bytes_reader, struct { u8, u8, u8, u8 }, allocator, header_signature_stream.reader(), .little, message_start_offset);

    self.message_type = @enumFromInt(if (message_type > 4) 0 else message_type);
    self.flags = flags;

    // Rest of the header
    const length, const serial, const headers: []Header =
    try self.deserializeValues(bytes_reader, struct { u32, u32, []Header }, allocator, header_signature_stream_2.reader(), if (byteorder == 'l') .little else .big, message_start_offset);
    defer allocator.free(headers);

    alignRead(bytes_reader, 8, message_start_offset) catch return DeserializationError.MessageTooShort;
    const payloadbuff = try allocator.alloc(u8, length);
    defer allocator.free(payloadbuff);
    _ = bytes_reader.read(payloadbuff) catch return DeserializationError.MessageTooShort;
    try self.payload.appendSlice(payloadbuff);
    self.serial = serial;

    for (headers) |header| {
        switch (header.name) {
            @intFromEnum(Header.Name.PATH) => {
                self.path = header.value.object_path.value;
            },
            @intFromEnum(Header.Name.INTERFACE) => {
                self.interface = header.value.string.value;
            },
            @intFromEnum(Header.Name.MEMBER) => {
                self.member = header.value.string.value;
            },
            @intFromEnum(Header.Name.ERROR_NAME) => {
                self.error_name = header.value.string.value;
            },
            @intFromEnum(Header.Name.REPLY_SERIAL) => {
                self.reply_serial = header.value.uint32;
            },
            @intFromEnum(Header.Name.DESTINATION) => {
                self.destination = header.value.string.value;
            },
            @intFromEnum(Header.Name.SENDER) => {
                self.sender = header.value.string.value;
            },
            @intFromEnum(Header.Name.SIGNATURE) => {
                try self.signature.appendSlice(header.value.signature.value);
            },
            @intFromEnum(Header.Name.UNIX_FDS) => {
                try self.unix_fds.appendSlice(unix_fds_alist.items[0..header.value.uint32]);
                unix_fds_alist.replaceRangeAssumeCapacity(0, unix_fds_alist.items.len - header.value.uint32, unix_fds_alist.items[header.value.uint32..]);
            },
            else => {},
        }
    }

    self._reader = .{
        .byteorder = if (byteorder == 'l') .little else .big,
        .payload_stream = std.io.fixedBufferStream(self.payload.items),
        .signature_stream = std.io.fixedBufferStream(self.signature.items),
    };

    try self.headers.appendSlice(headers);
    return self;
}

/// Reads a value (or tuple of values) from the message payload or returns an error.
/// Caller owns the memory allocated for such value types as slices, Strings, Signatures, ObjectPaths.
/// slices should be freed using the allocator directly. Other types require `.deinit` call with same allocator as one passed to the `read`
pub fn read(self: *Self, comptime T: type, allocator: std.mem.Allocator) DeserializationError!T {
    std.debug.assert(self._reader != null);
    if (T == void) return {};
    return self.deserializeValues(
        self._reader.?.payload_stream.reader(),
        T, allocator,
        self._reader.?.signature_stream.reader(),
        self._reader.?.byteorder, 0);
}

/// Writes a value (or the tuple of values) to the message payload or returns an error.
///
/// File descriptors can be closed right after the call. File descriptors are `dup`ed so function can cause file descriptor exhaustion if not freed properly.
///
/// Serialization Rules:
///
/// - Value can be any type except pointers that are not slices.
/// - Unions are serialized as variants.
/// - In order for struct to be serialized as a Dictionary, it must contain `.put`, `.getOrPut`, `.get`, `.iterator` methods and a `.KV` declaration.
/// It is an Unchecked Illegal Behavior to use hash algorithms that do not support hashing of slices (See autohash with .Deep recursion). You may use dbuz.Dictionary defined by that package.
pub fn write(self: *Self, value: anytype) SerializationError!void {
    std.debug.assert(self._reader == null);

    const signature = getSignature(value);
    const typeinfo = @typeInfo(@TypeOf(value));
    switch (typeinfo) {
        .@"struct" => |structinfo| {
            if (structinfo.is_tuple) {
                inline for (value) |el| {
                    try self.serializeValue(self.payload.writer(), el, 0);
                }
                try self.addSignature(signature);
                return;
            }
        },
        else => {},
    }

    try self.serializeValue(self.payload.writer(), value, 0);
    try self.addSignature(signature);
}

/// **Internal**
///
/// Deserializes values into a given type. Just a wrapper to deserialize into tuples as actual deserializer treats tuples as structs.
///
/// Caller owns returned memory.
inline fn deserializeValues(self: Self, reader: anytype, comptime T: type, allocator: std.mem.Allocator, signature_reader: anytype, byteorder: std.builtin.Endian, align_offset: usize) DeserializationError!T {
    comptime var readers_signature: []const u8 = "";
    const typeinfo = @typeInfo(T);

    switch (typeinfo) {
        .@"struct" => |structinfo| {
            if (structinfo.is_tuple) {
                inline for (typeinfo.@"struct".fields) |field| {
                    readers_signature = readers_signature ++ guessSignature(field.type);
                }
            } else {
                readers_signature = readers_signature ++ guessSignature(T);
            }
        },
        else => readers_signature = readers_signature ++ guessSignature(T),
    }

    var sig_buffer: [readers_signature.len]u8 = undefined;
    _ = signature_reader.read(&sig_buffer) catch return DeserializationError.MessageTooShort;

    if (!std.mem.eql(u8, &sig_buffer, readers_signature)) return DeserializationError.SignatureMismatch;

    switch (typeinfo) {
        .@"struct" => |structinfo| {
            if (structinfo.is_tuple) {
                var rtuple: T = undefined;
                inline for (typeinfo.@"struct".fields) |field| {
                    const val = try deserializeValue(self, field.type, reader, allocator, byteorder, 0, align_offset);
                    @field(rtuple, field.name) = val;
                    errdefer {
                        switch (field.type) {
                            String, ObjectPath, Signature => val.deinit(allocator),
                            else => {
                                switch (@typeInfo(field.type)) {
                                    else => {},
                                    .pointer => |ptrinfo| {
                                        if (ptrinfo.size != .slice) @compileError("Unexpected non-sentiel pointer inside errdefer at deserializeValues");
                                        allocator.free(val);
                                    }
                                }
                            }
                        }
                    }
                }
                return rtuple;
            }
        },
        else => {},
    }
    return try deserializeValue(self, T, reader, allocator, byteorder, 0, align_offset);
}

/// **Internal**
///
/// Deserializes a value from payload to a T giving Serialization Rules for type T.
///
/// Caller owns returned memory.
fn deserializeValue(self: Self, comptime T: type, reader: anytype, allocator: std.mem.Allocator, byteorder: std.builtin.Endian, depth: u8, align_offset: usize) DeserializationError!T {
    if (depth > 64) return DeserializationError.DepthLimitReached;

    const typeinfo = @typeInfo(T);
    switch (T) {
        Signature => {
            var siglen: u8 = 0;
            siglen = reader.readByte() catch return DeserializationError.MessageTooShort;
            const signature = Signature{ .value = try allocator.alloc(u8, siglen), .ownership = true };
            _ = reader.readAtLeast(@constCast(signature.value), siglen) catch return DeserializationError.MessageTooShort;
            _ = reader.readByte() catch return DeserializationError.MessageTooShort;
            return signature;
        },
        ObjectPath => {
            alignRead(reader, std.meta.alignment(u32), align_offset) catch return DeserializationError.MessageTooShort;
            var pathlen: u32 = 0;
            pathlen = reader.readInt(u32, byteorder) catch return DeserializationError.MessageTooShort;
            const path = ObjectPath{ .value = try allocator.alloc(u8, pathlen), .ownership = true };
            _ = reader.readAtLeast(@constCast(path.value), pathlen) catch return DeserializationError.MessageTooShort;
            _ = reader.readByte() catch return DeserializationError.MessageTooShort;
            return path;
        },
        String => {
            alignRead(reader, std.meta.alignment(u32), align_offset) catch return DeserializationError.MessageTooShort;
            var strlen: u32 = 0;
            strlen = reader.readInt(u32, byteorder) catch return DeserializationError.MessageTooShort;
            const string = String{ .value = try allocator.alloc(u8, strlen), .ownership = true };
            _ = reader.readAtLeast(@constCast(string.value), strlen) catch return DeserializationError.MessageTooShort;
            _ = reader.readByte() catch return DeserializationError.MessageTooShort;
            return string;
        },
        std.fs.File, std.fs.Dir => {
            alignRead(reader, std.meta.alignment(u32), align_offset) catch return DeserializationError.MessageTooShort;
            var fd_index: u32 = 0;
            fd_index = reader.readInt(u32, byteorder) catch return DeserializationError.MessageTooShort;
            return .{ .handle = self.unix_fds.items[fd_index] };
        },
        else => {
            switch (typeinfo) {
                .int => |intinfo| {
                    if (intinfo.bits <= 8) {
                        return @truncate(reader.readInt(u8, byteorder) catch return DeserializationError.MessageTooShort);
                    } else if (intinfo.bits <= 16) {
                        var val: if (intinfo.signedness == .signed) i16 else u16 = 0;
                        alignRead(reader, std.meta.alignment(u16), align_offset) catch return DeserializationError.MessageTooShort;
                        val = reader.readInt(@TypeOf(val), byteorder) catch return DeserializationError.MessageTooShort;
                        return @truncate(val);
                    } else if (intinfo.bits <= 32) {
                        var val: if (intinfo.signedness == .signed) i32 else u32 = 0;
                        alignRead(reader, std.meta.alignment(u32), align_offset) catch return DeserializationError.MessageTooShort;
                        val = reader.readInt(@TypeOf(val), byteorder) catch return DeserializationError.MessageTooShort;
                        return @truncate(val);
                    } else if (intinfo.bits <= 64) {
                        var val: if (intinfo.signedness == .signed) i64 else u64 = 0;
                        alignRead(reader, std.meta.alignment(u64), align_offset) catch return DeserializationError.MessageTooShort;
                        val = reader.readInt(@TypeOf(val), byteorder) catch return DeserializationError.MessageTooShort;
                        return @truncate(val);
                    }
                },
                .float => {
                    var val: u64 = 0;
                    alignRead(reader, std.meta.alignment(u64), align_offset) catch return DeserializationError.MessageTooShort;
                    val = reader.readInt(u64, byteorder) catch return DeserializationError.MessageTooShort;
                    const casted_float: f64 = @bitCast(val);
                    return @floatCast(casted_float);
                },
                .bool => {
                    var val: u32 = 0;
                    alignRead(reader, std.meta.alignment(u32), align_offset) catch return DeserializationError.MessageTooShort;
                    val = reader.readInt(u32, byteorder) catch return DeserializationError.MessageTooShort;
                    return val != 0;
                },
                .pointer => |ptrinfo| {
                    if (ptrinfo.size == .slice) {
                        var len: u32 = 0;
                        alignRead(reader, std.meta.alignment(u32), align_offset) catch return DeserializationError.MessageTooShort;
                        len = reader.readInt(u32, byteorder) catch return DeserializationError.MessageTooShort;

                        const buff: []u8 = try allocator.alloc(u8, len);
                        defer allocator.free(buff);

                        alignRead(reader, typeAlignment(ptrinfo.child), align_offset) catch return DeserializationError.MessageTooShort;

                        _ = reader.read(buff) catch return DeserializationError.MessageTooShort;

                        var buffstream = std.io.fixedBufferStream(buff);
                        const buffreader = buffstream.reader();
                        var slice: std.ArrayList(ptrinfo.child) = std.ArrayList(ptrinfo.child).init(allocator);
                        errdefer slice.deinit();

                        var i: u32 = 0;
                        while (true) : (i += 1) {
                            const val: ptrinfo.child = self.deserializeValue(ptrinfo.child, buffreader, allocator, byteorder, depth + 1, 0) catch |err| {
                                switch (err) {
                                    DeserializationError.MessageTooShort => break,
                                    else => return err,
                                }
                            };
                            slice.append(val) catch return DeserializationError.MessageTooShort;
                        }
                        return slice.toOwnedSlice();
                    } else @compileError("Invalid type for array deserialization");
                },
                .@"struct" => |structinfo| {

                    if (isDict(T)) {
                        const KV = @field(T, "KV");
                        const K = @FieldType(KV, "key");// @TypeOf(@field(KV, "key"));
                        const V = @FieldType(KV, "value");// @TypeOf(@field(KV, "value"));

                        const slice = try self.deserializeValue([]KV, reader, allocator, byteorder, depth+1, align_offset);
                        defer allocator.free(slice);

                        var map = T.init(allocator);
                        for (slice) |el| {
                            const entry = try map.getOrPut(el.key);
                            if (entry.found_existing) {
                                switch (K) {
                                    String, Signature, ObjectPath => entry.key_ptr.deinit(allocator),
                                    else => {
                                        switch(@typeInfo(K)) {
                                            else => {},
                                            .@"pointer" => {
                                                allocator.free(entry.key_ptr.*);
                                            }
                                        }
                                    },
                                }
                                switch (V) {
                                    String, Signature, ObjectPath => entry.value_ptr.deinit(allocator),
                                    else => {
                                        switch(@typeInfo(V)) {
                                            else => {},
                                            .@"pointer" => {
                                                allocator.free(entry.value_ptr.*);
                                            }
                                        }
                                    },
                                }
                            }
                            entry.key_ptr.* = el.key;
                            entry.value_ptr.* = el.value;
                        }
                        return map;

                    } else {
                        var s: T = undefined;
                        alignRead(reader, 8, align_offset) catch return DeserializationError.MessageTooShort;

                        inline for (structinfo.fields) |field| {
                            const fieldval: field.type = try self.deserializeValue(field.type, reader, allocator, byteorder, depth + 1, align_offset);
                            @field(s, field.name) = fieldval;
                        }

                        return s;
                    }
                },
                .@"union" => |unioninfo| {
                    if (unioninfo.tag_type == null) @compileError("Cannot deserialize to" ++ @typeName(T) ++ ": Only tagged unions are supported");
                    const sig = try self.deserializeValue(Signature, reader, allocator, byteorder, depth + 1, align_offset);
                    defer sig.deinit(allocator);

                    inline for (unioninfo.fields) |ufield| {
                        switch (@typeInfo(ufield.type)) {
                            else => {
                                const fieldsig = guessSignature(ufield.type);
                                if (std.mem.eql(u8, fieldsig, sig.value)) {
                                    const fieldval = try self.deserializeValue(ufield.type, reader, allocator, byteorder, depth + 1, align_offset);
                                    return @unionInit(T, ufield.name, fieldval);
                                }
                            },
                            .pointer => |ptr| {
                                if (ptr.size != .slice) continue;
                                const fieldsig = guessSignature(ufield.type);
                                if (std.mem.eql(u8, fieldsig, sig.value)) {
                                    const fieldval = try self.deserializeValue(ufield.type, reader, allocator, byteorder, depth + 1, align_offset);
                                    return @unionInit(T, ufield.name, fieldval);
                                }
                            }
                        }
                    }
                    return DeserializationError.VariantUnexpectedSignature;
                },
                else => @compileError("Unsupported kind of type aka " ++ @tagName(typeinfo)),
            }
        },
    }
    unreachable;
}

/// Closes all `.dup`ed fds if message is not in the reader mode.
/// Frees all allocated memory.
pub fn deinit(self: *Self) void {
    if (self._reader == null) {
        for (self.unix_fds.items) |fd| {
            std.posix.close(fd);
        }
    }
    for (self.headers.items) |header| {
        switch (header.value) {
            .object_path => |o| {
                o.deinit(self.allocator);
            },
            .string => |s| {
                s.deinit(self.allocator);
            },
            .signature => |s| {
                s.deinit(self.allocator);
            },
            else => {},
        }
    }
    self.payload.deinit();
    self.headers.deinit();
    self.unix_fds.deinit();
    self.signature.deinit();
}

/// Adds header to the message. Dupes value if needed.
pub fn addHeader(self: *Self, name: Header.Name, value: Header.ValueType) !void {
    std.debug.assert(self._reader == null);
    std.debug.assert(name != .INVALID);
    switch (value) {
        else => try self.headers.append(.{ .name = @intFromEnum(name), .value = value }),
        .string => |s| {
            try self.headers.append(.{ .name = @intFromEnum(name), .value =
                .{
                    .string = .{
                        .value = try self.allocator.dupe(u8, s.value),
                        .ownership = true
                    }
                }
            });
        },
        .signature => |s| {
            try self.headers.append(.{ .name = @intFromEnum(name), .value =
                .{
                    .signature = .{
                        .value = try self.allocator.dupe(u8, s.value),
                        .ownership = true
                    }
                }
            });
        },
        .object_path => |o| {
            try self.headers.append(.{ .name = @intFromEnum(name), .value =
                .{
                    .object_path = .{
                        .value = try self.allocator.dupe(u8, o.value),
                        .ownership = true
                    }
                }
            });
        }
    }

}

/// Finalizes the message by combining all headers and payload into a single buffer.
///
/// Must be a message in write mode.
/// Automatically adds header fields based on optional message fields and signature.
///
/// **Caller owns returned memory.**
pub fn finalize(self: *Self) SerializationError![]const u8 {
    std.debug.assert(self._reader == null);
    std.debug.assert(self.serial != 0);

    if (self.signature.items.len > 0) {
        try self.addHeader(.SIGNATURE, .{ .signature = .{ .value = self.signature.items } });
    }
    if (self.unix_fds.items.len > 0) {
        try self.addHeader(.UNIX_FDS, .{ .uint32 = @truncate(self.unix_fds.items.len) });
    }

    if (self.path) |v| {
        try self.addHeader(.PATH, .{ .object_path = .{ .value = v } });
    }
    if (self.interface) |v| {
        try self.addHeader(.INTERFACE, .{ .string = .{ .value = v } });
    }
    if (self.member) |v| {
        try self.addHeader(.MEMBER, .{ .string = .{ .value = v } });
    }
    if (self.destination) |v| {
        try self.addHeader(.DESTINATION, .{ .string = .{ .value = v } });
    }
    if (self.error_name) |v| {
        try self.addHeader(.ERROR_NAME, .{ .string = .{ .value = v } });
    }
    if (self.reply_serial) |v| {
        try self.addHeader(.REPLY_SERIAL, .{ .uint32 = v });
    }

    var res_payload = try std.ArrayList(u8).initCapacity(self.allocator, 12 + 256 + self.payload.items.len);
    try self.serializeValue(res_payload.writer(), (struct { u8, u8, u8, u8, u32, u32, []Header }){ 'l', @intFromEnum(self.message_type), self.flags, 1, @truncate(self.payload.items.len), self.serial, self.headers.items }, 0);
    try alignPayload(res_payload.writer(), 8);
    try res_payload.appendSlice(self.payload.items);
    return res_payload.toOwnedSlice();
}

inline fn addSignature(self: *Self, signature: []const u8) AllocatorError!void {
    try self.signature.fixedWriter().writeAll(signature);
}


/// Serializes a given value according to the DBus serialization rules.
/// It is a **Checked Illegal Behavior** to call this function with depth greater than 64.
fn serializeValue(self: *Self, writer: anytype, value: anytype, depth: u8) SerializationError!void {
    if (depth > 64) return SerializationError.DepthLimitReached;

    const valtype = @TypeOf(value);
    switch (valtype) {
        Signature => {
            writer.writeByte(@truncate(value.value.len)) catch return SerializationError.MessageTooLarge;
            writer.writeAll(value.value) catch return SerializationError.MessageTooLarge;
            writer.writeByte(0) catch return SerializationError.MessageTooLarge;
        },
        ObjectPath, String => {
            alignPayload(writer, @alignOf(u32)) catch return SerializationError.MessageTooLarge;
            writer.writeInt(u32, @truncate(value.value.len), .little) catch return SerializationError.MessageTooLarge;
            writer.writeAll(value.value) catch return SerializationError.MessageTooLarge;
            writer.writeByte(0) catch return SerializationError.MessageTooLarge;
        },
        std.fs.File, std.fs.Dir => {
            const new_fd = std.posix.dup(value.handle) catch return SerializationError.OutOfMemory;
            self.unix_fds.appendAssumeCapacity(new_fd);
            alignPayload(writer, std.meta.alignment(u32)) catch return SerializationError.MessageTooLarge;
            writer.writeInt(u32, self.unix_fds.items.len - 1, .little) catch return SerializationError.MessageTooLarge;
        },
        else => {
            const typeinfo = @typeInfo(valtype);
            switch (typeinfo) {
                .int => |intinfo| {
                    if (intinfo.bits <= 8) {
                        writer.writeByte(value) catch return SerializationError.MessageTooLarge;
                    } else if (intinfo.bits <= 16) {
                        alignPayload(writer, std.meta.alignment(u16)) catch return SerializationError.MessageTooLarge;
                        writer.writeInt(if (intinfo.signedness == .signed) i16 else u16, value, .little) catch return SerializationError.MessageTooLarge;
                    } else if (intinfo.bits <= 32) {
                        alignPayload(writer, std.meta.alignment(u32)) catch return SerializationError.MessageTooLarge;
                        writer.writeInt(if (intinfo.signedness == .signed) i32 else u32, value, .little) catch return SerializationError.MessageTooLarge;
                    } else if (intinfo.bits <= 64) {
                        alignPayload(writer, std.meta.alignment(u64)) catch return SerializationError.MessageTooLarge;
                        writer.writeInt(if (intinfo.signedness == .signed) i64 else u64, value, .little) catch return SerializationError.MessageTooLarge;
                    }
                },
                .float => {
                    const converted_value: f64 = @floatCast(value);
                    alignPayload(writer, std.meta.alignment(f64)) catch return SerializationError.MessageTooLarge;
                    const integerized_float: u64 = @bitCast(converted_value);
                    writer.writeInt(u64, integerized_float, .little) catch return SerializationError.MessageTooLarge;
                },
                .bool => {
                    alignPayload(writer, std.meta.alignment(u32)) catch return SerializationError.MessageTooLarge;
                    writer.writeInt(u32, if (value) 1 else 0, .little) catch return SerializationError.MessageTooLarge;
                },
                .pointer => |ptrinfo| {
                    if (ptrinfo.size == .slice) {
                        alignPayload(writer, std.meta.alignment(u32)) catch return SerializationError.MessageTooLarge;

                        var buf: [4096]u8 = undefined;
                        var bstream = std.io.fixedBufferStream(&buf);
                        const awriter = bstream.writer();
                        for (value) |item| {
                            self.serializeValue(awriter, item, depth + 1) catch return SerializationError.MessageTooLarge;
                        }
                        writer.writeInt(u32, @truncate(bstream.pos), .little) catch return SerializationError.MessageTooLarge;
                        alignPayload(writer, typeAlignment(@TypeOf(ptrinfo.child))) catch return SerializationError.MessageTooLarge;
                        writer.writeAll(bstream.getWritten()) catch return SerializationError.MessageTooLarge;
                    } else @compileError("Only slice pointer types are supported");
                },
                .@"struct" => |structinfo| {
                    if (isDict(valtype)) {
                        alignPayload(writer, std.meta.alignment(u32)) catch return SerializationError.MessageTooLarge;

                        var buf: [4096]u8 = undefined;
                        var bstream = std.io.fixedBufferStream(&buf);
                        const awriter = bstream.writer();

                        var it = value.iterator();
                        while (it.next()) |entry| {
                            alignPayload(awriter, 8) catch return SerializationError.MessageTooLarge;
                            self.serializeValue(awriter, entry.key_ptr.*, depth + 1) catch return SerializationError.MessageTooLarge;
                            self.serializeValue(awriter, entry.value_ptr.*, depth + 1) catch return SerializationError.MessageTooLarge;
                        }

                        writer.writeInt(u32, @truncate(bstream.pos), .little) catch return SerializationError.MessageTooLarge;
                        alignPayload(writer, 8) catch return SerializationError.MessageTooLarge;
                        writer.writeAll(bstream.getWritten()) catch return SerializationError.MessageTooLarge;
                    } else {
                        alignPayload(writer, 8) catch return SerializationError.MessageTooLarge;
                        inline for (structinfo.fields) |field| {
                            try self.serializeValue(writer, @field(value, field.name), depth + 1);
                        }
                    }
                },
                .@"union" => |unioninfo| {
                    if (unioninfo.tag_type == null) @compileError("Cannot serialize " ++ @typeName(valtype) ++ ": Only tagged unions are supported");
                    if (std.meta.fields(@TypeOf(value)).len > 0) {
                        const active_tag = @tagName(value);
                        inline for (unioninfo.fields) |ufield| {
                            if (std.mem.eql(u8, ufield.name, active_tag)) {
                                const field_signature = guessSignature(ufield.type);
                                try self.serializeValue(writer, Signature{ .value = field_signature }, depth + 1);
                                try self.serializeValue(writer, @field(value, ufield.name), depth + 1);
                                break;
                            }
                        }
                    } else {
                        try self.serializeValue(writer, Signature{ .value = "" }, depth + 1);
                    }

                },
                else => @compileError("Unsupported type " ++ @typeName(@TypeOf(value)) ++ " in DBusMessage.serializeValue"),
            }
        },
    }
}

/// Align the payload arraylist to the specified alignment
fn alignPayload(writer: anytype, alignment: usize) !void {
    const size = switch (@TypeOf(writer.context)) {
        *ArrayListBuffer => writer.context.items.len,
        *std.io.FixedBufferStream([]u8) => writer.context.pos,
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(writer.context)) ++ " in alignPayload"),
    };
    const padding = std.mem.alignForward(usize, size, alignment) - size;
    try writer.writeByteNTimes(0, padding);
}

fn readerGetPos(reader: anytype) usize {
    return switch (@TypeOf(reader.context)) {
        *ArrayListBuffer => reader.context.items.len,
        *std.io.FixedBufferStream([]u8) => reader.context.pos,
        *const anyopaque => blk: {
            const ctx: *const *std.io.FixedBufferStream([:0]u8) = @alignCast(@ptrCast(reader.context));
            break :blk ctx.*.pos;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(reader.context)) ++ " in alignRead"),
    };
}

fn readerSetPos(reader: anytype, pos: usize) void {
    return switch (@TypeOf(reader.context)) {
        *std.io.FixedBufferStream([]u8) => reader.context.pos = pos,
        *const anyopaque => {
            const ctx: *const *std.io.FixedBufferStream([:0]u8) = @alignCast(@ptrCast(reader.context));
            ctx.*.pos = pos;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(reader.context)) ++ " in alignRead"),
    };
}

fn readerGetMax(reader: anytype) usize {
    return switch (@TypeOf(reader.context)) {
        *ArrayListBuffer => reader.context.items.len,
        *std.io.FixedBufferStream([]u8) => reader.context.buffer.len,
        *const anyopaque => blk: {
            const ctx: *const *std.io.FixedBufferStream([:0]u8) = @alignCast(@ptrCast(reader.context));
            break :blk ctx.*.buffer.len;
        },
        else => @compileError("Unsupported type " ++ @typeName(@TypeOf(reader.context)) ++ " in alignRead"),
    };
}

/// Reads needed byte count to align the reader to the specified alignment.
///
/// `offset` is the position of the reader where current message starts.
fn alignRead(reader: anytype, alignment: usize, offset: usize) !void {
    const size = readerGetPos(reader) - offset;
    const padding = std.mem.alignForward(usize, size, alignment) - size;
    try reader.skipBytes(padding, .{ .buf_size = 512 });
}

fn typeAlignment(comptime T: type) u26 {
    const info = @typeInfo(T);
    return switch (T) {
        String, ObjectPath => 4,
        Signature => 1,
        else => switch (info) {
            else => 1,
            .bool => 4,
            .float => 8,
            .int => |intinfo| blk: {
                break :blk if (intinfo.bits <= 8) 1
                else if (intinfo.bits <= 16) std.meta.alignment(u16)
                else if (intinfo.bits <= 32) std.meta.alignment(u32)
                else if (intinfo.bits <= 64) std.meta.alignment(u64)
                else @compileError("integer too large");
            },
            .pointer => |ptrinfo| blk: {
                if (ptrinfo.size != .slice) @compileError("Only slices are supported");
                break :blk 4;
            },
            .@"union" => 1,
            .@"struct" => 8
        }
    };
}

pub fn clone(self: *const Self, allocator: std.mem.Allocator) Self.Error!Self {
    var new = Self{
        .allocator = allocator,
        .path = if (self.path) |path| try allocator.dupe(u8, path) else null,
        .destination = if (self.destination) |dest| try allocator.dupe(u8, dest) else null,
        .error_name = if (self.error_name) |name| try allocator.dupe(u8, name) else null,
        .interface = if (self.interface) |iface| try allocator.dupe(u8, iface) else null,
        .sender = if (self.sender) |sender| try allocator.dupe(u8, sender) else null,
        .member = if (self.member) |member| try allocator.dupe(u8, member) else null,
        .flags = self.flags,
        .headers = cloneArrayList(std.ArrayList(Header), self.headers, allocator),
        .signature = try cloneArrayList(ArrayListBuffer, self.signature, allocator),
        .message_type = self.message_type,
        ._reader = null,
        .reply_serial = self.reply_serial,
        .serial = self.serial,
        .unix_fds = cloneArrayList(std.ArrayList(i32), self.unix_fds, allocator),
        .payload = try cloneArrayList(ArrayListBuffer, self.payload, allocator),
    };
    if (self._reader) |reader| {
        new._reader = .{
            .byteorder = reader.byteorder,
            .payload_stream = std.io.fixedBufferStream(self.payload.items),
            .signature_stream = std.io.fixedBufferStream(self.signature.items),
        };
    }
    return new;
}

fn cloneArrayList(comptime T: type, src: T, allocator: std.mem.Allocator) !T {
    var arrlist = T.init(allocator);
    errdefer arrlist.deinit();
    try arrlist.appendSlice(src.items);
    return arrlist;
}
