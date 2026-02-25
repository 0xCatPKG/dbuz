
/// Represents DBus Message.
const Message = @This();

const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const posix = std.posix;

const logger = std.log.scoped(.Message);

const dbuz = @import("../dbuz.zig");
const codec = dbuz.codec;

/// Message type according to DBus specifications 
pub const Type = enum (u8) {
    invalid = 0,
    method_call = 1,
    method_response = 2,
    @"error" = 3,
    signal = 4,
};

/// Messy mess used for serialization and deserialization.
body: struct {
    fdlist: ?std.ArrayList(i32) = null,
    op: union(enum) { read: struct {
        base: ?*Io.Reader,
        buffer: std.ArrayList(u8),
        fixed: ?Io.Reader = null,
        reader: ?codec.Reader = null,
        remaining: u32 = 0,
    }, write: struct {
        base: Io.Writer.Allocating,
        writer: ?codec.Writer = null,
        finished: bool = false,
    } } = undefined,
},

endian: std.builtin.Endian,

allocator: mem.Allocator,

type: Type = .invalid,

flags: struct { no_reply_expected: bool = false, no_auto_start: bool = false, allow_interactive_authorization: bool = false } = .{},

size: u32 = 0,
serial: u32 = 0,

fields: struct {
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    reply_serial: ?u32 = null,
    destination: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    signature: ?[]const u8 = null,
    unix_fd_amount: u32 = 0,
} = .{},

/// Initializes a new empty message for writing.
pub fn initWriting(allocator: mem.Allocator, endian: std.builtin.Endian, with_fds: bool) !Message {
    var m: Message = .{
        .endian = endian,
        .allocator = allocator,
        .body = .{
            .fdlist = if (with_fds) try std.ArrayList(i32).initCapacity(allocator, 100) else null,
        },
    };
    m.body.op = .{ .write = .{
        .base = Io.Writer.Allocating.init(allocator),
    } };
    return m;
}

/// Acquire writer for message. Is a checked illegal behavior to request writer for message that is not opened for writing.
pub fn writer(self: *Message) *codec.Writer {
    return switch (self.body.op) {
        .write => {
            return if (self.body.op.write.writer) |*w| w else blk: {
                self.body.op.write.writer = codec.Writer.from(self.allocator, &self.body.op.write.base.writer, if (self.body.fdlist) |*fds| fds else null);
                self.body.op.write.writer.?.endian = self.endian;
                break :blk &(self.body.op.write.writer.?);
            };
        },
        else => @panic("Message is not opened for writing"),
    };
}

/// Acquire reader for message. Is a checked illegal behavior to request reader for message that is not opened for reading.
/// If message is not complete yet (we still in process of receiving chunks from DBus), it is an error to call this method and generally this should be impossible.
pub fn reader(self: *Message) !*codec.Reader {
    return switch (self.body.op) {
        .read => {
            if (self.body.op.read.remaining > 0) return error.MessageNotFullyRead;
            return if (self.body.op.read.reader) |*r| r else {
                self.body.op.read.reader = codec.Reader.from(self.allocator, &self.body.op.read.fixed.?, if (self.body.fdlist) |*fds| fds else null, self.endian);
                return &self.body.op.read.reader.?;
            };
        },
        else => @panic("Message is not opened for reading"),
    };
}

/// Initialize message for reading. Message may be incomplete after this method, make sure to call isComplete before requesting reader from it.
pub fn initReading(allocator: mem.Allocator, r: *Io.Reader, fds_source: ?*std.ArrayList(i32)) !Message {
    var sreader = codec.Reader.from(allocator, r, null, .little);

    const endian, const _type, const flags, const version = try sreader.read(struct { u8, u8, u8, u8 }, null);

    // std.debug.print("DBus Message Header: endian={c}, type={d}, flags={d}, version={d}\n", .{ endian, _type, flags, version });

    if (version != 1) return error.UnsupportedDBusVersion;
    sreader.endian = if (endian == 'l') .little else if (endian == 'B') .big else return error.InvalidEndian;

    const size, const serial = try sreader.read(struct { u32, u32 }, null);

    // std.debug.print("DBus Message Body: size={d}, serial={d}\n", .{ size, serial });

    if (serial == 0) return error.InvalidSerial;

    var m: Message = .{
        .endian = sreader.endian,
        .allocator = allocator,
        .type = @enumFromInt(_type),
        .flags = .{
            .no_reply_expected = (flags & 0x1) != 0,
            .no_auto_start = (flags & 0x2) != 0,
            .allow_interactive_authorization = (flags & 0x4) != 0,
        },
        .size = size,
        .serial = serial,
        .body = .{
            .fdlist = null,
            .op = .{ .read = .{
                .base = r,
                .buffer = .empty,
                .remaining = size,
            } },
        },
    };

    errdefer {
        m.body.op.read.buffer.deinit(allocator);
        if (m.body.fdlist) |*fdlist| {
            fdlist.deinit(allocator);
        }

        if (m.fields.destination) |dest| allocator.free(dest);
        if (m.fields.error_name) |ename| allocator.free(ename);
        if (m.fields.interface) |iface| allocator.free(iface);
        if (m.fields.member) |member| allocator.free(member);
        if (m.fields.path) |path| allocator.free(path);
        if (m.fields.signature) |sig| allocator.free(sig);
    }

    const HeaderType = union(enum) {
        u32: u32,
        string: dbuz.types.String,
        object_path: dbuz.types.ObjectPath,
        signature: dbuz.types.Signature,
    };

    const HeadersDict = std.AutoArrayHashMap(u8, HeaderType);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var headers = try sreader.read(HeadersDict, arena.allocator());

    var hdr_it = headers.iterator();
    while (hdr_it.next()) |entry| {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;

        switch (key) {
            1 => m.fields.path = switch (value) {
                .object_path => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            2 => m.fields.interface = switch (value) {
                .string => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            3 => m.fields.member = switch (value) {
                .string => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            4 => m.fields.error_name = switch (value) {
                .string => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            5 => m.fields.reply_serial = switch (value) {
                .u32 => |v| v,
                else => return error.InvalidHeaderType,
            },
            6 => m.fields.destination = switch (value) {
                .string => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            7 => m.fields.sender = switch (value) {
                .string => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            8 => m.fields.signature = switch (value) {
                .signature => |v| try allocator.dupe(u8, v.value),
                else => return error.InvalidHeaderType,
            },
            9 => m.fields.unix_fd_amount = switch (value) {
                .u32 => |v| v,
                else => return error.InvalidHeaderType,
            },
            else => {},
        }
    }

    if (m.fields.unix_fd_amount > 0 and fds_source == null) {
        return error.UnixFdsButNoSource;
    }

    if (fds_source) |fds| {
        if (fds.items.len < m.fields.unix_fd_amount) {
            return error.NotEnoughUnixFds;
        } else if (m.fields.unix_fd_amount > 0) {
            m.body.fdlist = std.ArrayList(i32).fromOwnedSlice(try allocator.dupe(i32, fds.items[0..m.fields.unix_fd_amount]));
            try fds.replaceRangeBounded(0, fds.items.len - m.fields.unix_fd_amount, fds.items[m.fields.unix_fd_amount..]);
        }
    }

    try sreader.alignReader(8);
    _ = m.continueReading() catch |err| {
        if (err != error.EndOfStream) return m
        else return error.EndOfStream;
    };

    logger.debug(\\Initialized new message for reading:
                 \\    serial: {},
                 \\    type:   {s},
                 \\    sender: {?s},
                 \\    dest:   {?s},
                 \\    path:   {?s},
                 \\    member: {?s},
                 \\    iface:  {?s},
                 \\    reply:  {?},
                 \\ -------
                 \\
    , .{
            m.serial,
            @tagName(m.type),
            m.fields.sender,
            m.fields.destination,
            m.fields.path,
            m.fields.member,
            m.fields.interface,
            m.fields.reply_serial
        }
    );

    return m;
}

/// Continue reading from *Io.Reader that was passed during initReading. Returns true if message is now complete.
pub fn continueReading(self: *Message) !bool {
    return switch (self.body.op) {
        .read => {
            if (self.body.op.read.remaining == 0) {
                self.body.op.read.fixed = Io.Reader.fixed(self.body.op.read.buffer.items[0..]);
                self.body.op.read.base = null;
                logger.debug("Message:{} is fully read", .{self.serial});
                return true;
            }
            const r = self.body.op.read.base.?;

            var dest: [1024]u8 = undefined;

            const to_read = self.body.op.read.remaining;
            const read_bytes = try r.readSliceShort(dest[0..@min(to_read, dest.len)]);

            try self.body.op.read.buffer.appendSlice(self.allocator, dest[0..read_bytes]);
            self.body.op.read.remaining -= @as(u32, @intCast(read_bytes));

            if (self.body.op.read.remaining == 0) {
                self.body.op.read.fixed = Io.Reader.fixed(self.body.op.read.buffer.items[0..]);
                logger.debug("Message:{} is fully read", .{self.serial});
                self.body.op.read.base = null;
            }

            return self.body.op.read.remaining == 0;
        },
        else => @panic("Message is not opened for reading"),
    };
}

pub fn isComplete(self: *const Message) bool {
    return switch (self.body.op) {
        .read => self.body.op.read.remaining == 0,
        else => @panic("Message is not opened for reading"),
    };
}

/// Writes final message down the given writer. If fw is provided and the message contains file descriptor set, also sets file to be sent.
pub fn write(self: *Message, w: *Io.Writer, fw: ?*[]const i32) !void {
    return switch (self.body.op) {
        .write => {
            logger.debug(\\Writing message to writer:
                        \\    serial: {},
                        \\    type:   {s},
                        \\    sender: {?s},
                        \\    dest:   {?s},
                        \\    path:   {?s},
                        \\    member: {?s},
                        \\    iface:  {?s},
                        \\    reply:  {?},
                        \\ -------
                        \\
            , .{
                    self.serial,
                    @tagName(self.type),
                    self.fields.sender,
                    self.fields.destination,
                    self.fields.path,
                    self.fields.member,
                    self.fields.interface,
                    self.fields.reply_serial
                }
            );
            if (self.serial == 0) return error.InvalidSerial;
            const body = self.body.op.write.base.written();

            var hw = codec.Writer.from(self.allocator, w, null);
            hw.endian = self.endian;

            var bitset: u8 = 0;
            if (self.flags.no_reply_expected) bitset |= 0x1;
            if (self.flags.no_auto_start) bitset |= 0x2;
            if (self.flags.allow_interactive_authorization) bitset |= 0x4;

            const endian: u8 = if (self.endian == .little) 'l' else 'B';
            const mtype = @intFromEnum(self.type);
            const flags: u8 = @as(u8, @intCast(bitset));

            try hw.write(struct { u8, u8, u8, u8 }{ endian, mtype, flags, 1 });

            try hw.write(struct { u32, u32 }{
                @truncate(body.len),
                self.serial,
            });

            const HeaderType = union(enum) {
                u32: u32,
                string: dbuz.types.String,
                object_path: dbuz.types.ObjectPath,
                signature: dbuz.types.Signature,
            };

            const HeadersDict = std.AutoArrayHashMap(u8, HeaderType);

            var headers = HeadersDict.init(self.allocator);

            if (self.fields.path) |path| {
                try headers.put(1, .{ .object_path = .{ .value = path } });
            }

            if (self.fields.interface) |interface| {
                try headers.put(2, .{ .string = .{ .value = interface } });
            }

            if (self.fields.member) |member| {
                try headers.put(3, .{ .string = .{ .value = member } });
            }

            if (self.fields.error_name) |error_name| {
                try headers.put(4, .{ .string = .{ .value = error_name } });
            }

            if (self.fields.reply_serial) |reply_serial| {
                try headers.put(5, .{ .u32 = reply_serial });
            }

            if (self.fields.destination) |destination| {
                try headers.put(6, .{ .string = .{ .value = destination } });
            }

            if (self.fields.sender) |sender| {
                try headers.put(7, .{ .string = .{ .value = sender } });
            }

            if (self.fields.signature) |signature| {
                try headers.put(8, .{ .signature = .{ .value = signature } });
            }

            if (self.body.fdlist) |fdlist| {
                if (fdlist.items.len > 0) {
                    if (fw == null) return error.UnixFdsButNoSink
                    else {
                        try headers.put(9, .{ .u32 = @truncate(fdlist.items.len) });
                        fw.?.* = fdlist.items[0..];
                    }
                }
            }

            try hw.write(headers);
            try hw.alignWriter(8);

            // std.debug.print("Writing message body of size {d}\n", .{body.len});
            if (body.len > 0) try w.writeAll(body);
        },
        else => @panic("Message is not opened for writing"),
    };
}

pub fn estimatedSize(self: *const Message) u32 {
    // _ = self;
    // return 1024;
    return 16 // Header size
    + if (self.fields.path) |path| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, path.len, 8) + 1)) else 0 
    + if (self.fields.interface) |interface| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, interface.len, 8) + 1)) else 0
    + if (self.fields.member) |member| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, member.len, 8) + 1)) else 0
    + if (self.fields.error_name) |error_name| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, error_name.len, 8) + 1)) else 0
    + if (self.fields.reply_serial) |_| 1 + 1 + 4 else 0
    + if (self.fields.destination) |destination| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, destination.len, 8) + 1)) else 0
    + if (self.fields.sender) |sender| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, sender.len, 8) + 1)) else 0
    + if (self.fields.signature) |signature| 1 + 1 + 4 + @as(u32, @truncate(mem.alignForward(usize, signature.len, 8) + 1)) else 0
    + if (self.fields.unix_fd_amount > 0) 1 + 1 + 4 else 0
    + @as(u32, @truncate(mem.alignForward(usize, switch (self.body.op) {
                                            .read => self.body.op.read.buffer.items.len,
                                            .write => self.body.op.write.base.writer.buffered().len,
                                        }, 8)));
}

pub fn deinit(self: *Message) void { 
    switch (self.body.op) {
        .read => {
            if (self.body.fdlist) |fdlist| {
                for (fdlist.items) |fd| {
                    posix.close(fd);
                }
            }
            self.body.op.read.buffer.deinit(self.allocator);
        },
        .write => {
            self.body.op.write.base.deinit();
        },
    }

    if (self.body.fdlist) |*fdlist| {
        fdlist.deinit(self.allocator);
    }
}

pub fn setPath(self: *Message, path: []const u8) *Message {
    self.fields.path = path;
    return self;
}

pub fn setInterface(self: *Message, interface: []const u8) *Message {
    self.fields.interface = interface;
    return self;
}

pub fn setMember(self: *Message, member: []const u8) *Message {
    self.fields.member = member;
    return self;
}

pub fn setErrorName(self: *Message, error_name: []const u8) *Message {
    self.fields.error_name = error_name;
    return self;
}

pub fn setDestination(self: *Message, destination: []const u8) *Message {
    self.fields.destination = destination;
    return self;
}

pub fn setSender(self: *Message, sender: []const u8) *Message {
    self.fields.sender = sender;
    return self;
}

pub fn setSignature(self: *Message, signature: []const u8) *Message {
    self.fields.signature = signature;
    return self;
}

pub fn setReplySerial(self: *Message, reply_serial: u32) *Message {
    self.fields.reply_serial = reply_serial;
    return self;
}

pub fn setUnixFdAmount(self: *Message, amount: u32) *Message {
    self.fields.unix_fd_amount = amount;
    return self;
}
