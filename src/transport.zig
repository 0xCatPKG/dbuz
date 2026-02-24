const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const posix = std.posix;

const assert = std.debug.assert;

const cmsg = @import("cmsg.zig");
const posixe = @import("posix_extended.zig");

pub const Reader = struct {
    handle: posix.fd_t,
    buffer: []u8,

    allocator: mem.Allocator,
    interface: Io.Reader,

    control_buffer: [512]u8 align(@alignOf(cmsg.cmsghdr)) = undefined,
    control_used: bool = false,

    pending_flags: u32 = 0,

    pub fn init(allocator: mem.Allocator, handle: posix.fd_t, buffer_size: usize) !Reader {
        const buffer = try allocator.alloc(u8, buffer_size);
        return Reader{
            .handle = handle,
            .buffer = buffer,
            .allocator = allocator,
            .interface = .{
                .buffer = buffer,
                .seek = 0,
                .end = 0,
                .vtable = &.{
                    .stream = stream,
                    .readVec = readVec,
                }
            }
        };
    }

    fn readVec(io_reader: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        // std.debug.print("Reader.readVec\n", .{});
        const r: *Reader = @alignCast(@fieldParentPtr("interface", io_reader));
        if (posixe.has_recvmsg) {
            var iovecs: [8]posix.iovec = undefined;
            const dest_n, const data_size = try io_reader.writableVectorPosix(&iovecs, data);
            const dest = iovecs[0..dest_n];
            assert(dest[0].len > 0);

            var message_header: posix.msghdr = .{
                .name = null,
                .namelen = 0,
                .iov = dest.ptr,
                .iovlen = dest_n,
                .control = @ptrCast(r.control_buffer[0..].ptr),
                .controllen = r.control_buffer.len,
                .flags = 0
            };

            const n = posixe.recvmsg(r.handle, &message_header, 0);

            if (n < 0) return error.ReadFailed;
            if (n == 0) return error.EndOfStream;
            r.control_used = message_header.controllen > 0;
            if (n > data_size) {
                io_reader.end += n - data_size;
                return data_size;
            }
            return n;
        }
        @compileError("Target platform don't supported yet");
    }

    fn stream(io_reader: *Io.Reader, io_writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_writer.writableSliceGreedy(1));
        var bufs: [1][]u8 = .{dest};
        const n = try readVec(io_reader, &bufs);
        io_writer.advance(n);
        return n;
    }

    pub fn pendingControlMessageType(self: *Reader) ?cmsg.SCM {
        if (!self.control_used) return null;
        const header = cmsg.bufferAsCmsghdr(self.control_buffer[0..].ptr);
        return @enumFromInt(header.type);
    }

    pub fn takeFileDescriptors(self: *Reader, fds: []i32) !usize {
        if (!self.control_used) return error.NoControlMessage;
        const header = cmsg.bufferAsCmsghdr(self.control_buffer[0..].ptr);
        const count = cmsg.getRightsLength(header) catch @panic("Header corrupted!");
        if (fds.len < count) return error.BufferTooSmall;
        try cmsg.getRights(header, fds[0..count]);
        self.control_used = false;
        return count;
    }

    pub fn takeCredentials(self: *Reader) !cmsg.ucred {
        if (!self.control_used) return error.NoControlMessage;
        const header = cmsg.bufferAsCmsghdr(self.control_buffer[0..].ptr);
        const cred = try cmsg.getCredentials(header);
        self.control_used = false;
        return cred;
    }

    pub fn takePidFD(self: *Reader) !i32 {
        if (!self.control_used) return error.NoControlMessage;
        const header = cmsg.bufferAsCmsghdr(self.control_buffer[0..].ptr);
        const pidfd = try cmsg.getPidFD(header);
        self.control_used = false;
        return pidfd;
    }

    pub fn discardControlMessage(self: *Reader) void {
        const cmsghdr = cmsg.bufferAsCmsghdr(self.control_buffer[0..].ptr);
        switch (@as(cmsg.SCM, @enumFromInt(cmsghdr.type))) {
            .RIGHTS => {
                var fds: [100]i32 = undefined;
                const count = cmsg.getRightsLength(cmsghdr) catch @panic("Header corrupted!");
                if (count > fds.len) @panic("Too many file descriptors!");
                cmsg.getRights(cmsghdr, fds[0..count]) catch return;
                for (fds[0..count]) |fd| {
                    posix.close(fd);
                }
            },
            .PIDFD => {
                const pidfd = cmsg.getPidFD(cmsghdr) catch return;
                posix.close(pidfd);
            },
            else => {}
        }
        self.control_used = false;
    }

    pub fn setPendingFlags(self: *Reader, flags: u32) void {
        self.pending_flags = flags;
    }

    pub fn deinit(self: *Reader) void {
        self.allocator.free(self.buffer);
    }
};

pub const Writer = struct {
    handle: posix.fd_t,
    buffer: Io.Writer.Allocating,

    interface: Io.Writer,

    control_buffer: [512]u8 align(@alignOf(cmsg.cmsghdr)) = undefined,
    control_pending_len: usize = 0,
    pending_flags: u32 = 0,

    pub fn init(allocator: mem.Allocator, handle: posix.fd_t, buffer_size: usize) !Writer {
        return Writer{
            .handle = handle,
            .buffer = try Io.Writer.Allocating.initCapacity(allocator, buffer_size),
            .interface = .{
                .buffer = &.{},
                .end = 0,
                .vtable = &.{
                    .drain = drain,
                    .flush = flush,
                }
            }
        };
    }

    pub fn deinit(self: *Writer) void {
        self.buffer.deinit();
    }

    pub fn drain(io_writer: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const w: *Writer = @alignCast(@fieldParentPtr("interface", io_writer));
        const writer = &w.buffer.writer;
        var n: usize = 0;
        for (data, 0..) |buf, i| {
            assert(buf.len > 0);
            if (i == data.len - 1 and splat > 1) {
                for (0..splat) | _ | {
                    try writer.writeAll(buf);
                    n += buf.len;
                }
            } else {
                try writer.writeAll(buf);
                n += buf.len;
            }
        }
        return n;
    }

    pub fn flush(io_writer: *Io.Writer) Io.Writer.Error!void {
        const w: *Writer = @alignCast(@fieldParentPtr("interface", io_writer));

        const data: []const u8 = w.buffer.written();

        const src: [1]posix.iovec_const = .{
            .{
                .base = data[0..].ptr,
                .len = data.len,
            }
        };

        var message_header: posix.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = src[0..].ptr,
            .iovlen = 1,
            .control = if (w.control_pending_len > 0) @ptrCast(w.control_buffer[0..].ptr) else null,
            .controllen = w.control_pending_len,
            .flags = 0
        };

        // std.debug.print("Writer.flush: writing {d} bytes with {d} control bytes\nBuffer debug:\n", .{data.len, w.control_pending_len});
        // for (data, 1..) |byte, i| {
        //     std.debug.print("{x:0>2} ", .{byte});
        //     if (i % 8 == 0) std.debug.print("\n", .{});
        //     if (i % 64 == 0) std.debug.print("\n", .{});
        // }
        // std.debug.print("\n", .{});

        _ = posix.sendmsg(w.handle, &message_header, w.pending_flags) catch return error.WriteFailed;

        // Reinitialize the buffer

        w.control_pending_len = 0;
        w.pending_flags = 0;
        return;
    }

    pub fn putFDs(self: *Writer, fds: []const i32) !void {
        var cmsg_allocator = std.heap.FixedBufferAllocator.init(&self.control_buffer);
        _ = try cmsg.initRights(cmsg_allocator.allocator(), fds);
        self.control_pending_len = cmsg_allocator.end_index;
    }
};
