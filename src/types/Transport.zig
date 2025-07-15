const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const cmsg_ = @import("../cmsg.zig");

comptime {
    if (!std.net.has_unix_sockets) {
        @compileError("Platform does not support Unix sockets");
    }
}

const Self = @This();

const has_out_of_band: bool = switch (builtin.target.os.tag) {
    .linux, .freebsd, .dragonfly, .macos, .netbsd, .openbsd, .solaris, .illumos, .fuchsia => true,
    else => false,
};

fd: posix.socket_t,
allocator: std.mem.Allocator,

pub fn init(socket: posix.socket_t, allocator: std.mem.Allocator) Self {
    return .{
        .fd = socket,
        .allocator = allocator,
    };
}

pub const Error = error {
    ConnectionLost,
    WouldBlock,
    BadCMSG
} || std.mem.Allocator.Error;

pub const OutOfBandData = union(enum) {
    none: void,
    rights: []const i32,
    creds: cmsg_.ucred,
    pidfd: i32,
};

const DataMessage = struct {
    data: []u8,
    fds: ?[]i32 = null,
    out_of_band: OutOfBandData,

    allocator: std.mem.Allocator,

    pub fn init(data: []const u8, out_of_band: OutOfBandData, allocator: std.mem.Allocator) std.mem.Allocator.Error!DataMessage {
        var oobd = OutOfBandData{ .none = {} };
        var fds: ?[]i32 = null;
        if (out_of_band == .rights) {
            fds = try allocator.dupe(i32, out_of_band.rights);
            oobd = .{ .rights = fds.? };
        } else {
            oobd = out_of_band;
        }

        const message = DataMessage{
            .data = try allocator.alloc(u8, data.len),
            .out_of_band = oobd,
            .fds = fds,
            .allocator = allocator,
        };
        std.mem.copyForwards(u8, message.data, data);
        return message;
    }

    pub fn deinit(self: DataMessage) void {
        self.allocator.free(self.data);
        if (self.fds != null) self.allocator.free(self.fds.?);
    }
};

pub fn write(self: *Self, buf: []const u8, out_of_band: OutOfBandData, should_block: bool) Error!void {
    const flags: u32 = if (!should_block) posix.MSG.DONTWAIT else 0 | posix.MSG.NOSIGNAL;
    const iovec = [_]posix.iovec_const{.{ .base = buf.ptr, .len = buf.len }};

    var msg = posix.msghdr_const{ .name = null, .namelen = 0, .flags = 0, .controllen = 0, .control = null, .iov = &iovec, .iovlen = 1 };

    switch (out_of_band) {
        .none => {
            _ = posix.sendmsg(self.fd, &msg, flags) catch |err| switch (err) {
                error.WouldBlock => return Error.WouldBlock,
                else => return Error.ConnectionLost
            };
        },
        .creds => |creds| {
            const cmsg = cmsg_.initStatic(cmsg_.ucred).init(cmsg_.SCM.CREDENTIALS, creds);
            msg.controllen = @truncate(cmsg.header.len);
            msg.control = &cmsg;

            _ = posix.sendmsg(self.fd, &msg, flags) catch |err| switch (err) {
                error.WouldBlock => return Error.WouldBlock,
                else => return Error.ConnectionLost
            };
        },
        .rights => |fds| {
            var cmsg_buf: [8192]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&cmsg_buf);
            const cmsg = try cmsg_.initRights(fba.allocator(), fds);
            msg.controllen = @truncate(cmsg.len);
            msg.control = cmsg;

            _ = posix.sendmsg(self.fd, &msg, flags) catch |err| switch (err) {
                error.WouldBlock => return Error.WouldBlock,
                else => return Error.ConnectionLost
            };
        },
        else => {},
    }
}

pub fn read(self: *Self, should_block: bool) Error!DataMessage {
    const flags: u32 = if (should_block) 0 else posix.MSG.DONTWAIT;

    var recvbuf: [10240]u8 = undefined;
    var recviov = [_]posix.iovec{.{
        .base = &recvbuf,
        .len = 10240,
    }};

    var recvcmsgbuf: [16 + 400]u8 align(8) = undefined;
    var recvmsg = posix.msghdr{ .name = undefined, .namelen = 0, .iov = &recviov, .iovlen = 1, .control = &recvcmsgbuf, .controllen = 16 + 400, .flags = 0 };

    const rc = std.os.linux.recvmsg(self.fd, &recvmsg, flags);
    switch (posix.errno(rc)) {
        .SUCCESS => {
            if (rc == 0) {
                return Error.ConnectionLost;
            }
            const cmsg = if (recvmsg.controllen > 0) cmsg_.bufferAsCmsghdr(@ptrCast(recvmsg.control)) else null;
            var oobd: OutOfBandData = .none;
            if (cmsg) |msg| {
                switch (msg.type) {
                    @intFromEnum(cmsg_.SCM.RIGHTS) => {
                        var fds: [100]i32 = undefined;
                        cmsg_.getRights(msg, fds[0..]) catch return Error.BadCMSG;
                        oobd = OutOfBandData{
                            .rights = fds[0..cmsg_.getRightsLength(msg) catch return Error.BadCMSG],
                        };
                    },
                    @intFromEnum(cmsg_.SCM.CREDENTIALS) => {
                        const creds: cmsg_.ucred = cmsg_.getCredentials(msg) catch return Error.BadCMSG;
                        oobd = OutOfBandData{
                            .creds = creds,
                        };
                    },
                    else => {
                        std.debug.print("Unhandled message type {d}\n", .{msg.type});
                    },
                }
            }
            return DataMessage.init(recvbuf[0..rc], oobd, self.allocator);
        },
        .AGAIN => {
            return Error.WouldBlock;
        },
        else => {
            return Error.ConnectionLost;
        },
    }

    unreachable;
}
