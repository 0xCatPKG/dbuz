const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

pub const SCM = enum(u8) { RIGHTS = 0x01, CREDENTIALS = 0x02, SECURITY = 0x03, PIDFD = 0x04 };

pub const ucred = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

pub const cmsghdr = extern struct {
    len: usize,
    level: c_int,
    type: c_int,
};

pub fn initStatic(comptime T: type) type {
    return extern struct {
        const Self = @This();

        header: cmsghdr,
        data: [@sizeOf(T)]u8 align(@alignOf(usize)),

        pub fn init(scm_type: SCM, data: T) Self {
            var self: Self = undefined;
            self.header = .{
                .len = @offsetOf(Self, "data") + @sizeOf(T),
                .level = posix.SOL.SOCKET,
                .type = @intFromEnum(scm_type),
            };

            const data_u8: [*]const u8 = @ptrCast(&data);
            std.mem.copyForwards(u8, &self.data, data_u8[0..@sizeOf(T)]);
            return self;
        }
    };
}

pub fn initRights(allocator: std.mem.Allocator, fds: []const i32) !*cmsghdr {
    const size = std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize)) + fds.len * @sizeOf(i32);
    const buffer = (try allocator.alignedAlloc(u8, @alignOf(cmsghdr), size)).ptr;
    @memset(buffer[0..size], 0);
    const header: *cmsghdr = @ptrCast(buffer);
    const data_start = buffer + std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize));

    header.* = .{
        .len = size,
        .level = posix.SOL.SOCKET,
        .type = @intFromEnum(SCM.RIGHTS),
    };

    const data_u8: [*]const u8 = @ptrCast(fds.ptr);
    std.mem.copyForwards(u8, data_start[0 .. fds.len * @sizeOf(i32)], data_u8[0 .. fds.len * @sizeOf(i32)]);
    return header;
}

pub fn initCredentials(allocator: std.mem.Allocator, creds: ucred) !*cmsghdr {
    const size = std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize)) + @sizeOf(ucred);
    const buffer = (try allocator.alignedAlloc(u8, @alignOf(cmsghdr), size)).ptr;
    @memset(buffer[0..size], 0);
    const header: *cmsghdr = @ptrCast(buffer);
    const data_start = buffer + std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize));

    header.* = .{
        .len = size,
        .level = posix.SOL.SOCKET,
        .type = @intFromEnum(SCM.CREDENTIALS),
    };

    const data_u8: [*]const u8 = @ptrCast(&creds);
    std.mem.copyForwards(u8, data_start[0..@sizeOf(ucred)], data_u8[0..@sizeOf(ucred)]);
    return header;
}

pub fn initPidFD(allocator: std.mem.Allocator, pidfd: i32) !*cmsghdr {
    const size = std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize)) + @sizeOf(i32);
    const buffer = (try allocator.alignedAlloc(u8, @alignOf(cmsghdr), size)).ptr;
    @memset(buffer[0..size], 0);
    const header: *cmsghdr = @ptrCast(buffer);
    const data_start = std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize));

    header.* = .{
        .len = size,
        .level = posix.SOL.SOCKET,
        .type = @intFromEnum(SCM.PIDFD),
    };

    const data_u8: [*]const u8 = @ptrCast(&pidfd);
    std.mem.copyForwards(u8, data_start[0..@sizeOf(i32)], data_u8[0..@sizeOf(i32)]);
    return header;
}

pub fn deinit(allocator: std.mem.Allocator, header: *cmsghdr) void {
    const size = header.len;
    const buffer_u8: [*]u8 = @ptrCast(header);
    const allocated_buffer: []u8 = buffer_u8[0..size];

    allocator.free(allocated_buffer);
}

pub fn bufferAsCmsghdr(buffer: [*]u8) *cmsghdr {
    const header: *cmsghdr = @alignCast(@ptrCast(buffer));
    return header;
}

pub fn getRightsLength(header: *cmsghdr) !usize {
    const data_size = header.len - std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize));
    const fd_count = data_size / @sizeOf(i32);
    if (fd_count > 100) return CmsgError.BadHeader;
    return fd_count;
}

pub fn getRights(header: *cmsghdr, fds: []i32) !void {
    const header_ptr: [*]cmsghdr = @ptrCast(header);

    const buffer_ptr: [*]u8 = @ptrCast(header_ptr);
    const data_start: [*]u8 = buffer_ptr + std.mem.alignForward(usize, @sizeOf(cmsghdr), @alignOf(usize));
    const data_size = header.len - @sizeOf(cmsghdr);
    const fd_count = data_size / @sizeOf(i32);

    if (fd_count > 100) return CmsgError.BadHeader;

    const fds_bufptr: [*]u8 = @ptrCast(fds);

    std.mem.copyForwards(u8, fds_bufptr[0..data_size], data_start[0..data_size]);
}

pub fn getPidFD(header: *cmsghdr) CmsgError!i32 {
    const header_ptr: [*]cmsghdr = @ptrCast(header);
    const data_start: [*]u8 = @ptrCast(header_ptr + 1);
    const data_size = header.len - @sizeOf(cmsghdr);

    if (data_size < @sizeOf(i32)) {
        return CmsgError.BadPayload;
    }

    var fd: i32 = undefined;
    var fd_bufptr: [*]u8 = @ptrCast(&fd);

    std.mem.copyForwards(u8, fd_bufptr[0..@sizeOf(i32)], data_start[0..data_size]);
    return fd;
}

pub fn getCredentials(header: *cmsghdr) !ucred {
    const header_ptr: [*]cmsghdr = @ptrCast(header);
    const data_start: [*]u8 = @ptrCast(header_ptr + 1);
    const data_size = header.len - @sizeOf(cmsghdr);

    if (data_size < @sizeOf(ucred)) {
        return CmsgError.BadPayload;
    }

    var creds: ucred = undefined;
    var cred_buf: [*]u8 = @ptrCast(&creds);

    std.mem.copyForwards(u8, cred_buf[0..@sizeOf(ucred)], data_start[0..data_size]);
    return creds;
}

pub const CmsgError = error{ BadPayload, BadHeader };
