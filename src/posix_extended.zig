const std = @import("std");
const mem = std.mem;
const posix = std.posix;

const builtin = @import("builtin");

pub const has_recvmsg = builtin.os.tag == .linux or builtin.link_libc;
pub const recvmsg = if (builtin.os.tag == .linux) std.os.linux.recvmsg else if (builtin.link_libc) std.c.recvmsg else unreachable;


