const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const posix = std.posix;
const net = std.net;

const transport = @import("transport.zig");

pub const AuthClient = struct {
    mechanism: enum {
        External,
        Unknown,
    } = .External,

    state: enum {
        MechanismSelection,
        DataResponse,
        UnixFDResponse
    },

    reader: transport.Reader,
    allocator: mem.Allocator,

    handle: posix.fd_t,

    pub fn auth(allocator: mem.Allocator, stream: net.Stream ) !void {
        var client: AuthClient = .{
            .state = .MechanismSelection,
            .reader = try transport.Reader.init(allocator, stream.handle, 4096),
            .allocator = allocator,
            .handle = stream.handle,
        };
        defer client.reader.deinit();

        var writer = stream.writer(&.{});
        const w = &writer.interface;

        const vec: []const []const u8 = &.{
            "\x00AUTH EXTERNAL\r\n",
            "DATA\r\n",
            "NEGOTIATE_UNIX_FD\r\n",
        };

        _ = try w.writeVec(vec);
        const r = &client.reader.interface;
        
        while (true) {
            const line = (try r.takeDelimiter('\n')).?;
            if (line[line.len - 1] != '\r') return error.InvalidResponse;
            switch (client.state) {
                .MechanismSelection => {
                    if (mem.startsWith(u8, line, "REJECTED")) return error.AuthMechanismNotSupported
                    else if (mem.startsWith(u8, line, "DATA")) {
                        client.state = .DataResponse;
                    } else {
                        return error.InvalidResponse;
                    }
                },
                .DataResponse => {
                    if (mem.startsWith(u8, line, "OK")) {
                        client.state = .UnixFDResponse;
                    } else {
                        return error.InvalidResponse;
                    }
                },
                .UnixFDResponse => {
                    if (mem.startsWith(u8, line, "AGREE_UNIX_FD")) {
                        _ = try w.write("BEGIN\r\n");
                        return;
                    } else {
                        return error.UnixFDNotSupported;
                    }
                }
            }
        }
    }


};
pub const AuthServer = struct {};

test "SASL AuthClient External Mechanism" {
    const allocator = std.testing.allocator;

    const stream = try net.connectUnixSocket("/run/user/1000/bus");
    defer stream.close();

    try AuthClient.auth(allocator, stream);
}
