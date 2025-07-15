
const std = @import("std");
const autoHash = std.hash.autoHashStrat;
const Wyhash = std.hash.Wyhash;

const dbus_types = @import("dbus_types.zig");
const String = dbus_types.String;
const ObjectPath = dbus_types.ObjectPath;
const Signature = dbus_types.Signature;

pub fn from(comptime K: type, comptime V: type) type {
    return std.hash_map.HashMap(K, V, struct {
        pub const hash = getHashFn(K, @This());
        pub const eql = getEqlFn(K, @This());
    }, std.hash_map.default_max_load_percentage);
}

fn getHashFn(comptime K: type, comptime Context: type) (fn (Context, K) u64) {
    return struct {
        fn hash(ctx: Context, key: K) u64 {
            _ = ctx;
            if (std.meta.hasUniqueRepresentation(K)) {
                return Wyhash.hash(0, std.mem.asBytes(&key));
            } else {
                var hasher = Wyhash.init(0);
                autoHash(&hasher, key, .Deep);
                return hasher.final();
            }
        }
    }.hash;
}

fn getEqlFn(comptime K: type, comptime Context: type) (fn (Context, K, K) bool) {
    return struct {
        fn eql(ctx: Context, a: K, b: K) bool {
            return std.meta.eql(ctx.hash(a), ctx.hash(b));
        }
    }.eql;
}

pub fn cleanDeinit(dict: anytype, allocator: std.mem.Allocator) void {
    var it = dict.iterator();
    while (it.next()) |entry| {
        dbus_types.deinitValueRecursive(entry.key_ptr.*, allocator);
        dbus_types.deinitValueRecursive(entry.value_ptr.*, allocator);
    }
    dict.deinit();
}
