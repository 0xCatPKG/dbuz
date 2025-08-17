# DBuz - Pure Zig D-Bus client library

This library is more like a pet project and practice for me to learn Zig. It provides a simple interface to interact with D-Bus offloading multiple tasks to the zig's comptime.

## Installation

```sh
$ zig fetch --save git+https://github.com/0xCatPKG/dbuz
```

Then in your build.zig file, do something like
```zig
const std = @import("std");

pub fn build(b: *std.Build) void {

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dbuz = b.dependency("dbuz", .{
        .target = target,
        .optimize = optimize,
    });

    // ...

    exe_mod.addImport("dbuz", dbuz.module("dbuz"));
    // ...
}
```

## Usage

### Simple example

```zig
const std = @import("std");
const dbuz = @import("dbuz");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    /// Create connection to D-Bus session bus
    const connection = try dbuz.connect(allocator, .{});
    defer connection.deinit();

    const poll_cond, const poll_thread =
    try dbuz.spawnPollingThread(connection, allocator);

    defer allocator.destroy(poll_cond);
    defer poll_thread.join();
    defer poll_cond.* = false;

    std.posix.nanosleep(0, std.time.ns_per_ms * 25); // Sleep for some time to avoid busy loop

    std.debug.print('My unique name is: {?s}\n', .{connection.unique_name});
}
```

### Calling dbus standard methods

NOTICE! You must avoid calling blocking methods in pollers, as they will block until timeout is reached.

```zig
const std = @import("std");
const dbuz = @import("dbuz");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    /// Create connection to D-Bus session bus
    const connection = try dbuz.connect(allocator, .{});
    defer connection.deinit();

    const poll_cond, const poll_thread =
    try dbuz.spawnPollingThread(connection, allocator);

    defer allocator.destroy(poll_cond);
    defer poll_thread.join();
    defer poll_cond.* = false;

    const names = try connection.dbus().ListNames();
    for (names) |name| { // Notice, there name is not []const u8, but a custom DBusMessage struct
        std.debug.print("Name: {s}\n", .{name.value});
        name.deinit(allocator);
    }

    // Caller owns memory, so we free it manually
    allocator.free(names);
}
```

### Calling methods and waiting
```zig
const std = @import("std");
const dbuz = @import("dbuz");
const DBusString = dbuz.types.DBusString;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    /// Create connection to D-Bus session bus
    const connection = try dbuz.connect(allocator, .{});
    defer connection.deinit();

    const poll_cond, const poll_thread =
    try dbuz.spawnPollingThread(connection, allocator);

    defer allocator.destroy(poll_cond);
    defer poll_thread.join();
    defer poll_cond.* = false;

    const somestr = DBusString { .value = "Hello World!" };
    const someint: i32 = 42;
    const somebool: bool = true;

    const future = connection.call(.{
        .destination = "org.example.Test",
        .path = "/org/example/Test",
        .interface = "org.example.Interface",
        .member = "Somemethod",
    }, .{somestr, someint, somebool}, allocator) orelse unreachable;
    // Future in case if call is passed without
    // .flags = .{
    //     .no_reply = true,
    // },
    // will always return pointer to a DBusPendingResponse or an error

    // Second argument in call method is a tuple of values, library generates code for serialization at comptime using compile time reflection

    // There it can't return null unless call options has it's .feedback set to .call\
    // Reply is owned by future, when all references to it are dropped, it will be freed
    const reply = try future.wait(.{}) orelse unreachable;
    const x, const y, const z = try reply.read(struct{i32, DBusString, bool}, allocator);
    // Method above reads from DBusMessage values and returns type specified in first argument, allocations are done by allocator passed in second argument

    y.deinit(allocator);
}


}
```

### Example of publishing interfaces and names
TODO

## Serialization rules
dbuz serializes native types using compile time reflection. Following mapping exists:
| DBus signature symbol | Native type | Notes |
| --- | --- | --- |
| `y` | u/i1..8 | Any int with less or equal to 8 bits is serialized as a byte |
| `b` | bool | Boolean type |
| `n` | i9..16 | Any int with less or equal to 16 bits is serialized as a short |
| `q` | u9..16 | Any int with less or equal to 16 bits is serialized as a short |
| `i` | i17..32 | Any int with less or equal to 32 bits is serialized as an int |
| `u` | u17..32 | Any int with less or equal to 32 bits is serialized as an unsigned int |
| `x` | i33..64 | Any int with less or equal to 64 bits is serialized as a long |
| `t` | u33..64 | Any int with less or equal to 64 bits is serialized as an unsigned long |
| `d` | f1..64 | All floats must be less than or equal to 64 bits |
| `h` | std.fs.File, std.fs.Dir | Out of band data, uses .handle as file descriptor |
| `s` | DBusString | String type |
| `o` | DBusObjectPath | Object path type |
| `g` | DBusSignature | Signature type |
| `a` | []T | All pointers passed to de/serialization must be slices |
| `()` | struct{...} | All structs except tuples are serialized recursively according to their field native types, tuples are serialized as sequence of values |
| `{}` | struct{...} | All structs are serialized as dicts, if they have following declarations: put, getOrPut, getOrPutAdapted, get, iterator, KV |
| `v` | union(enum) {...} | All union types are serialized as a variants. Duplicate types are unchecked illegal behavior |
