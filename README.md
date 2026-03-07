# DBuz - Pure Zig D-Bus client library

This library is more like a pet project and practice for me to learn Zig. It provides a simple interface to interact with D-Bus offloading multiple tasks to the zig's comptime.

## Installation

```sh
$ zig fetch --save git+https://git.rvvm.dev/0xCatPKG/dbuz
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
    const connection = try dbuz.connect(allocator, .Session);
    defer connection.deinit();

    var looper_exit: bool = false;
    const looper_thread = try dbuz.spawnLooperThread(allocator, connection, &looper_exit);
    defer looper_thread.join();

    try connection.hello();
    looper_exit = true;
    std.debug.print('My unique name is: {?s}\n', .{connection.unique_name});
}
```

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
| `h` | any struct that contains .handle is considered to be fd | Out of band data, uses .handle as file descriptor |
| `s` | dbuz.types.String | String type |
| `o` | dbuz.types.ObjectPath | Object path type |
| `g` | dbuz.types.Signature | Signature type |
| `a` | []T | All pointers passed to de/serialization must be slices |
| `()` | struct{...} | All structs **except tuples** are serialized recursively according to their field native types, tuples are serialized as sequence of values |
| `{}` | struct{...} | All structs are serialized as dicts, if they have following declarations: put, getOrPut, getOrPutAdapted, get, iterator, KV |
| `v` | union(enum) {...} | All union types are serialized as a variants. Duplicate types are unchecked illegal behavior |

Enums are serialized as their corresponding tag type. Exhaustive arrays are not supported for deserialization, as DBus can return any value, and dbuz internally uses `@enumFromInt()` for enum deserialization.

## Publishing interfaces

Sometimes you want to handle incoming method call or publish some properties on known path with some interface name.
dbuz provides 2 general ways to handle incoming messages: DIY way where you filter all incoming messages by yourself,
or by creating structure that implements dbuz.types.Interface. Here we will skip DIY way and will look into semi-automatic way.

Lets assume we want to implement some interface named `org.example.MyInterface` on path `/org/example/MyObject`.

```zig

const dbuz = @import("dbuz");
const Method = dbuz.types.Method;
const Signal = dbuz.types.Signal;
const Property = dbuz.types.Property;

const Interface = dbuz.types.Interface;

// ...
    const MyInterfacePrototype = struct {\
        // Required!
        pub const interface_name: []const u8 = "org.example.MyInterface";
        
        // Our methods that we want glue code for.
        pub const Echo = Method(echo, .{});
        pub const Add = Method(add, .{});
        pub const Fail = Method(fail, .{});

        // Some property
        pub const version = Property(u32, &1, .{});

        // And some signal. Signals in interface prototypes are just used for DBus-introspection autogen.
        pub const SomeSignal = Signal(struct{dbuz.types.String, u32}, .{});

        fn echo(_: *MyInterfacePrototype, text: dbuz.types.String) dbuz.types.String {
            return text;
        }

        fn add(_: *MyInterfacePrototype, a: u32, b: u32) u32 {
            return a + b;
        }

        fn fail(_: *MyInterfacePrototype) !void {
            return error.VeryError;
        }
    };

    // We generate glue code for our interface prototype in comptime. Second argument can be used to provide our introspection xml
    const MyInterface = Interface.AutoInterface(MyInterfacePrototype, null);
    
    // We assume that allocator already defined beforehand.
    const iface_impl = try MyInterface.create(allocator);
    defer if (iface_impl.interface.release() == 1) iface_impl.interface.deinit(allocator);

    // Property initialization. (This step is required! Unless you want garbage data inside of your properties of course)
    // You must explicitly initialize properties, for which no default value was provided! (In current example default value of 1 is provided for version)
    iface_impl.properties = .{};

    // Finally, register created interface on connection. Be sure to only register it after initialization, as we have no guarantee
    // that some other bus connection will not start introspection and try to get values from unitialized .properties
    // `allocator` here is an allocator used to allocate iface_impl in question. As there's no restriction on control flow,
    // anyone can release last reference to an interface, so all parties must have original allocator used for allocation.
    try connection.registerInterface(iface_impl, "/org/example/MyObject", allocator);
    // Starting from that point, connection is capable of processing of method calls automatically. Only prerequisite is looper running
    // or some other mechanism that will call connection.handleMessage

    defer _ = connection.unregisterInterface(iface_impl, "/org/example/MyObject");
// ...


```

This design still not refined, and any suggestions are welcome.

## Subbing to signals

This part assumes that you already have an proxy object (TODO: Proxy objects guide.). One of such objects is instance of `org.freedesktop.DBus` proxy located at `connection.dbus`


```zig

const dbuz = @import("dbuz");
const String = dbuz.types.String;

// ...
    
fn name_owner_changed(name: String, old_owner: String, new_owner: String, _: ?*anyopaque) void {
    std.debug.print("Name owner of \"{s}\" changed: {s} -> {s}\n", .{name.value, old_owner.value, new_owner.value});
}

// pub fn main() !void
// ...

try conn.dbus.NameOwnerChanged.subscribe(&name_owner_changed, null, .Persistent);

// ...

```

