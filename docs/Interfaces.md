# Interfaces in dbuz

When I first looked at zig, it interested me with its comptime capabilities. Then, when I started to creating this library, I realized I can use compile time reflection in zig to simplify the implementation of interfaces. So how interfaces work in dbuz?

## Interface definition rules.

`Interface` in dbuz is a any struct (from now on can be referred as InterfacePrototype), that follows a set of rules. One strict rule is that it must have a proper init function, with following signature:
```zig
fn (*anyopaque, std.mem.Allocator) anyerror!@This()
```

First argument is a pointer to any data that user wants to pass to the interface. Second is a allocator that will be used by that interface. It can return any error, but must return @This() as return value.

Then there can be **optionally** deinit method. It takes *@This() as argument and not returns anything. It will be called on interface destruction.

### **Defining methods**

Then, usually we want to make our interface somewhat usable. Let's say we want to implement a dbus method on that interface. How we can do that?

Method definition in dbuz follows following rules: This should be a member function, name of which starts with "method@" and then name after that prefix is follows DBus member naming rules.

Method should take at least one argument: `*@This()`. It may return any error (error name will be converted to ERROR message and sent to caller), and any value that is DBus serializable. Optionally last parameter can be `*DBusMessage` which will be original message struct that contains that method call.

For example, lets define following method:
```zig
pub fn @"method@testmethod"(self: *@This(), some_string: DBusString, some_int: i32, some_struct: struct{field: u32, field_bytearray: []const u8}) anyerror!f32 {
    ...
}
```

What dbuz will do with that method?
1. It will guess it's signature: in that case it will be `in:"si(uay)"` and `out:"d"`
2. It will extract it's name: `testmethod`
3. DBusInterface.init will generate code at comptime that handles that method, that checks if member of message is matching `testmethod`, and then:
    - It will read struct{DBusString, i32, struct{field: u32, field_bytearray: []const u8}} from message using `message.read()` method
    - It will execute @"method@testmethod" with pointer to Interface prototype, arguments read from message
    - It will reply with `conn.reply` with result of method execution
    - it will reply with `conn.replyError` error name generated from error and description that is "" or any string that returned from `InterfacePrototype.descError`

Why method names are prefixed with "method@"? Zig doesn't provide any ways to mark methods with custom annotations, so i invented my own way to do that.

Also note that all arguments that called during method execution, that is require some sort of heap allocation is owned by connection and will be invalidates immediately after method execution (thanks to std.heap.ArenaAllocator for simplifying memory management), so if you need to keep them, you should copy them during method execution.

### *DBusMessage argument
You may optionally pass `*DBusMessage` as last argument to method, that will be original message struct that contains that method call. Note that message read position will be modified by every argument read for method signature params. Usually this should be used only for getting access to some things that are usually handled automatically, like message serials, senders, etc.

### The magic of InterfacePrototype.errorDesc method
Interface may declare fn errorDesc(anyerror) []const u8 method. It will be called when any method returns any error, it will be passed as error description to body of error message. All memory returned from this method is owned by user.

## **Properties**
Interface may publish properties on interface. All communication is made using org.freedesktop.DBusProperties interface that is automatically attached to connection on `dbuz.connect` method.

On user's side, properties are just member functions that now are prefixed by "property@".
Properties cannot be write-only (i was lazy, feel free to contribute), only read-only, or read-write.

Read-only properties has following prototype:
```zig
pub fn @"property@name"(self: *@This) DBusProperties.Error!T { ... }
```

Where T is dbus serializable zig type. DBusProperties.Error! may be ommited.

Read-write properties has following prototype:
```zig
pub fn @"property@name"(self: *@This, value: ?T) DBusProperties.Error!T { ... }
```

Where T is dbus serializable zig type. DBusProperties.Error! may be ommited.
Unwrapped type of value and return type must be the same. Calls to property function with second argument set to null should be treated as read operations, otherwise they should be treated as write operations and return value is ignored. All data returned from property function is owned by user. All data passed to property function is owned by connection and immediately invalidated on return. All data that requires ownership should be copied by user code inside property function.

org.freedesktop.DBusProperties.GetAll is implemented as calls to each property function in read mode.

## **Introspection**

dbuz provides a comptime introspection support, so it will introspect all methods, properties and signals of interface. As zig doesn't store method param names, method args will not have any meaningful names.

### Signals in introspection

As signals are handled by MatchGroup interface, they are not described in that file, however for introspection purposes, they still can be described in interface prototype struct.

Simple signal definition looks like that:
```zig
pub fn @"signal@name"(name: T1, other: T2) void {}
```
As method is never called, it can skip *@This() argument. It should always return void, and all arguments should have types that are serializable by DBus.


### Custom instrospection XML

DBusInterface struct contains setIntrospection([]const u8) for that purpose.

## **Publishing interface**

Publishing interface is done by calling registerInterface() on DBusConnection or DBusName struct. Only difference is order in which interfaces are searched and that DBusConnection supports "*" path to publish interface on all paths.

DBusInterface struct returned by that function are owned by connection and reference counted.
DBusInterface.destroy() is used to unregister interface and at the same time to release reference from user side.

See methods for more information
