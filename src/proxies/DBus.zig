
const DBus = @This();

const std = @import("std");
const dbuz = @import("../dbuz.zig");

const Method = dbuz.types.Method;
const Property = dbuz.types.Property;
const Signal = dbuz.types.Signal;
const SignalManager = dbuz.types.SignalManager;

const Proxy = dbuz.types.Proxy;

const Connection = dbuz.types.Connection;
const Promise = dbuz.types.Promise;

const String = dbuz.types.String;

const DBusError = dbuz.types.DBusError;
const SpawnError = error {
    ExecFailed,
    ForkFailed,
    ChildExited,
    ChildSignaled,
    FailedToSetup,
    ConfigInvalid,
    ServiceNotValid,
    ServiceNotFound,
    PermissionsInvalid,
    FileInvalid,
} || DBusError;

pub const interface_name = "org.freedesktop.DBus";

pub fn Hello(c: *Connection) !*Promise(String, DBusError) {
    var request = try c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
        .path = "/org/freedesktop/DBus",
    };
    const promise = try c.trackResponse(request, String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();
    try c.sendMessage(&request);
    return promise;
}

const RequestNameFlags = struct {
    allow_replacement: bool = false,
    replace: bool = false,
    do_not_queue: bool = true,

    pub fn toInteger(s: *const @This()) u32 {
        var val: u32 = 0;
        if (s.allow_replacement) val |= 0x01;
        if (s.replace) val |= 0x02;
        if (s.do_not_queue) val |= 0x04;
        return val;
    }
};
const RequestNameResponse = enum (u32) {
    primary_owner = 1,
    in_queue = 2,
    exists = 3,
    already_owned = 4,
    _
};
pub fn RequestName(i: *const DBus, name: []const u8, flags: RequestNameFlags) !*Promise(RequestNameResponse, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "RequestName",
        .path = "/org/freedesktop/DBus",
        .signature = "su",
    };


    const w = request.writer();
    try w.write(.{String{.value = name}, flags.toInteger()});

    const promise = try i.c.trackResponse(request, RequestNameResponse, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

const ReleaseNameResponse = enum (u32) {
    released = 1,
    non_existent = 2,
    not_owner = 3,
    _
};
pub fn ReleaseName(i: *const DBus, name: []const u8) !*Promise(ReleaseNameResponse, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ReleaseName",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };

    const w = request.writer();
    try w.write(String{.value = name});
    
    const promise = try i.c.trackResponse(request, ReleaseNameResponse, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn ListQueuedOwners(i: *const DBus, name: []const u8) !*Promise([]String, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListQueuedOwners",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };

    const w = request.writer();
    try w.write(String{.value = name});
    
    const promise = try i.c.trackResponse(request, []String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn ListNames(i: *const DBus) !*Promise([]String, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListNames",
        .path = "/org/freedesktop/DBus",
    };
    
    const promise = try i.c.trackResponse(request, []String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn ListActivatableNames(i: *const DBus) !*Promise([]String, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListActivatableNames",
        .path = "/org/freedesktop/DBus",
    };
    
    const promise = try i.c.trackResponse(request, []String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn NameHasOwner(i: *const DBus, name: []const u8) !*Promise(bool, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "NameHasOwner",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };

    const w = request.writer();
    try w.write(String{.value = name});
    
    const promise = try i.c.trackResponse(request, bool, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

const StartServiceByNameFlags = struct {
    pub fn toInteger(_: *const @This()) u32 { return 0; }
};
const StartServiceByNameResponse = enum (u32) {
    success = 1,
    already_running = 2,
    _
};
pub fn StartServiceByName(i: *const DBus, name: []const u8, flags: StartServiceByNameFlags) !*Promise(StartServiceByNameResponse, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "StartServiceByName",
        .path = "/org/freedesktop/DBus",
        .signature = "su",
    };


    const w = request.writer();
    try w.write(.{String{.value = name}, flags.toInteger()});

    const promise = try i.c.trackResponse(request, StartServiceByNameResponse, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;

}

const EnvironmentDict = dbuz.types.Dict(String, String);
pub fn UpdateActivationEnvironment(i: *const DBus, environment: EnvironmentDict) !*Promise(void, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "UpdateActivationEnvironment",
        .path = "/org/freedesktop/DBus",
        .signature = "a{ss}",
    };


    const w = request.writer();
    try w.write(environment);

    const promise = try i.c.trackResponse(request, void, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetNameOwner(i: *const DBus, name: []const u8) !*Promise(String, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "GetNameOwner",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };


    const w = request.writer();
    try w.write(String{.value = name});

    const promise = try i.c.trackResponse(request, String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetConnectionUnixUser(i: *const DBus, name: []const u8) !*Promise(u32, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "GetConnectionUnixUser",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };


    const w = request.writer();
    try w.write(String{.value = name});

    const promise = try i.c.trackResponse(request, u32, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetConnectionUnixProcessID(i: *const DBus, name: []const u8) !*Promise(u32, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "GetConnectionUnixProcessID",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };


    const w = request.writer();
    try w.write(String{.value = name});

    const promise = try i.c.trackResponse(request, u32, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

const CredentialsValue = union (enum) {
    u: u32,
    au: []u32,
    s: String,
    ay: []const u8,
    h: std.fs.File,
};
const Credentials = dbuz.types.Dict(String, CredentialsValue);
pub fn GetConnectionCredentials(i: *const DBus, name: []const u8) !*Promise(Credentials, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "GetConnectionCredentials",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };


    const w = request.writer();
    try w.write(String{.value = name});

    const promise = try i.c.trackResponse(request, Credentials, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn AddMatch(i: *const DBus, rule: []const u8) !*Promise(void, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "AddMatch",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };


    const w = request.writer();
    try w.write(String{.value = rule});

    const promise = try i.c.trackResponse(request, void, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn RemoveMatch(i: *const DBus, rule: []const u8) !*Promise(void, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "RemoveMatch",
        .path = "/org/freedesktop/DBus",
        .signature = "s",
    };


    const w = request.writer();
    try w.write(String{.value = rule});

    const promise = try i.c.trackResponse(request, void, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetId(i: *const DBus) !*Promise(String, DBusError) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "GetId",
        .path = "/org/freedesktop/DBus",
    };

    const promise = try i.c.trackResponse(request, String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub const Signals = struct {
    pub const NameOwnerChanged = Signal(struct { String, String, String }, .{});
    pub const NameLost = Signal(struct { String }, .{});
    pub const NameAcquired = Signal(struct { String }, .{});
    pub const ActivatableServicesChanged = Signal(struct {}, .{});
};

c: *Connection,
interface: Proxy = .{
    .name = DBus.interface_name,
    .connection = null,
    .refcounter = .init(1),
    .object_path = "/org/freedesktop/DBus",
    .vtable = &.{
        .handle_signal = &signal,
        .destroy = &Proxy.noopDestroy,
    }
},
signals: SignalManager(Signals),

fn signal(i: *Proxy, m: *Message, gpa: mem.Allocator) Proxy.Error!void {
    const dbus: *DBus = @fieldParentPtr("interface", i);
    return dbus.signals.handle(m, gpa) catch error.HandlingFailed;
}

pub fn bind(c: *Connection, listener: SignalManager(Signals).Listener) DBus {
    return .{
        .c = c,
        .signals = .init(listener)
    };
}

const Message = dbuz.types.Message;
const mem = std.mem;
