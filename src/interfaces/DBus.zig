
const DBus = @This();

const std = @import("std");
const dbuz = @import("../dbuz.zig");

const Method = dbuz.types.Method;
const Property = dbuz.types.Property;
const SignalProxy = dbuz.types.SignalProxy;

const Connection = dbuz.types.Connection;
const Promise = dbuz.types.Promise;

const String = dbuz.types.String;

pub const interface_name = "org.freedesktop.DBus";

pub fn Hello(i: *const DBus) !*Promise(String) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
        .path = "/org/freedesktop/DBus",
    };
    const promise = try i.c.trackResponse(request, String);
    errdefer if (promise.release() == 1) promise.destroy();
    try i.c.sendMessage(&request);
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
pub fn RequestName(i: *const DBus, name: []const u8, flags: RequestNameFlags) !*Promise(RequestNameResponse) {
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

    const promise = try i.c.trackResponse(request, RequestNameResponse);
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
pub fn ReleaseName(i: *const DBus, name: []const u8) !*Promise(ReleaseNameResponse) {
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
    
    const promise = try i.c.trackResponse(request, ReleaseNameResponse);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn ListQueuedOwners(i: *const DBus, name: []const u8) !*Promise([]String) {
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
    
    const promise = try i.c.trackResponse(request, []String);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn ListNames(i: *const DBus) !*Promise([]String) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListNames",
        .path = "/org/freedesktop/DBus",
    };
    
    const promise = try i.c.trackResponse(request, []String);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn ListActivatableNames(i: *const DBus) !*Promise([]String) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListActivatableNames",
        .path = "/org/freedesktop/DBus",
    };
    
    const promise = try i.c.trackResponse(request, []String);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn NameHasOwner(i: *const DBus, name: []const u8) !*Promise(bool) {
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
    
    const promise = try i.c.trackResponse(request, bool);
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
pub fn StartServiceByName(i: *const DBus, name: []const u8, flags: StartServiceByNameFlags) !*Promise(StartServiceByNameResponse) {
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

    const promise = try i.c.trackResponse(request, StartServiceByNameResponse);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;

}

const EnvironmentDict = dbuz.types.Dict(String, String);
pub fn UpdateActivationEnvironment(i: *const DBus, environment: EnvironmentDict) !*Promise(void) {
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

    const promise = try i.c.trackResponse(request, void);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetNameOwner(i: *const DBus, name: []const u8) !*Promise(String) {
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

    const promise = try i.c.trackResponse(request, String);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetConnectionUnixUser(i: *const DBus, name: []const u8) !*Promise(u32) {
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

    const promise = try i.c.trackResponse(request, u32);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetConnectionUnixProcessID(i: *const DBus, name: []const u8) !*Promise(u32) {
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

    const promise = try i.c.trackResponse(request, u32);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

const CredentialsValue = union (enum) {
    uint: u32,
    uint_arr: []u32,
    string: String,
    bytes: []const u8,
    fd: std.fs.File,
};
const Credentials = dbuz.types.Dict(String, CredentialsValue);
pub fn GetConnectionCredentials(i: *const DBus, name: []const u8) !*Promise(Credentials) {
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

    const promise = try i.c.trackResponse(request, Credentials);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn AddMatch(i: *const DBus, rule: []const u8) !*Promise(void) {
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

    const promise = try i.c.trackResponse(request, void);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn RemoveMatch(i: *const DBus, rule: []const u8) !*Promise(void) {
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

    const promise = try i.c.trackResponse(request, void);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

pub fn GetId(i: *const DBus) !*Promise(String) {
    var request = try i.c.startMessage(null);
    defer request.deinit();
    request.type = .method_call;
    request.fields = .{
        .destination = "org.freedesktop.DBus",
        .interface = "org.freedesktop.DBus",
        .member = "GetId",
        .path = "/org/freedesktop/DBus",
    };

    const promise = try i.c.trackResponse(request, String);
    errdefer if (promise.release() == 1) promise.destroy();

    try i.c.sendMessage(&request);
    return promise;
}

c: *Connection,
NameOwnerChanged: SignalProxy(struct { String, String, String }),
NameLost: SignalProxy(struct { String }),
NameAcquired: SignalProxy(struct { String }),
ActivatableServicesChanged: SignalProxy(struct {}),
interface: Interface = .{
    .name = DBus.interface_name,
    .connection = null,
    .refcounter = .init(1),
    .description = "",
    .object_path = null,
    .vtable = &.{
        .method_call = null,
        .property_op = null,
        .signal = &signal,

        .destroy = &destroy,
    }
},

pub fn init(c: *Connection) !DBus {
    return .{
        .c = c,
        .ActivatableServicesChanged = .init(c.default_allocator),
        .NameAcquired = .init(c.default_allocator),
        .NameLost = .init(c.default_allocator),
        .NameOwnerChanged = .init(c.default_allocator),
    };
}

pub fn deinit(i: *DBus) void {
    i.ActivatableServicesChanged.deinit();
    i.NameAcquired.deinit();
    i.NameLost.deinit();
    i.NameOwnerChanged.deinit();
}

fn destroy(_: *dbuz.types.Interface, _: mem.Allocator) void {}

fn signal(i: *Interface, m: *Message, gpa: mem.Allocator) Interface.Error!void {
    const dbus: *DBus = @fieldParentPtr("interface", i);
    return
         if (mem.eql(u8, m.fields.member.?, "NameOwnerChanged")) dbus.NameOwnerChanged.receive(m, gpa) catch error.HandlingFailed
    else if (mem.eql(u8, m.fields.member.?, "NameAcquired")) dbus.NameAcquired.receive(m, gpa) catch error.HandlingFailed
    else if (mem.eql(u8, m.fields.member.?, "NameLost")) dbus.NameLost.receive(m, gpa) catch error.HandlingFailed
    else if (mem.eql(u8, m.fields.member.?, "ActivatableServicesChanged")) dbus.ActivatableServicesChanged.receive(m, gpa) catch error.HandlingFailed;
}

const Interface = dbuz.types.Interface;
const Message = dbuz.types.Message;
const mem = std.mem;
