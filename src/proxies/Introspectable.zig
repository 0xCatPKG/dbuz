/// This a fake proxy actually. org.freedesktop.Introspectable has no signals nor properties
const Introspectable = @This();

const std = @import("std");
const xml = @import("dishwasher");
const dbuz = @import("../dbuz.zig");

const Connection = dbuz.types.Connection;
const Proxy = dbuz.types.Proxy;
const Promise = dbuz.types.Promise;
const PromiseError = dbuz.types.PromiseError;
const Message = dbuz.types.Message;

const interface_name = "org.freedesktop.DBus.Introspectable";

const Introspection = xml.Populate(Document);
const OwnedIntrospection = Introspection.OwnedDocument;

pub const Node = struct {
    pub const xml_shape = .{
        .name = .{ .maybe, .{ .attribute, "name" } },
        .subnodes = .{ .elements, "node", Node },
        .interfaces = .{ .elements, "interface", Interface },
    };

    name: ?[]const u8,
    subnodes: []Node,
    interfaces: []Interface,

    pub fn implementsInterface(node: *const Node, name: []const u8) bool {
        for (node.interfaces) |iface| {
            if (std.mem.eql(u8, iface.name, name)) return true;
        }
        return false;
    }

};

pub const Method = struct {
    pub const xml_shape = .{
        .name = .{ .attribute, "name" },
        .args = .{ .elements, "arg", .{
            .name = .{ .attribute, "name" },
            .type = .{ .attribute, "type" },
            .direction = .{ .attribute, "direction" },
        } },
        .annotations = .{ .elements, "annotation", Annotation },
    };

    name: []const u8,
    args: []struct {
        name: []const u8,
        type: []const u8,
        direction: []const u8,
    },
    annotations: []Annotation,
};

pub const Signal = struct {
    pub const xml_shape = .{
        .name = .{ .attribute, "name" },
        .args = .{ .elements, "arg", .{
            .name = .{ .attribute, "name" },
            .type = .{ .attribute, "type" },
        } },
        .annotations = .{ .elements, "annotation", Annotation },
    };

    name: []const u8,
    args: []struct {
        name: []const u8,
        type: []const u8,
    },
    annotations: []Annotation,
};

pub const Property = struct {
    pub const xml_shape = .{
        .name = .{ .attribute, "name" },
        .type = .{ .attribute, "type" },
        .access = .{ .attribute, "access" },
        .annotations = .{ .elements, "annotation", Annotation },
    };

    name: []const u8,
    type: []const u8,
    access: []const u8,
    annotations: []Annotation,
};

const Interface = struct {
    pub const xml_shape = .{
        .name = .{ .attribute, "name" },
        .methods = .{ .elements, "method", Method },
        .signals = .{ .elements, "signal", Signal },
        .properties = .{ .elements, "property", Property },
    };

    name: []const u8,
    methods: []Method,
    signals: []Signal,
    properties: []Property,
};

const Annotation = struct {
    pub const xml_shape = .{
        .name = .{ .attribute, "name" },
        .value = .{ .attribute, "value" }
    };

    name: []const u8,
    value: []const u8,
};

const Document = struct {
    pub const xml_shape = .{
        .node = .{ .element, "node", Node },
    };

    node: Node,
};

pub fn IntrospectRaw(c: *Connection, gpa: std.mem.Allocator, dest: []const u8, path: []const u8) !*Promise(dbuz.types.String) {
    var request = try c.startMessage(gpa);
    defer request.deinit();

    request.type = .method_call;
    _ = request.setDestination(dest)
               .setInterface(interface_name)
               .setPath(path)
               .setMember("Introspect");

    const promise = try c.trackResponse(request, dbuz.types.String);
    errdefer if (promise.release() == 1) promise.destroy();

    try c.sendMessage(&request);
    return promise;
}

/// Sends introspection request to the remote peer, returns promise used for internal tracking.
/// User must provide callbacks that will receive error union with results of introspection.
const CallbackData = struct {
    pub const Error = error{ParsingFailed} || PromiseError.Error;
    callback: *const fn (result: Error!OwnedIntrospection, userdata: ?*anyopaque) void,
    userdata: ?*anyopaque,
    gpa: std.mem.Allocator,
};
pub fn IntrospectAsync(
    c: *Connection,
    gpa: std.mem.Allocator,
    dest: []const u8,
    path: []const u8,
    callback: *const fn (result: CallbackData.Error!OwnedIntrospection, userdata: ?*anyopaque) void,
    userdata: ?*anyopaque
) !*Promise(dbuz.types.String) {
    const promise = try IntrospectRaw(c, gpa, dest, path);
    errdefer if (promise.release() == 1) promise.destroy();

    const cbd = try gpa.create(CallbackData);
    cbd.* = .{
        .callback = callback,
        .userdata = userdata,
        .gpa = gpa,
    };
    
    promise.setupCallbacks(.{
        .timeout = null,

        .response = &introspectionResponse,
        .@"error" = &introspectionError,
    },cbd);

    return promise;
}

fn introspectionResponse(
    _: *Promise(dbuz.types.String),
    xml_data: dbuz.types.String,
    arena: *std.heap.ArenaAllocator,
    userdata: ?*anyopaque
) void {
    const cbd_ptr: *CallbackData = @alignCast(@ptrCast(userdata));
    const cbd = cbd_ptr.*;
    cbd.gpa.destroy(cbd_ptr);

    const offset = if (std.mem.startsWith(u8, xml_data.value, "<!DOCTYPE")) std.mem.indexOfScalar(u8, xml_data.value, '>').? + 1 else 0;

    const owned_doc = Introspection.initFromSlice(arena.allocator(), xml_data.value[offset..]) catch {
        cbd.callback(CallbackData.Error.ParsingFailed, cbd.userdata);
        return;
    };
    defer owned_doc.deinit();
    cbd.callback(owned_doc, cbd.userdata); 
}

fn introspectionError(_: *Promise(dbuz.types.String), err: PromiseError, userdata: ?*anyopaque) void {
    const cbd_ptr: *CallbackData = @alignCast(@ptrCast(userdata));
    const cbd = cbd_ptr.*;
    cbd.gpa.destroy(cbd_ptr);

    cbd.callback(err.error_code, cbd.userdata);
}

pub fn Introspect(
    c: *Connection,
    gpa: std.mem.Allocator,
    dest: []const u8,
    path: []const u8,
) !OwnedIntrospection {
    const promise = try IntrospectRaw(c, gpa, dest, path);
    defer if (promise.release() == 1) promise.destroy();

    const value, _ = try promise.wait(null);
    switch (value) {
        .@"error" => |err| return err.error_code,
        .response => |val| {
            const offset = if (std.mem.startsWith(u8, val.value, "<!DOCTYPE")) std.mem.indexOfScalar(u8, val.value, '>').? + 1 else 0;
            return Introspection.initFromSlice(gpa, val.value[offset..]);
        },
    }
}
