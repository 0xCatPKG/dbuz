/// This a fake proxy actually. org.freedesktop.Introspectable has no signals nor properties
const Introspectable = @This();

const std = @import("std");
const xml = @import("dishwasher");
const dbuz = @import("../dbuz.zig");

const Connection = dbuz.types.Connection;
const Proxy = dbuz.types.Proxy;
const Promise = dbuz.types.Promise;
const DBusError = dbuz.types.DBusError;
const Message = dbuz.types.Message;

const interface_name = "org.freedesktop.DBus.Introspectable";

const Introspection = xml.Populate(Document);
const IntrospectionError = error {ParsingFailed} || DBusError;

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

const OwnedIntrospection = struct {
    pub const dbus_signature = "s";

    doc: Document,
    arena: std.heap.ArenaAllocator,

    pub fn fromDBus(gpa: std.mem.Allocator, r: *dbuz.codec.Reader) !OwnedIntrospection {
        var res: OwnedIntrospection = undefined;

        const xml_data = try r.read(dbuz.types.String, gpa);
        const offset = if (std.mem.startsWith(u8, xml_data.value, "<!DOCTYPE")) std.mem.indexOfScalar(u8, xml_data.value, '>').? + 1 else 0;

        res.arena = Introspection.fromSlice(gpa, xml_data.value[offset..], &res.doc) catch |err| return switch (err) { error.OutOfMemory => err, else => return error.ParsingFailed};

        return res;
    }

};

pub fn IntrospectRaw(c: *Connection, gpa: std.mem.Allocator, dest: []const u8, path: []const u8) !*Promise(dbuz.types.String, DBusError) {
    var request = try c.startMessage(gpa);
    defer request.deinit();

    request.type = .method_call;
    _ = request.setDestination(dest)
               .setInterface(interface_name)
               .setPath(path)
               .setMember("Introspect");

    const promise = try c.trackResponse(request, dbuz.types.String, DBusError);
    errdefer if (promise.release() == 1) promise.destroy();

    try c.sendMessage(&request);
    return promise;
}

pub fn Introspect(
    c: *Connection,
    gpa: std.mem.Allocator,
    dest: []const u8,
    path: []const u8,
) !*Promise(OwnedIntrospection, IntrospectionError) {
    var request = try c.startMessage(gpa);
    defer request.deinit();

    request.type = .method_call;
    _ = request.setDestination(dest)
               .setInterface(interface_name)
               .setPath(path)
               .setMember("Introspect");

    const promise = try c.trackResponse(request, OwnedIntrospection, IntrospectionError);
    errdefer if (promise.release() == 1) promise.destroy();

    try c.sendMessage(&request);
    return promise;
}
