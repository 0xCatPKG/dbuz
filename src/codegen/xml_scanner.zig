const std = @import("std");
const xml = @import("xml");

const Io = std.Io;
const fs = std.fs;
const mem = std.mem;
const proc = std.process;

const assert = std.debug.assert;

const gpa = general_purpose_allocator.allocator();
var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    defer assert(general_purpose_allocator.deinit() == .ok);

    var xml_src: ?[]const u8 = null;
    var dest: ?[]const u8 = null;
    var passed_name: ?[]const u8 = null;

    var args = proc.args();
    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-i")) {
            xml_src = args.next() orelse return error.ArgMissing;
        } else if (mem.eql(u8, arg, "-d")) {
            dest = args.next() orelse return error.ArgMissing;
        } else if (mem.eql(u8, arg, "-n")) {
            passed_name = args.next() orelse return error.ArgMissing;
        }

    }

    if (xml_src == null or dest == null or passed_name == null) return error.RequiredArgMissing;
    const xmlfile = try fs.openFileAbsolute(xml_src.?, .{});
    defer xmlfile.close();

    var buffspace: [4096*2]u8 = undefined;

    var rd = xmlfile.reader(&buffspace);
    _ = try rd.interface.discardDelimiterInclusive('\n');

    const owned_doc = try xml.Populate(Document).initFromReader(gpa, &rd.interface);
    defer owned_doc.deinit();


    var proxyfile = Io.Writer.Allocating.init(gpa);
    defer proxyfile.deinit();

    const writer = &proxyfile.writer;

    var native_types = std.ArrayList(struct {[]const u8, []const u8}).empty;
    defer native_types.deinit(gpa);

    const interface = owned_doc.value.node.interface;

    try writer.print(
        \\
        \\const std = @import("std");
        \\const dbuz = @import("dbuz");
        \\
        \\const {s} = @This();
        \\
        \\pub const interface_name = "{s}";
        \\
        \\interface: dbuz.types.Proxy = .{{
        \\    .connection = null,
        \\    .name = interface_name,
        \\    .object_path = null,
        \\    .vtable = &.{{
        \\        .handle_signal = &{s},
        \\        .destroy = &destroy,
        \\    }},
        \\}},
        \\properties: Properties = .{{}},
        \\properties_manager: dbuz.proxies.Properties(Properties, PropertyUnion, PropertyNames) = undefined,
        \\signals: dbuz.types.SignalManager(Signals),
        \\remote: []const u8,
        \\signals_listener_registration_id: usize = undefined,
        \\
        \\
        , .{
            passed_name.?,
            interface.name,
            if (interface.signals.len > 0) "signal_handler" else "dbuz.types.Proxy.noopSignalHandler"
        }
    );

    for (interface.methods) |method| {
        var native_types_annotation: ?mem.SplitIterator(u8, .scalar) = null;
        for (method.annotations) |annotation| {
            if (mem.eql(u8, annotation.name, "com.github.0xCatPKG.DBuz.TypeHint")) native_types_annotation = mem.splitScalar(u8, annotation.value, ',');
        }

        var ins_ended_when: ?usize = null;

        try writer.print("pub fn {s}(p: *{s}, gpa: ?std.mem.Allocator", .{method.name, passed_name.?});
        in_loop: for (method.args, 0..) |arg, i| {
            if (mem.eql(u8, arg.direction, "out")) {
                ins_ended_when = i;
                break :in_loop;
            }

            try writer.print(", @\"{s}\": ", .{arg.name});

            if (native_types_annotation) |*nts| {
                if (nts.next()) |native_type| {
                    try writer.print("{s}", .{ native_type });
                    try native_types.append(gpa, .{ native_type, arg.type });
                    continue :in_loop;
                }
            }

            try writeDBusType(arg.type, writer);
        }

        try writer.print(") !*dbuz.types.Promise(", .{});

        if (ins_ended_when) |idx| {
            if (method.args[idx..].len > 1) try writer.print("struct {{", .{});
            out_loop: for (method.args[idx..]) |arg| {

                if (native_types_annotation) |*nts| {
                    if (nts.next()) |native_type| {
                        try writer.print("{s}", .{ native_type });
                        try native_types.append(gpa, .{ native_type, arg.type });
                        continue :out_loop;
                    }
                }

                try writeDBusType(arg.type, writer);
                if (method.args[idx..].len > 1) try writer.print(", ", .{});
            }
            if (method.args[idx..].len > 1) try writer.print("}}", .{});
        } else try writer.print("void", .{});

        try writer.print(
            \\) {{
            \\    if (p.interface.connection == null) return error.Unbound;
            \\    var request = try p.interface.connection.?.startMessage(gpa);
            \\    defer request.deinit();
            \\    _ = request.setDestination(p.remote)
            \\               .setInterface(interface_name)
            \\               .setPath(p.interface.object_path.?)
            \\               .setMember("{s}")
            , .{
                method.name,
            }
        );
        if (method.args.len == 0 or method.args.len - (if (ins_ended_when) |idx| idx + 1 else 0) == 0) {
            try writer.print("\n               .setSignature(\"", .{});
            for (method.args) |arg| {
                if (mem.eql(u8, arg.direction, "out")) try writer.print("{s}", .{arg.type});
            }
            try writer.print("\")", .{});
        }
        try writer.print(";\n\n", .{});


        if (method.args.len != 0 or method.args.len - (if (ins_ended_when) |idx| idx + 1 else 0) != 0) {
            try writer.print(
                \\    const w = request.writer();
                \\    try w.write(.{{ 
            , .{});
            for (method.args) |arg| {
                if (mem.eql(u8, arg.direction, "in")) try writer.print("@\"{s}\", ", .{arg.name});
            }

            try writer.print("}});\n\n", .{});
        }

        try writer.print(
            \\    const promise = try p.interface.connection.?.trackResponse(request,
            \\          @typeInfo(@typeInfo(@typeInfo( @TypeOf({s}) ).@"fn".return_type.?).error_union.payload).pointer.child.Type);
            \\    errdefer if (promise.release() == 1) promise.destroy();
            \\
            \\    try p.interface.connection.?.sendMessage(&request);
            \\    return promise;
            \\}}
            \\
            \\
            , .{method.name}
        );

    }

    try writer.print(
        \\pub fn destroy(i: *dbuz.types.Proxy, gpa: std.mem.Allocator) void {{
        \\    const p: *{s} = @fieldParentPtr("interface", i);
        \\
        \\    if (!p.properties._inited) return;
        \\    p.properties._mutex.lock();
        \\    defer p.properties._mutex.unlock();
        \\
        \\    const st_info = @typeInfo(Properties).@"struct";
        \\    inline for (st_info.fields) |field| {{
        \\        if (comptime std.mem.startsWith(u8, field.name, "_")) comptime continue;
        \\        dbuz.utils.deinitValue(gpa, @field(p.properties, field.name));
        \\    }}
        \\}}
        \\
        \\
        , .{passed_name.?}
    );

    try writer.print(
        \\pub const Properties = struct {{
        \\    _inited: bool = false,
        \\    _mutex: std.Thread.Mutex = .{{}},
        \\
        , .{}
    );
    for (interface.properties) |property| {
        var native_type: ?[]const u8 = null;
        for (property.annotations) |annotation| {
            if (mem.eql(u8, annotation.name, "com.github.0xCatPKG.DBuz.TypeHint")) native_type = annotation.value;
        }

        try writer.print("    @\"{s}\": ", .{property.name});
        if (native_type) |nt| {
            try writer.print("{s}", .{nt});
            try native_types.append(gpa, .{ nt, property.name });
        } else {
            try writeDBusType(property.type, writer);
        }
        try writer.print(" = undefined,\n", .{});
    }
    try writer.print("}};\n\n", .{});

    try writer.print(
        \\pub const PropertyNames = enum {{
        \\
        , .{}
    );
    for (interface.properties) |property| {
        try writer.print("    @\"{s}\",\n", .{property.name});
    }
    try writer.print("}};\n\n", .{});

    // PropertyUnion
    try writer.print("pub const PropertyUnion = dbuz.types.Variant(&.{{", .{});
    for (interface.properties) |property| {
        var native_type: ?[]const u8 = null;
        for (property.annotations) |annotation| {
            if (mem.eql(u8, annotation.name, "com.github.0xCatPKG.DBuz.TypeHint")) native_type = annotation.value;
        }

        try writer.print("\n    ", .{});
        if (native_type) |nt| {
            try writer.print("{s}", .{nt});
        } else {
            try writeDBusType(property.type, writer);
        }
        try writer.print(", ", .{});
    }
    try writer.print("}});\n\n", .{});

    try writer.print("pub const Signals = struct {{\n", .{});
    for (interface.signals) |signal| {
        var native_types_annotation: ?mem.SplitIterator(u8, .scalar) = null;
        for (signal.annotations) |annotation| {
            if (mem.eql(u8, annotation.name, "com.github.0xCatPKG.DBuz.TypeHint")) native_types_annotation = mem.splitScalar(u8, annotation.value, ',');
        }
        try writer.print("    pub const @\"{s}\" = dbuz.types.Signal(struct {{ ", .{signal.name});
        arg_loop: for (signal.args) |arg| {
            if (native_types_annotation) |*nts| {
                if (nts.next()) |native_type| {
                    try writer.print("{s}", .{ native_type });
                    try native_types.append(gpa, .{ native_type, arg.type });
                    continue :arg_loop;
                }
            }

            try writeDBusType(arg.type, writer);
            try writer.print(", ", .{});
        }
        try writer.print("}}, .{{}});\n", .{});
    }

    try writer.print("}};\n\n", .{});
    try writer.print(
        \\pub fn bind(
        \\    p: *{s},
        \\    gpa: std.mem.Allocator,
        \\    c: *dbuz.types.Connection,
        \\    remote: []const u8,
        \\    object_path: []const u8,
        \\    listener: @FieldType({s}, "signals").Listener
        \\) !void {{
        \\    p.interface.connection = c;
        \\    p.interface.object_path = object_path;
        \\    try p.properties_manager.bind(c, remote, interface_name, object_path, &p.properties, gpa);
        \\    p.remote = remote;
        \\
        \\    const lp = try c.registerListenerAsync(
        \\        p,
        \\        .{{
        \\            .interface = interface_name,
        \\            .path = object_path,
        \\            .sender = remote,
        \\        }},
        \\        &p.signals_listener_registration_id,
        \\        gpa
        \\    );
        \\    defer if (lp.release() == 1) lp.deinit();
        \\    p.signals.init(listener);
        \\}}
        \\
        \\fn signal_handler(i: *dbuz.types.Proxy, m: *dbuz.types.Message, gpa: std.mem.Allocator) error{{OutOfMemory,HandlingFailed}}!void {{
        \\    const p: *{s} = @fieldParentPtr("interface", i);
        \\    return p.signals.handle(m, gpa) catch error.HandlingFailed;
        \\}}
        \\
        \\
        , .{passed_name.?, passed_name.?, passed_name.?});

    const outfile = try fs.createFileAbsolute(dest.?, .{});
    defer outfile.close();

    var outwriter = outfile.writer(&.{});
    const ow = &outwriter.interface;

    try ow.writeAll(proxyfile.written());
}

fn writeDBusType(signature: []const u8, writer: *Io.Writer) !void {
    var struct_depth: usize = 0;
    var struct_depth_stack: [64]usize = undefined;
    var struct_depth_stack_pointer: i8 = -1;
    for (signature, 0..) |letter, j| {
        if (
            struct_depth > 0
            and letter != '{'
            and letter != '}'
            and letter != ')'
        ) try writer.print("field{}: ", .{j});
        switch (letter) {
            'y' => try writer.print("u8", .{}),
            'b' => try writer.print("bool", .{}),
            'n' => try writer.print("i16", .{}),
            'q' => try writer.print("u16", .{}),
            'i' => try writer.print("i32", .{}),
            'u' => try writer.print("u32", .{}),
            'x' => try writer.print("i64", .{}),
            't' => try writer.print("u64", .{}),

            'd' => try writer.print("f64", .{}),
            'h' => try writer.print("std.fs.File", .{}),
            's' => try writer.print("dbuz.types.String", .{}),
            'o' => try writer.print("dbuz.types.ObjectPath", .{}),
            'g' => try writer.print("dbuz.types.Signature", .{}),
            'a' => {
                if (signature[j + 1] == '{') continue;
                try writer.print("[]", .{});
            },
            '(' => {
                try writer.print("struct {{", .{});
                struct_depth += 1;
                continue;
            },
            ')' => {
                try writer.print("}}", .{});
                struct_depth -= 1;
                continue;
            },
            '{' => {
                try writer.print("dbuz.types.Dict(", .{});
                struct_depth_stack_pointer += 1;
                const idx = @as(u8, @bitCast(struct_depth_stack_pointer));
                struct_depth_stack[idx] = struct_depth;
                struct_depth = 0;
                continue;
            },
            '}' => {
                try writer.print(")", .{});
                assert(struct_depth == 0);
                assert(struct_depth_stack_pointer >= 0);
                const idx = @as(u8, @bitCast(struct_depth_stack_pointer));
                struct_depth = struct_depth_stack[idx];
                struct_depth_stack_pointer -= 1;
                continue;
            },
            'v' => try writer.print("dbuz.types.DefaultVariant", .{}),
            else => @panic("Unexpected type letter."),
        }
        if ((struct_depth != 0 or (struct_depth_stack_pointer != -1 and signature[j+1] != '}') and letter != '{' and letter != '(')) try writer.print(", ", .{});
    }
}

// const Property = struct {
//     type: []const u8,
//     signature: []const u8,
//     native_types: []const []const u8,
// };
//
// const Method = struct {
//     params_names: []const []const u8,
//     param_signatures: []const []const u8,
//     param_native_types: []const []const u8,
//     return_signature: []const u8,
//     return_type: []const u8,
//     is_noreply: bool,
// };
//
// const Signal = struct {
//
// };

const Interface = struct {
    pub const xml_shape = .{
        .name = .{ .attribute, "name" },
        .methods = .{ .elements, "method", .{
            .name = .{ .attribute, "name" },
            .args = .{ .elements, "arg", .{
                .name = .{ .attribute, "name" },
                .type = .{ .attribute, "type" },
                .direction = .{ .attribute, "direction" },
            } },
            .annotations = .{ .elements, "annotation", .{
                .name = .{ .attribute, "name" },
                .value = .{ .attribute, "value" },
            } },
        } },
        .signals = .{ .elements, "signal", .{
            .name = .{ .attribute, "name" },
            .args = .{ .elements, "arg", .{
                .name = .{ .attribute, "name" },
                .type = .{ .attribute, "type" },
            } },
            .annotations = .{ .elements, "annotation", .{
                .name = .{ .attribute, "name" },
                .value = .{ .attribute, "value" },
            } },
        } },
        .properties = .{ .elements, "property", .{ 
            .name = .{ .attribute, "name" },
            .type = .{ .attribute, "type" },
            .access = .{ .attribute, "access" },
            .annotations = .{ .elements, "annotation", .{
                .name = .{ .attribute, "name" },
                .value = .{ .attribute, "value" }
            } },
        } },
    };

    name: []const u8,
    methods: []struct {
        name: []const u8,
        args: []struct {
            name: []const u8,
            type: []const u8,
            direction: []const u8,
        },
        annotations: []Annotation,
    },
    signals: []struct {
        name: []const u8,
        args: []struct {
            name: []const u8,
            type: []const u8,
        },
        annotations: []Annotation,
    },
    properties: []struct {
        name: []const u8,
        type: []const u8,
        access: []const u8,
        annotations: []Annotation,
    },
};

const Annotation = struct {
    name: []const u8,
    value: []const u8,
};

const Document = struct {
    pub const xml_shape = .{
        .node = .{ .element, "node", .{
            .interface = .{ .element, "interface", Interface },
        } },
    };
    node: struct { interface: Interface, },
};
