
/// Represents MatchRule that can be used to filter out DBus messages. In real usecase is prerequisite for receiving remote's signals
const MatchRule = @This();

const std = @import("std");
const mem = std.mem;
const Io = std.Io;

const trie = @import("../tree.zig");
const dbuz = @import("../dbuz.zig");

const Message = dbuz.types.Message;

member: ?[]const u8 = null,
interface: ?[]const u8 = null,
sender: ?[]const u8 = null,
destination: ?[]const u8 = null,
type: Message.Type = .signal,
path: ?[]const u8 = null,
path_namespace: ?[]const u8 = null,

/// Build rule string from current MatchRule passable to AddMatch and RemoveMatch DBus calls. Caller owns memory.
pub fn string(m: *const MatchRule, gpa: mem.Allocator) ![]const u8 {
    var aw = Io.Writer.Allocating.init(gpa);
    const w = &aw.writer;

    defer aw.deinit();

    try w.print("type='{s}'", .{@tagName(m.type)});
    if (m.interface)   |interface| try w.print(",interface='{s}'", .{interface});
    if (m.member)      |member| try w.print(",member='{s}'", .{member});
    if (m.sender)      |sender| try w.print(",sender='{s}'", .{sender});
    if (m.destination) |destination| try w.print(",destination='{s}'", .{destination});
    if (m.path)        |path| try w.print(",path='{s}'", .{path});

    if (m.path_namespace) |path_ns| try w.print(",path_namespace='{s}'", .{path_ns});

    return try aw.toOwnedSlice();
}

/// Checks if passed message matches the current rule.
pub fn match(r: *const MatchRule, m: *const Message) bool {
    if (m.type != r.type) return false;
    if (r.member) |member| if (!mem.eql(u8, member, m.fields.member orelse return false)) return false;
    if (r.interface) |interface| if (!mem.eql(u8, interface, m.fields.interface orelse return false)) return false;
    if (r.sender) |sender| if (!mem.eql(u8, sender, m.fields.sender orelse return false)) return false;
    if (r.destination) |dest| if (!mem.eql(u8, dest, m.fields.destination orelse return false)) return false;
    if (r.path) |path| if (!mem.eql(u8, path, m.fields.path orelse return false)) return false;

    if (r.path_namespace) |path_ns| {
        var scratchbuf: [4096]u8 = undefined;
        var sballoc = std.heap.FixedBufferAllocator.init(&scratchbuf);

        const namespace = trie.runtimeKey(path_ns, sballoc.allocator()) catch unreachable;
        const path = trie.runtimeKey(m.fields.path orelse return false, sballoc.allocator()) catch return false;
        if (namespace.len > path.len) return false;

        for (namespace, 0..) |part, i| {
            if (!mem.eql(u8, part, path[i])) return false;
        } 
    }

    return true;
}

/// Checks if current rule is subset of another rule. idk where it is useful, but anyways.
pub fn isSubsetOf(r: *const MatchRule, other: MatchRule) bool {
    if (r.type != other.type) return false;
    if (other.member) |member| if (!mem.eql(u8, member, r.member orelse return false)) return false;
    if (other.interface) |interface| if (!mem.eql(u8, interface, r.interface orelse return false)) return false;
    if (other.sender) |sender| if (!mem.eql(u8, sender, r.sender orelse return false)) return false;
    if (other.destination) |dest| if (!mem.eql(u8, dest, r.destination orelse return false)) return false;
    if (other.path) |path| if (!mem.eql(u8, path, r.path orelse return false)) return false;

    if (other.path_namespace) |path_ns| {
        var scratchbuf: [4096]u8 = undefined;
        var sballoc = std.heap.FixedBufferAllocator.init(&scratchbuf);

        const namespace = trie.runtimeKey(path_ns, sballoc.allocator()) catch unreachable;
        const own_namespace = trie.runtimeKey(r.path_namespace orelse return false, sballoc.allocator()) catch return false;
        if (namespace.len > own_namespace.len) return false;

        for (namespace, 0..) |part, i| {
            if (!mem.eql(u8, part, own_namespace[i])) return false;
        }

    }

    return true;
}
