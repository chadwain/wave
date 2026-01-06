const Client = @This();

const std = @import("std");
const Io = std.Io;

pub fn start(io: Io, port: u16) !void {
    const addr = try Io.net.IpAddress.parse("127.0.0.1", port);
    std.debug.print("Client connecting to {f}\n", .{addr});
    var stream = try addr.connect(io, .{ .protocol = .tcp, .mode = .stream });
    defer stream.close(io);

    var out_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &out_buffer);

    var in_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &in_buffer);

    try writer.interface.writeAll("Hello from client!\n");
    try writer.interface.flush();

    const line = try reader.interface.takeDelimiter('\n');
    std.debug.print("Client received: {?s}\n", .{line});
}
