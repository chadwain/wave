const Server = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Config = struct {
    sync_dir_absolute: []const u8,
    port: u16,
};

sync_dir: Io.Dir,
tcp: Io.net.Server,

pub fn init(config: Config, io: Io, allocator: Allocator) !Server {
    const sync_dir = try Io.Dir.cwd().openDir(io, config.sync_dir_absolute, .{ .iterate = true });
    errdefer sync_dir.close(io);

    var walker = try sync_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        std.debug.print("{s}\n", .{entry.path});
    }

    const addr = try Io.net.IpAddress.parseIp4("127.0.0.1", config.port);
    var tcp_server = try addr.listen(io, .{ .protocol = .tcp, .mode = .stream });
    errdefer tcp_server.deinit(io);

    std.debug.print("TCP Server created at {f}\n", .{tcp_server.socket.address});

    return .{ .sync_dir = sync_dir, .tcp = tcp_server };
}

pub fn deinit(server: *Server, io: Io) void {
    server.sync_dir.close(io);
    server.tcp.deinit(io);
}

pub fn start(server: *Server, io: Io) !void {
    var stream = try server.tcp.accept(io);
    defer stream.close(io);

    var out_buffer: [1024]u8 = undefined;
    var writer = stream.writer(io, &out_buffer);

    var in_buffer: [1024]u8 = undefined;
    var reader = stream.reader(io, &in_buffer);

    try writer.interface.writeAll("Hello from server!\n");
    try writer.interface.flush();

    const line = try reader.interface.takeDelimiter('\n');
    std.debug.print("Server received: {?s}\n", .{line});
}
