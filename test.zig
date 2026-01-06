const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const wave = @import("wave");

pub fn main() !void {
    var dbg_alloc = std.heap.DebugAllocator(.{}).init;
    defer assert(dbg_alloc.deinit() == .ok);
    const allocator = dbg_alloc.allocator();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const config = try makeConfig(allocator);
    defer freeConfig(config, allocator);

    var server: wave.Server = try .init(config, io, allocator);
    defer server.deinit(io);

    var server_task = try io.concurrent(wave.Server.start, .{ &server, io });
    defer server_task.cancel(io) catch {};

    const port = server.tcp.socket.address.getPort();
    var client_task = try io.concurrent(wave.Client.start, .{ io, port });
    defer client_task.cancel(io) catch {};

    try server_task.await(io);
    try client_task.await(io);
}

fn makeConfig(allocator: Allocator) !wave.Server.Config {
    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    switch (args.len) {
        2 => {
            const server_sync_dir = try allocator.dupe(u8, args[1]);
            return .{ .sync_dir_absolute = server_sync_dir, .port = 0 };
        },
        else => {
            return error.InvalidArguments;
        },
    }
}

fn freeConfig(config: wave.Server.Config, allocator: Allocator) void {
    allocator.free(config.sync_dir_absolute);
}
