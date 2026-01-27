const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const wave = @import("wave");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try Args.init(init.minimal.args, init.arena);

    const sync_dir_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, args.syncDir());
    defer allocator.free(sync_dir_wtf16);

    var db = try wave.windows.Database.init(.wtf16ZCast(sync_dir_wtf16), allocator);
    defer db.deinit();

    var watch_task = try io.concurrent(wave.windows.watch, .{ db.sync_dir, io });
    defer watch_task.cancel(io) catch {};

    var client_in = Io.Reader.fixed(&.{});
    var client_out = Io.Writer.Allocating.init(allocator);
    defer client_out.deinit();
    var client = wave.windows.Client.init(&db, allocator);
    defer client.deinit();
    try client.start(io, &client_in, &client_out.writer);
    defer client.stop(io);

    var stdin_buffer: [64]u8 = undefined;
    var stdin = Io.File.stdin().reader(io, &stdin_buffer);
    const reader = &stdin.interface;

    var stdout = Io.File.stdout().writer(io, &.{});
    std.debug.print("s - scan, a - print all files, n - print files needing sync, q - quit\n", .{});
    while (true) {
        var line: []const u8 = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.ReadFailed, error.EndOfStream => |e| return e,
            error.StreamTooLong => {
                _ = try reader.discardDelimiterInclusive('\n');
                continue;
            },
        };
        reader.toss(1);
        line = std.mem.trimEnd(u8, line, "\r");
        if (line.len != 1) continue;
        switch (line[0]) {
            'a' => {
                try db.debug.printKnownFiles(&stdout.interface);
                try stdout.interface.flush();
            },
            'n' => {
                try db.debug.printFilesNeedingSync(&stdout.interface);
                try stdout.interface.flush();
            },
            's' => {
                try wave.windows.completeScan(&db, allocator);
                try stdout.interface.writeAll("scan complete\n");
                try stdout.interface.flush();
            },
            '0'...'9' => |c| {
                const index = c - '0';
                try db.debug.clientTransferFile(io, &client, index);
            },
            'w' => {
                std.debug.print("{x}\n", .{client_out.written()});
            },
            'q' => break,
            else => continue,
        }
    }
}

const Args = struct {
    slice: []const [:0]const u8,

    fn init(args: std.process.Args, arena: *std.heap.ArenaAllocator) !Args {
        const slice = try args.toSlice(arena.allocator());

        switch (slice.len) {
            2 => return .{ .slice = slice },
            else => return error.InvalidArguments,
        }
    }

    fn syncDir(args: Args) []const u8 {
        return args.slice[1];
    }
};

fn startServer(io: Io, addr_queue: *Io.Queue(Io.net.IpAddress)) !void {
    const addr = Io.net.IpAddress.parseIp4("127.0.0.1", 0) catch unreachable;
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    try addr_queue.putAll(io, &.{server.socket.address});
    const stream = try server.accept(io);
    defer stream.close(io);

    var read_buffer: [64]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    var futures = try wave.Server.start(io, &reader.interface, &writer.interface);
    defer {
        futures.send.cancel(io) catch {};
        futures.receive.cancel(io) catch {};
    }
    _ = try io.select(.{
        .send = &futures.send,
        .receive = &futures.receive,
    });
}

fn startClient(io: Io, addr_queue: *Io.Queue(Io.net.IpAddress)) !void {
    const addr = try addr_queue.getOne(io);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var read_buffer: [64]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    var futures = try wave.Client.start(io, &reader.interface, &writer.interface);
    defer {
        futures.send.cancel(io) catch {};
        futures.receive.cancel(io) catch {};
    }
    _ = try io.select(.{
        .send = &futures.send,
        .receive = &futures.receive,
    });
}
