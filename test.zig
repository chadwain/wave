const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const wave = @import("wave");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try Args.init(init.minimal.args, init.arena);

    const sync_dir = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, args.syncDir());
    defer allocator.free(sync_dir);

    var db = try wave.windows.Database.init(.wtf16ZCast(sync_dir), io, args.syncDir(), allocator);
    defer db.deinit(io);

    // var watch_task = try io.concurrent(wave.windows.watch, .{ db.sync_dir, io });
    // defer watch_task.cancel(io) catch {};

    const peer_sync_dir = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, args.peerSyncDir());
    defer allocator.free(peer_sync_dir);

    var tx_queue_buffer: [1]wave.windows.Host.Transaction.Data = undefined;
    var tx_queue: wave.windows.Host.TxQueue = .init(&tx_queue_buffer);
    defer tx_queue.close(io);

    var host_pair_task = try io.concurrent(
        startHostPair,
        .{ io, &db, .wtf16ZCast(peer_sync_dir), args.peerSyncDir(), &tx_queue },
    );
    defer host_pair_task.cancel(io) catch {};

    try runCli(io, &db, &tx_queue, allocator);
}

fn runCli(io: Io, db: *wave.windows.Database, tx_queue: *wave.windows.Host.TxQueue, allocator: Allocator) !void {
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
                try db.mutex.lock(io);
                defer db.mutex.unlock(io);
                try db.debug.printKnownFiles(&stdout.interface);
                try stdout.interface.flush();
            },
            'n' => {
                try db.mutex.lock(io);
                defer db.mutex.unlock(io);
                try db.debug.printFilesNeedingSync(&stdout.interface);
                try stdout.interface.flush();
            },
            's' => {
                try wave.windows.completeScan(db, io, allocator);
                try stdout.interface.writeAll("scan complete\n");
                try stdout.interface.flush();
            },
            '0'...'9' => |c| {
                const index = c - '0';
                try db.mutex.lock(io);
                defer db.mutex.unlock(io);
                try db.debug.hostTransferFile(index, io, tx_queue);
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
            3 => return .{ .slice = slice },
            else => return error.InvalidArguments,
        }
    }

    fn syncDir(args: Args) []const u8 {
        return args.slice[1];
    }

    fn peerSyncDir(args: Args) []const u8 {
        return args.slice[2];
    }
};

fn startHostPair(
    io: Io,
    db: *wave.windows.Database,
    peer_sync_dir: wave.windows.Wtf16Z,
    peer_sync_dir_wtf8: []const u8,
    tx_queue: *wave.windows.Host.TxQueue,
) !void {
    const addr = Io.net.IpAddress.parseIp4("127.0.0.1", 0) catch unreachable;
    var server = try addr.listen(io, .{});
    defer server.deinit(io);

    var peer = try io.concurrent(startPeer, .{ io, server.socket.address, peer_sync_dir, peer_sync_dir_wtf8 });
    defer peer.cancel(io) catch {};

    const stream = try server.accept(io);
    defer stream.close(io);

    var read_buffer: [64]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    var dbg_allocator = std.heap.DebugAllocator(.{}).init;
    defer assert(dbg_allocator.deinit() == .ok);
    const allocator = dbg_allocator.allocator();

    var host = wave.windows.Host.init(db, allocator, .{ .name = "A" });
    defer host.deinit();
    std.debug.print("connected\n", .{});
    _ = try host.run(io, tx_queue, &reader.interface, &writer.interface);
}

fn startPeer(io: Io, addr: Io.net.IpAddress, sync_dir: wave.windows.Wtf16Z, sync_dir_wtf8: []const u8) !void {
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var read_buffer: [64]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var write_buffer: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);

    var dbg_allocator = std.heap.DebugAllocator(.{}).init;
    defer assert(dbg_allocator.deinit() == .ok);
    const allocator = dbg_allocator.allocator();

    var db = try wave.windows.Database.init(sync_dir, io, sync_dir_wtf8, allocator);
    defer db.deinit(io);

    var tx_queue: wave.windows.Host.TxQueue = .init(&.{});
    defer tx_queue.close(io);

    var host = wave.windows.Host.init(&db, allocator, .{ .name = "B" });
    defer host.deinit();
    _ = try host.run(io, &tx_queue, &reader.interface, &writer.interface);
}
