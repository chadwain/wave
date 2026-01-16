const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const wave = @import("wave");

pub fn main() !void {
    var dbg_alloc = std.heap.DebugAllocator(.{}).init;
    defer assert(dbg_alloc.deinit() == .ok);
    const allocator = dbg_alloc.allocator();

    var threaded = Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = try Args.init(allocator);
    defer args.deinit(allocator);

    const sync_dir_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, args.syncDir());
    defer allocator.free(sync_dir_wtf16);

    const w = std.os.windows;
    const sync_dir = try wave.host_windows.openSyncDir(.wtf16ZCast(sync_dir_wtf16));
    defer w.CloseHandle(sync_dir);

    var db = wave.host_windows.Database.init(allocator);
    defer db.deinit();

    var watch_task = try io.concurrent(wave.host_windows.watch, .{ sync_dir, io });
    defer watch_task.cancel(io) catch {};

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
                try wave.host_windows.completeScan(&db, sync_dir, allocator);
                try stdout.interface.writeAll("scan complete\n");
                try stdout.interface.flush();
            },
            'q' => break,
            else => continue,
        }
    }

    try wave.host_windows.simulateFileTransfer(&db, sync_dir, io, allocator);
}

const Args = struct {
    all_args: [][:0]u8,

    fn init(allocator: Allocator) !Args {
        var args = try std.process.argsAlloc(allocator);
        errdefer std.process.argsFree(allocator, args);

        switch (args.len) {
            2 => return .{ .all_args = args },
            else => return error.InvalidArguments,
        }
    }

    fn deinit(args: Args, allocator: Allocator) void {
        std.process.argsFree(allocator, args.all_args);
    }

    fn syncDir(args: Args) []const u8 {
        return args.all_args[1];
    }
};
