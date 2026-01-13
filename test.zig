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

    // var listing = try wave.host.completeScan(sync_dir, io, allocator);
    // defer listing.deinit(allocator);
    // var stdout = Io.File.stdout().writer(io, &.{});
    // try listing.print(&stdout.interface);

    const w = std.os.windows;
    const sync_dir_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, args.syncDir());
    defer allocator.free(sync_dir_wtf16);

    // const sync_dir = try Io.Dir.cwd().openDir(io, args.syncDir(), .{ .iterate = true });
    // defer sync_dir.close(io);

    const sync_dir = try wave.host.openSyncDir(sync_dir_wtf16);
    defer w.CloseHandle(sync_dir);

    var watch_task = try io.concurrent(wave.host.watch, .{ sync_dir, io });
    defer watch_task.cancel(io) catch {};

    var stdin_buffer: [64]u8 = undefined;
    var stdin = Io.File.stdin().reader(io, &stdin_buffer);
    const reader = &stdin.interface;

    std.debug.print("Press q to quit\n", .{});
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
        if (std.mem.eql(u8, line, "q")) return;
    }

    try wave.host.simulateFileTransfer(io, allocator, sync_dir.handle);
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
