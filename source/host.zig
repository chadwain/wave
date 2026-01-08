const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// A listing of all files in the sync directory.
pub const Listing = struct {
    map: std.StringArrayHashMapUnmanaged(void) = .empty,
    strings: std.heap.ArenaAllocator.State = .{},

    pub fn deinit(listing: *Listing, allocator: Allocator) void {
        listing.map.deinit(allocator);
        var arena = listing.strings.promote(allocator);
        arena.deinit();
        listing.* = undefined;
    }

    fn add(listing: *Listing, allocator: Allocator, path: []const u8) !void {
        const gop = try listing.map.getOrPut(allocator, path);
        errdefer if (!gop.found_existing) listing.map.swapRemoveAt(gop.index);
        if (gop.found_existing) std.debug.panic("TODO: Found existing path while generating a directory listing: {s}\n", .{path});

        var arena = listing.strings.promote(allocator);
        defer listing.strings = arena.state;
        gop.key_ptr.* = try arena.allocator().dupe(u8, path);
    }

    pub fn print(listing: *const Listing, writer: *std.Io.Writer) !void {
        var it = listing.map.iterator();
        while (it.next()) |entry| {
            try writer.print("{s}\n", .{entry.key_ptr.*});
        }
    }
};

pub fn completeScan(
    /// Must have been opened with `std.Io.Dir.OpenOptions.iterate` set to `true`.
    sync_dir: Io.Dir,
    io: Io,
    allocator: Allocator,
) !Listing {
    var listing = Listing{};
    errdefer listing.deinit(allocator);

    var walker = try sync_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        try listing.add(allocator, entry.path);
    }

    return listing;
}

const w = std.os.windows;

pub fn watch(sync_dir: w.HANDLE, io: Io) !void {
    const buffer_size = 64 * 1024;
    var buffer align(@alignOf(w.DWORD)) = @as([buffer_size]w.BYTE, undefined);
    const notify_filters: w.FileNotifyChangeFilter = .{ .file_name = true, .dir_name = true, .last_write = true };
    var overlapped = std.mem.zeroes(w.OVERLAPPED);

    main: while (true) {
        { // TODO: Try to call ReadDirectoryChanges immediately after GetOverlappedResult so that we don't miss changes
            var bytes_returned: w.DWORD = undefined;
            const res = w.kernel32.ReadDirectoryChangesW(sync_dir, &buffer, buffer_size, w.TRUE, notify_filters, &bytes_returned, &overlapped, null);
            if (res == 0) return error.ReadDirectoryChanges;
        }

        const bytes_transferred: w.DWORD = blk: while (true) {
            try io.sleep(.fromSeconds(1), .cpu_thread);

            var bytes_transferred: w.DWORD = undefined;
            const res = w.kernel32.GetOverlappedResult(sync_dir, &overlapped, &bytes_transferred, w.FALSE);
            switch (res) {
                w.FALSE => switch (w.GetLastError()) {
                    .IO_INCOMPLETE => continue,
                    else => |err| {
                        std.debug.print("Windows error: {s}\n", .{@tagName(err)});
                        return error.GetOverlappedResult;
                    },
                },
                else => {},
            }
            if (bytes_transferred == 0) {
                std.debug.print("Couldn't read directory changes\n", .{});
                continue :main;
            }
            break :blk bytes_transferred;
        };

        processChanges((&buffer)[0..bytes_transferred]);
    }
}

fn processChanges(buffer_complete: []align(@alignOf(w.DWORD)) w.BYTE) void {
    var ptr: [*]w.BYTE = buffer_complete.ptr;
    while (true) {
        const file_notify_info: *const w.FILE_NOTIFY_INFORMATION = @ptrCast(@alignCast(ptr));

        const Action = enum(w.DWORD) {
            added = w.FILE_ACTION_ADDED,
            removed = w.FILE_ACTION_REMOVED,
            modified = w.FILE_ACTION_MODIFIED,
            renamed_old_name = w.FILE_ACTION_RENAMED_OLD_NAME,
            renamed_new_name = w.FILE_ACTION_RENAMED_NEW_NAME,
        };
        const action: Action = @enumFromInt(file_notify_info.Action);

        const file_name_begin = ptr + @sizeOf(w.FILE_NOTIFY_INFORMATION);
        const file_name: []const w.WCHAR = @ptrCast(@alignCast(file_name_begin[0..file_notify_info.FileNameLength]));
        std.debug.print("{s}: {f}\n", .{ @tagName(action), std.unicode.fmtUtf16Le(file_name) });

        if (file_notify_info.NextEntryOffset == 0) break;
        ptr += file_notify_info.NextEntryOffset;
    }
}
