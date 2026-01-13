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
        if (gop.found_existing) {
            std.debug.panic("TODO: Found existing path while generating a directory listing: {s}\n", .{path});
        }

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

pub fn openSyncDir(path_wtf16: [:0]const u16) !w.HANDLE {
    const FILE_SHARE_READ = 0x1;
    const FILE_SHARE_WRITE = 0x2;
    const FILE_SHARE_DELETE = 0x4;
    const handle = w.kernel32.CreateFileW(
        path_wtf16,
        .{ .GENERIC = .{ .READ = true } },
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        null,
        w.OPEN_EXISTING,
        w.FILE_FLAG_BACKUP_SEMANTICS | w.FILE_FLAG_OVERLAPPED,
        null,
    );
    if (handle == w.INVALID_HANDLE_VALUE) return error.CreateFile;
    return handle;
}

pub fn watch(sync_dir: w.HANDLE, io: Io) !void {
    const buffer_size = 64 * 1024;
    var buffer align(@alignOf(w.DWORD)) = @as([buffer_size]w.BYTE, undefined);
    const notify_filters: w.FileNotifyChangeFilter = .{ .file_name = true, .dir_name = true, .last_write = true };
    var overlapped = std.mem.zeroes(w.OVERLAPPED);

    main: while (true) {
        { // TODO: Try to call ReadDirectoryChanges immediately after GetOverlappedResult so that we don't miss changes
            var bytes_returned: w.DWORD = undefined;
            const res = w.kernel32.ReadDirectoryChangesW(
                sync_dir,
                &buffer,
                buffer_size,
                w.TRUE,
                notify_filters,
                &bytes_returned,
                &overlapped,
                null,
            );
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

const FileInfo = extern struct {
    path_len_bytes: u64,
    size: u64,
};
const endian: std.builtin.Endian = .little;

fn sendFile(writer: *Io.Writer, sync_dir: w.HANDLE, file_name_wtf16: [:0]const u16, file_name_wtf8: []const u8) !FileInfo {
    var temp_io = Io.Threaded.init_single_threaded;
    const io = temp_io.io();

    var file = try temp_io.dirOpenFileWtf16(sync_dir, file_name_wtf16, .{});
    defer file.close(io);
    const stat = try file.stat(io);

    const info = FileInfo{ .size = stat.size, .path_len_bytes = file_name_wtf8.len };
    std.debug.print("send: {}\n", .{info});
    try writer.writeStruct(info, endian);
    try writer.writeAll(file_name_wtf8);

    var reader_buffer: [1 << 20]u8 = undefined;
    var reader = file.readerStreaming(io, &reader_buffer);
    try reader.interface.streamExact(writer, stat.size);

    try writer.flush();
    return info;
}

fn receiveFile(reader: *Io.Reader, allocator: Allocator, expected: FileInfo) !void {
    const info = try reader.takeStruct(FileInfo, endian);
    std.debug.assert(std.meta.eql(info, expected));

    const file_name = blk: {
        const buffer = try allocator.alloc(u8, info.path_len_bytes);
        errdefer allocator.free(buffer);
        try reader.readSliceAll(buffer);
        break :blk buffer;
    };
    defer allocator.free(file_name);

    const content = blk: {
        const buffer = try allocator.alloc(u8, info.size);
        errdefer allocator.free(buffer);
        try reader.readSliceAll(buffer);
        break :blk buffer;
    };
    defer allocator.free(content);

    std.debug.print("{s}\n{s}\n", .{ file_name, content });
}

pub fn simulateFileTransfer(io: Io, allocator: Allocator, sync_dir: w.HANDLE) !void {
    var listing = try completeScan(.{ .handle = sync_dir }, io, allocator);
    defer listing.deinit(allocator);
    if (listing.map.entries.len == 0) return error.NoFiles;

    const random_file_path_wtf8 = blk: {
        var rng = std.Random.DefaultPrng.init(42);
        const int = rng.random().uintAtMost(usize, listing.map.entries.len - 1);
        break :blk listing.map.keys()[int];
    };
    const random_file_path_wtf16 = try std.unicode.wtf8ToWtf16LeAllocZ(allocator, random_file_path_wtf8);
    defer allocator.free(random_file_path_wtf16);

    var writer = Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    const info = try sendFile(&writer.writer, sync_dir, random_file_path_wtf16, random_file_path_wtf8);

    var reader = Io.Reader.fixed(writer.written());
    try receiveFile(&reader, allocator, info);
}
