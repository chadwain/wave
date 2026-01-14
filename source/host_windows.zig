const std = @import("std");
const w = std.os.windows;
const wtf16 = std.unicode.wtf8ToWtf16LeStringLiteral;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// A listing of all files in the sync directory.
pub const Listing = struct {
    map: std.ArrayHashMapUnmanaged([]const u16, void, MapContext, true) = .empty,
    strings: std.heap.ArenaAllocator.State = .{},

    pub const MapContext = struct {
        pub fn hash(_: MapContext, s: []const u16) u32 {
            // TODO: Better hashing
            // TODO: Do WTF-16 strings have a unique representation?
            var hasher = std.hash.Wyhash.init(0);
            for (s) |c| std.hash.autoHash(&hasher, c);
            return @truncate(hasher.final());
        }
        pub fn eql(_: @This(), a: []const u16, b: []const u16, _: usize) bool {
            return std.mem.eql(u16, a, b);
        }
    };

    pub fn deinit(listing: *Listing, allocator: Allocator) void {
        listing.map.deinit(allocator);
        var arena = listing.strings.promote(allocator);
        arena.deinit();
        listing.* = undefined;
    }

    pub fn print(listing: *const Listing, writer: *std.Io.Writer) !void {
        var it = listing.map.iterator();
        while (it.next()) |entry| {
            try writer.print("{f}\n", .{std.unicode.fmtUtf16Le(entry.key_ptr.*)});
        }
    }
};

const ScanContext = struct {
    listing: Listing = .{},
    pending_dirs: std.ArrayList([]const u16) = .empty,
    pending_dir_names: std.heap.ArenaAllocator.State = .{},
    sub_path: std.ArrayList(u16) = .empty,
    component_delimeters: std.ArrayList(u16) = .empty,
    open_dir_handles: std.ArrayList(w.HANDLE) = .empty,

    fn init(sync_dir: w.HANDLE, allocator: Allocator) !ScanContext {
        var ctx = ScanContext{};
        try ctx.open_dir_handles.append(allocator, sync_dir);
        return ctx;
    }

    fn deinit(ctx: *ScanContext, allocator: Allocator) void {
        ctx.listing.deinit(allocator);
        ctx.pending_dirs.deinit(allocator);
        var arena = ctx.pending_dir_names.promote(allocator);
        arena.deinit();
        ctx.pending_dir_names = arena.state;
        ctx.sub_path.deinit(allocator);
        ctx.component_delimeters.deinit(allocator);
        for (0..ctx.open_dir_handles.items.len - 1) |i| {
            const handle = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1 - i];
            w.CloseHandle(handle);
        }
        ctx.open_dir_handles.deinit(allocator);
        ctx.* = undefined;
    }

    fn finalize(ctx: *ScanContext, allocator: Allocator) Listing {
        const listing = ctx.listing;
        ctx.listing = .{};
        ctx.deinit(allocator);
        return listing;
    }

    fn enterDir(ctx: *ScanContext, allocator: Allocator, dir_path: []const u16) !w.HANDLE {
        try ctx.component_delimeters.append(allocator, @intCast(ctx.sub_path.items.len));
        try ctx.sub_path.appendSlice(allocator, dir_path);
        try ctx.sub_path.appendSlice(allocator, comptime wtf16("\\"));

        const parent_dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
        const dir = try openDir(parent_dir, dir_path);
        try ctx.open_dir_handles.append(allocator, dir);
        return dir;
    }

    fn exitDir(ctx: *ScanContext) void {
        _ = ctx.pending_dirs.pop();
        const component_delimeter_index = ctx.component_delimeters.pop().?;
        ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
        const dir = ctx.open_dir_handles.pop().?;
        w.CloseHandle(dir);
    }

    fn addObject(ctx: *ScanContext, allocator: Allocator, name: []const u16, attrs: w.FILE.ATTRIBUTE) !void {
        if (attrs.REPARSE_POINT) return;

        const component_delimeter_index = ctx.sub_path.items.len;
        defer ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
        try ctx.sub_path.appendSlice(allocator, name);
        try ctx.sub_path.append(allocator, 0);

        const sub_path = ctx.sub_path.items[0 .. ctx.sub_path.items.len - 1 :0];
        const gop = try ctx.listing.map.getOrPut(allocator, sub_path);
        errdefer if (!gop.found_existing) ctx.listing.map.swapRemoveAt(gop.index);
        if (gop.found_existing) {
            std.debug.panic(
                "TODO: Found existing path while generating a directory listing: {f}\n",
                .{std.unicode.fmtUtf16Le(sub_path)},
            );
        }

        {
            var arena = ctx.listing.strings.promote(allocator);
            defer ctx.listing.strings = arena.state;
            const copied_sub_path = try arena.allocator().dupe(u16, sub_path);
            gop.key_ptr.* = copied_sub_path;
        }

        if (attrs.NORMAL) return;
        if (attrs.DIRECTORY) {
            var arena = ctx.pending_dir_names.promote(allocator);
            defer ctx.pending_dir_names = arena.state;
            const copied_name = try arena.allocator().dupe(u16, name);
            try ctx.pending_dirs.append(allocator, copied_name);
        }
    }
};

pub fn completeScan(sync_dir: w.HANDLE, allocator: Allocator) !Listing {
    var ctx = try ScanContext.init(sync_dir, allocator);
    errdefer ctx.deinit(allocator);

    try scanOneDirectory(sync_dir, allocator, &ctx);
    while (ctx.pending_dirs.items.len > 0) {
        const dir_path_ptr = &ctx.pending_dirs.items[ctx.pending_dirs.items.len - 1];
        if (dir_path_ptr.len == 0) {
            ctx.exitDir();
            continue;
        }

        const dir_path = dir_path_ptr.*;
        dir_path_ptr.* = &.{};
        const dir = try ctx.enterDir(allocator, dir_path);
        try scanOneDirectory(dir, allocator, &ctx);
    }
    return ctx.finalize(allocator);
}

fn scanOneDirectory(dir: w.HANDLE, allocator: Allocator, ctx: *ScanContext) !void {
    var buffer align(@alignOf(w.FILE_BOTH_DIR_INFORMATION)) = @as([64 * 1024]u8, undefined);
    var io_status_block: w.IO_STATUS_BLOCK = undefined;
    var restart_scan: w.BOOLEAN = w.TRUE;

    while (true) {
        const status = w.ntdll.NtQueryDirectoryFile(
            dir,
            null,
            null,
            null,
            &io_status_block,
            &buffer,
            buffer.len,
            .BothDirectory,
            w.FALSE,
            null,
            restart_scan,
        );
        sw: switch (status) {
            .NO_MORE_FILES => break,
            .BUFFER_OVERFLOW => return error.NtBufferOverflow,
            .SUCCESS => if (io_status_block.Information == 0) return error.NtBufferOverflow,
            .PENDING => {
                try w.WaitForSingleObject(dir, w.INFINITE);
                continue :sw io_status_block.u.Status;
            },
            else => return w.unexpectedStatus(status),
        }
        restart_scan = w.FALSE;

        var offset: usize = 0;
        var next_entry_offset: usize = 1; // Any non-zero value
        while (next_entry_offset != 0) : (offset += next_entry_offset) {
            const info: *const w.FILE_BOTH_DIR_INFORMATION = @ptrCast(@alignCast(&buffer[offset]));
            next_entry_offset = info.NextEntryOffset;
            const offset_of_file_name = @offsetOf(w.FILE_BOTH_DIR_INFORMATION, "FileName");
            const file_name_bytes = buffer[offset + offset_of_file_name ..][0..info.FileNameLength];
            const file_name: []const u16 = @ptrCast(@alignCast(file_name_bytes));

            switch (file_name.len) {
                1 => if (std.mem.eql(u16, file_name, comptime wtf16("."))) continue,
                2 => if (std.mem.eql(u16, file_name, comptime wtf16(".."))) continue,
                else => {},
            }

            try ctx.addObject(allocator, file_name, info.FileAttributes);
        }
    }
}

pub fn openDir(parent: ?w.HANDLE, path_wtf16: []const u16) !w.HANDLE {
    var handle: w.HANDLE = undefined;
    const path_len_bytes: w.USHORT = @intCast(@as([]const u8, @ptrCast(path_wtf16)).len);
    var unicode_string: w.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(path_wtf16.ptr),
    };
    const object_attributes: w.OBJECT_ATTRIBUTES = .{
        .Length = @sizeOf(w.OBJECT_ATTRIBUTES),
        .RootDirectory = parent,
        .ObjectName = &unicode_string,
        .Attributes = .{
            .CASE_INSENSITIVE = true,
        },
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var iosb: w.IO_STATUS_BLOCK = undefined;
    const status = w.ntdll.NtCreateFile(
        &handle,
        .{
            .STANDARD = .{
                .RIGHTS = .READ,
                .SYNCHRONIZE = true, // NOTE: Not required if we wait on events rather than the file handle itself.
            },
            .SPECIFIC = .{
                .FILE_DIRECTORY = .{
                    .LIST = true,
                    .TRAVERSE = true,
                },
            },
        },
        &object_attributes,
        &iosb,
        null,
        .{ .NORMAL = true },
        .{
            .READ = true,
            .WRITE = true,
            .DELETE = true,
        },
        .OPEN,
        .{
            .DIRECTORY_FILE = true,
            .OPEN_FOR_BACKUP_INTENT = true,
        },
        null,
        0,
    );

    switch (status) {
        .SUCCESS => return handle,
        else => return w.unexpectedStatus(status),
    }
}

pub fn openSyncDir(path_wtf16: [:0]const u16) !w.HANDLE {
    if (!std.fs.path.isAbsoluteWindowsWtf16(path_wtf16)) return error.NonAbsoluteSyncDirPath;
    const normalized = try w.wToPrefixedFileW(null, path_wtf16);
    return openDir(null, normalized.span());
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

fn sendFile(
    writer: *Io.Writer,
    sync_dir: w.HANDLE,
    file_name_wtf16: [:0]const u16,
    file_name_wtf8: []const u8,
) !FileInfo {
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
