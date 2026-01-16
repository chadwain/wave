const std = @import("std");
const assert = std.debug.assert;
const w = std.os.windows;
const wtf16 = std.unicode.wtf8ToWtf16LeStringLiteral;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Wtf16 = struct {
    slice: []const w.WCHAR,

    pub fn wtf16Cast(slice: []const w.WCHAR) Wtf16 {
        return .{ .slice = slice };
    }

    pub fn byteLen(self: Wtf16) usize {
        return self.slice.len * @sizeOf(w.WCHAR);
    }

    pub fn formatUtf8(self: Wtf16) std.fmt.Alt(Wtf16, formatWtf16AsUtf8(Wtf16)) {
        return .{ .data = self };
    }
};

pub const Wtf16Z = struct {
    slice: [:0]const w.WCHAR,

    pub fn wtf16ZCast(slice: [:0]const w.WCHAR) Wtf16Z {
        return .{ .slice = slice };
    }

    pub fn formatUtf8(self: Wtf16) std.fmt.Alt(Wtf16, formatWtf16AsUtf8(Wtf16)) {
        return .{ .data = self };
    }
};

fn formatWtf16AsUtf8(comptime T: type) fn (T, *Io.Writer) Io.Writer.Error!void {
    const ns = struct {
        fn format(self: T, writer: *Io.Writer) Io.Writer.Error!void {
            try writer.print("{f}", .{std.unicode.fmtUtf16Le(self.slice)});
        }
    };
    return ns.format;
}

pub const Database = struct {
    allocator: Allocator,
    file_path_arena: std.heap.ArenaAllocator.State = .{},
    all_known_files: FileHashMap(Entry) = .empty,
    files_needing_sync: FileHashMap(void) = .empty,
    debug: Debug,

    pub const Entry = struct {
        hash: FileHash,
        modified_time: w.LARGE_INTEGER,
        size: w.LARGE_INTEGER,
    };

    pub const FileHash = extern struct {
        blake3: [32]u8,

        pub fn format(hash: FileHash, writer: *Io.Writer) Io.Writer.Error!void {
            try writer.print("{x}", .{std.mem.nativeToBig(u256, @bitCast(hash.blake3))});
        }
    };

    pub fn FileHashMap(comptime V: type) type {
        const Context = struct {
            pub fn hash(_: @This(), self: Wtf16) u32 {
                // TODO: Better hashing
                // TODO: Do WTF-16 strings have a unique representation?
                var hasher = std.hash.Wyhash.init(0);
                for (self.slice) |c| std.hash.autoHash(&hasher, c);
                return @truncate(hasher.final());
            }
            pub fn eql(_: @This(), a: Wtf16, b: Wtf16) bool {
                return std.mem.eql(w.WCHAR, a.slice, b.slice);
            }
        };
        return std.HashMapUnmanaged(Wtf16, V, Context, std.hash_map.default_max_load_percentage);
    }

    pub fn init(allocator: Allocator) Database {
        return .{
            .allocator = allocator,
            .file_path_arena = .{},
            .all_known_files = .empty,
            .files_needing_sync = .empty,
            .debug = .{},
        };
    }

    pub fn deinit(db: *Database) void {
        db.all_known_files.deinit(db.allocator);
        db.files_needing_sync.deinit(db.allocator);
        var file_path_arena = db.file_path_arena.promote(db.allocator);
        file_path_arena.deinit();
        db.* = undefined;
    }

    fn createOrUpdateEntry(
        db: *Database,
        path: Wtf16,
        information: *const NtQueryInformation,
        hash: *const FileHash,
    ) !void {
        const gop = try db.all_known_files.getOrPut(db.allocator, path);
        errdefer db.all_known_files.removeByPtr(gop.key_ptr);

        const need_sync = !gop.found_existing or !std.mem.eql(u8, &gop.value_ptr.hash.blake3, &hash.blake3);

        var file_path_arena = db.file_path_arena.promote(db.allocator);
        defer db.file_path_arena = file_path_arena.state;
        const file_path_allocator = file_path_arena.allocator();
        if (!gop.found_existing) {
            const path_copied = try file_path_allocator.dupe(w.WCHAR, path.slice);
            gop.key_ptr.* = .wtf16Cast(path_copied);
        }
        errdefer if (!gop.found_existing) file_path_allocator.free(gop.key_ptr.slice);

        gop.value_ptr.* = .{
            .hash = hash.*,
            .modified_time = information.ChangeTime,
            .size = information.EndOfFile,
        };
        if (need_sync) try db.files_needing_sync.put(db.allocator, gop.key_ptr.*, {});
    }

    pub const Debug = struct {
        pub fn printKnownFiles(debug: *const Debug, writer: *Io.Writer) !void {
            const db: *const Database = @alignCast(@fieldParentPtr("debug", debug));
            var it = db.all_known_files.iterator();
            while (it.next()) |entry| {
                try writer.print(
                    "{f}: hash({f}) modified({}) size({})\n",
                    .{
                        entry.key_ptr.formatUtf8(),
                        entry.value_ptr.hash,
                        entry.value_ptr.modified_time,
                        entry.value_ptr.size,
                    },
                );
            }
        }

        pub fn printFilesNeedingSync(debug: *const Debug, writer: *Io.Writer) !void {
            const db: *const Database = @alignCast(@fieldParentPtr("debug", debug));
            var it = db.files_needing_sync.iterator();
            while (it.next()) |entry| {
                try writer.print("{f}\n", .{entry.key_ptr.formatUtf8()});
            }
        }
    };
};

const FullScanContext = struct {
    pending_dirs: std.ArrayList(Wtf16),
    pending_dir_names: std.heap.ArenaAllocator.State,
    sub_path: std.ArrayList(w.WCHAR),
    component_delimeters: std.ArrayList(u16),
    open_dir_handles: std.ArrayList(w.HANDLE),

    fn init(sync_dir: w.HANDLE, allocator: Allocator) !FullScanContext {
        var open_dir_handles: std.ArrayList(w.HANDLE) = .empty;
        try open_dir_handles.append(allocator, sync_dir);
        return .{
            .pending_dirs = .empty,
            .pending_dir_names = .{},
            .sub_path = .empty,
            .component_delimeters = .empty,
            .open_dir_handles = open_dir_handles,
        };
    }

    fn deinit(ctx: *FullScanContext, allocator: Allocator) void {
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

    fn enterDir(ctx: *FullScanContext, allocator: Allocator, dir_path: Wtf16) !void {
        try ctx.component_delimeters.append(allocator, @intCast(ctx.sub_path.items.len));
        try ctx.sub_path.appendSlice(allocator, dir_path.slice);
        try ctx.sub_path.appendSlice(allocator, comptime wtf16("\\"));

        const parent_dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
        const dir = try openDir(parent_dir, dir_path);
        try ctx.open_dir_handles.append(allocator, dir);
    }

    fn exitDir(ctx: *FullScanContext) void {
        const component_delimeter_index = ctx.component_delimeters.pop().?;
        ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
        const dir = ctx.open_dir_handles.pop().?;
        w.CloseHandle(dir);
    }

    fn addObject(
        ctx: *FullScanContext,
        db: *Database,
        allocator: Allocator,
        name: Wtf16,
        information: *const NtQueryInformation,
    ) !void {
        const rejected: w.FILE.ATTRIBUTE = .{
            .HIDDEN = true,
            .SYSTEM = true,
            .TEMPORARY = true,
            .REPARSE_POINT = true,
            .ENCRYPTED = true,
        };
        if (@as(w.ULONG, @bitCast(rejected)) & @as(w.ULONG, @bitCast(information.FileAttributes)) != 0) {
            const component_delimeter_index = ctx.sub_path.items.len;
            defer ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
            try ctx.sub_path.appendSlice(allocator, name.slice);
            std.debug.print("Not processing file: {f}\n", .{std.unicode.fmtUtf16Le(ctx.sub_path.items)});
            return;
        }

        if (information.FileAttributes.DIRECTORY) {
            var arena = ctx.pending_dir_names.promote(allocator);
            defer ctx.pending_dir_names = arena.state;
            const copied_name = try arena.allocator().dupe(w.WCHAR, name.slice);
            try ctx.pending_dirs.append(allocator, .wtf16Cast(copied_name));
        } else {
            const component_delimeter_index = ctx.sub_path.items.len;
            defer ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
            try ctx.sub_path.appendSlice(allocator, name.slice);

            const dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
            const file = try openFile(dir, name);
            defer w.CloseHandle(file);
            const hash = try computeFileHash(file, information.EndOfFile);

            try db.createOrUpdateEntry(.wtf16Cast(ctx.sub_path.items), information, &hash);
        }
    }
};

const nt_query_information_class: w.FILE.INFORMATION_CLASS = .IdBothDirectory;

// Corresponds to FILE_ID_BOTH_DIR_INFORMATION.
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_id_both_dir_information
const NtQueryInformation = extern struct {
    NextEntryOffset: w.ULONG,
    FileIndex: w.ULONG,
    CreationTime: w.LARGE_INTEGER,
    LastAccessTime: w.LARGE_INTEGER,
    LastWriteTime: w.LARGE_INTEGER,
    ChangeTime: w.LARGE_INTEGER,
    EndOfFile: w.LARGE_INTEGER,
    AllocationSize: w.LARGE_INTEGER,
    FileAttributes: w.FILE.ATTRIBUTE,
    FileNameLength: w.ULONG,
    EaSize: w.ULONG,
    ShortNameLength: CCHAR,
    ShortName: [12]w.WCHAR,
    FileId: w.LARGE_INTEGER,
    FileName: [1]w.WCHAR,

    // https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types
    const CCHAR = w.CHAR;
};

pub fn completeScan(db: *Database, sync_dir: w.HANDLE, allocator: Allocator) !void {
    var ctx = try FullScanContext.init(sync_dir, allocator);
    defer ctx.deinit(allocator);

    try scanOneDirectory(db, allocator, &ctx);
    while (ctx.pending_dirs.items.len > 0) {
        const dir_path_ptr = &ctx.pending_dirs.items[ctx.pending_dirs.items.len - 1];
        if (dir_path_ptr.slice.len == 0) {
            _ = ctx.pending_dirs.pop();
            ctx.exitDir();
            continue;
        }

        const dir_path = dir_path_ptr.*;
        dir_path_ptr.* = .wtf16Cast(&.{});
        try ctx.enterDir(allocator, dir_path);
        try scanOneDirectory(db, allocator, &ctx);
    }
}

fn scanOneDirectory(db: *Database, allocator: Allocator, ctx: *FullScanContext) !void {
    const dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
    var buffer align(@alignOf(NtQueryInformation)) = @as([64 * 1024]u8, undefined);
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
            nt_query_information_class,
            w.FALSE,
            null,
            restart_scan,
        );
        sw: switch (status) {
            .NO_MORE_FILES => break,
            .BUFFER_OVERFLOW => return error.NtBufferOverflow,
            .SUCCESS => if (io_status_block.Information == 0) return error.NtBufferOverflow,
            .PENDING => {
                w.WaitForSingleObject(dir, w.INFINITE) catch |err| switch (err) {
                    error.WaitAbandoned, error.WaitTimeOut => unreachable,
                    error.Unexpected => |e| return e,
                };
                continue :sw io_status_block.u.Status;
            },
            else => return w.unexpectedStatus(status),
        }
        restart_scan = w.FALSE;

        var offset: usize = 0;
        var next_entry_offset: usize = 1; // Any non-zero value
        while (next_entry_offset != 0) : (offset += next_entry_offset) {
            const info: *const NtQueryInformation = @ptrCast(@alignCast(&buffer[offset]));
            next_entry_offset = info.NextEntryOffset;
            const offset_of_file_name = @offsetOf(NtQueryInformation, "FileName");
            const file_name_bytes = buffer[offset + offset_of_file_name ..][0..info.FileNameLength];
            const file_name: Wtf16 = .wtf16Cast(@ptrCast(@alignCast(file_name_bytes)));

            if (std.mem.eql(w.WCHAR, file_name.slice, comptime wtf16(".")) or
                std.mem.eql(w.WCHAR, file_name.slice, comptime wtf16(".."))) continue;

            try ctx.addObject(db, allocator, file_name, info);
        }
    }
}

/// Opens a directory capable of async operations and being waited on.
pub fn openDir(parent: ?w.HANDLE, path: Wtf16) !w.HANDLE {
    var handle: w.HANDLE = undefined;
    const path_len_bytes: w.USHORT = @intCast(@as([]const u8, @ptrCast(path.slice)).len);
    var unicode_string: w.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(path.slice.ptr),
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
    // TODO: Do I need to wait?

    switch (status) {
        .SUCCESS => return handle,
        else => return w.unexpectedStatus(status),
    }
}

pub fn openSyncDir(path_wtf16: Wtf16Z) !w.HANDLE {
    if (!std.fs.path.isAbsoluteWindowsWtf16(path_wtf16.slice)) return error.NonAbsoluteSyncDirPath;
    const normalized = try w.wToPrefixedFileW(null, path_wtf16.slice);
    return openDir(null, .wtf16Cast(normalized.span()));
}

pub fn openFile(parent: ?w.HANDLE, path: Wtf16) !w.HANDLE {
    var handle: w.HANDLE = undefined;
    const path_len_bytes: w.USHORT = @intCast(@as([]const u8, @ptrCast(path.slice)).len);
    var unicode_string: w.UNICODE_STRING = .{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(path.slice.ptr),
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
            .GENERIC = .{ .READ = true },
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
        .{},
        null,
        0,
    );
    // TODO: Do I need to wait?

    switch (status) {
        .SUCCESS => return handle,
        else => return w.unexpectedStatus(status),
    }
}

fn computeFileHash(file: w.HANDLE, file_size: w.LARGE_INTEGER) !Database.FileHash {
    var iosb: w.IO_STATUS_BLOCK = undefined;
    var buffer: [64 * 1024]u8 = undefined;
    var written: w.LARGE_INTEGER = 0;
    var hash: std.crypto.hash.Blake3 = .init(.{});

    while (written < file_size) {
        const status = w.ntdll.NtReadFile(file, null, null, null, &iosb, &buffer, buffer.len, &written, null);
        sw: switch (status) {
            .SUCCESS => {
                hash.update((&buffer)[0..iosb.Information]);
                written += @intCast(iosb.Information);
            },
            .PENDING => {
                try w.WaitForSingleObject(file, w.INFINITE);
                continue :sw iosb.u.Status;
            },
            else => return w.unexpectedStatus(status),
        }
    }
    assert(written == file_size);

    var result: Database.FileHash = undefined;
    hash.final(&result.blake3);
    return result;
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

/// The endian-ness of messages, excluding file paths.
const message_endian: std.builtin.Endian = .little;

const cpu_endian = @import("builtin").cpu.arch.endian();

const Message = enum(u8) {
    transfer_file,
};

const PathEncoding = enum(u8) {
    wtf16le,
};

fn sendTransferFileMessage(
    writer: *Io.Writer,
    file: w.HANDLE,
    file_path: Wtf16,
    information: *const w.FILE.STANDARD_INFORMATION,
    hash: *const Database.FileHash,
) !void {
    try writer.writeByte(@intFromEnum(Message.transfer_file));

    const path_encoding: PathEncoding = switch (cpu_endian) {
        .big => @compileError("Big endian not supported"),
        .little => .wtf16le,
    };
    try writer.writeByte(@intFromEnum(path_encoding));
    try writer.writeInt(u64, file_path.byteLen(), message_endian);
    try writer.writeInt(u64, @intCast(information.EndOfFile), message_endian);
    try writer.writeAll(&hash.blake3);
    try writer.writeSliceEndian(w.WCHAR, file_path.slice, cpu_endian);

    var iosb: w.IO_STATUS_BLOCK = undefined;
    var written: w.LARGE_INTEGER = 0;
    while (written < information.EndOfFile) {
        const buffer = blk: {
            const slice = try writer.writableSliceGreedy(1);
            break :blk slice[0..@min(slice.len, std.math.maxInt(u32))];
        };
        const status = w.ntdll.NtReadFile(
            file,
            null,
            null,
            null,
            &iosb,
            buffer.ptr,
            @intCast(buffer.len),
            &written,
            null,
        );
        sw: switch (status) {
            .SUCCESS => {
                writer.advance(iosb.Information);
                written += @intCast(iosb.Information);
            },
            .PENDING => {
                try w.WaitForSingleObject(file, w.INFINITE);
                continue :sw iosb.u.Status;
            },
            else => return w.unexpectedStatus(status),
        }
    }
    assert(written == information.EndOfFile);

    try writer.flush();
}

/// Asserts a reader buffer size of at least 8.
fn receiveTransferFileMessage(reader: *Io.Reader, allocator: Allocator) !void {
    const alignment: std.mem.Alignment = comptime .max(.of(w.WCHAR), .of(u64));
    var dest: Io.Writer.Allocating = .initAligned(allocator, alignment);
    defer dest.deinit();

    const path_encoding: PathEncoding = @enumFromInt(try reader.takeByte());
    const path_len_bytes = try reader.takeInt(u64, message_endian);
    const file_size = try reader.takeInt(u64, message_endian);

    try reader.streamExact(&dest.writer, @sizeOf(Database.FileHash));
    const hash: Database.FileHash = .{ .blake3 = dest.written()[0..@sizeOf(Database.FileHash)].* };
    dest.clearRetainingCapacity();

    try reader.streamExact(&dest.writer, path_len_bytes);
    const path_bytes: []align(alignment.toByteUnits()) const u8 = @alignCast(try dest.toOwnedSlice());
    defer allocator.free(path_bytes);
    const path: Wtf16 = switch (path_encoding) {
        .wtf16le => switch (cpu_endian) {
            .big => @compileError("Big endian not supported"),
            .little => .wtf16Cast(@ptrCast(@alignCast(path_bytes))),
        },
    };

    try reader.streamExact(&dest.writer, file_size);
    const file_contents: []align(alignment.toByteUnits()) const u8 = @alignCast(try dest.toOwnedSlice());
    defer allocator.free(file_contents);

    std.debug.print("{f}: hash({f}) size({})\n{s}\n", .{
        path.formatUtf8(),
        hash,
        file_size,
        file_contents,
    });
}

pub fn simulateFileTransfer(db: *const Database, sync_dir: w.HANDLE, io: Io, allocator: Allocator) !void {
    const random_file = blk: {
        const max = std.math.sub(usize, db.all_known_files.size, 1) catch return;
        const now = try Io.Clock.real.now(io);
        var rng = std.Random.DefaultPrng.init(@bitCast(now.toMilliseconds()));
        const int = rng.random().uintAtMost(usize, max);
        var it = db.all_known_files.keyIterator();
        for (0..int) |_| _ = it.next().?;
        break :blk it.next().?.*;
    };

    const file = try openFile(sync_dir, random_file);
    defer w.CloseHandle(file);

    var iosb: w.IO_STATUS_BLOCK = undefined;
    var information: w.FILE.STANDARD_INFORMATION = undefined;
    const status = w.ntdll.NtQueryInformationFile(file, &iosb, &information, @sizeOf(@TypeOf(information)), .Standard);
    sw: switch (status) {
        .SUCCESS => {},
        .PENDING => {
            try w.WaitForSingleObject(file, w.INFINITE);
            continue :sw iosb.u.Status;
        },
        else => return w.unexpectedStatus(status),
    }

    const hash = try computeFileHash(file, information.EndOfFile);

    var writer = Io.Writer.Allocating.init(allocator);
    defer writer.deinit();
    try sendTransferFileMessage(&writer.writer, file, random_file, &information, &hash);

    var reader = Io.Reader.fixed(writer.written());
    const message: Message = @enumFromInt(try reader.takeByte());
    switch (message) {
        .transfer_file => try receiveTransferFileMessage(&reader, allocator),
    }
}
