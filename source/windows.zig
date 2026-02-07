const std = @import("std");
const assert = std.debug.assert;
const w = std.os.windows;
const wtf16 = std.unicode.wtf8ToWtf16LeStringLiteral;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const wave = @import("wave.zig");
const network = wave.network;

const cpu_endian = @import("builtin").cpu.arch.endian();

/// A WTF-16 encoded string, with the endianness of the host system.
pub const Wtf16 = struct {
    slice: []const w.WCHAR,

    pub fn wtf16Cast(slice: []const w.WCHAR) Wtf16 {
        return .{ .slice = slice };
    }

    pub fn byteLen(self: Wtf16) usize {
        return self.slice.len * @sizeOf(w.WCHAR);
    }

    pub fn dupe(self: Wtf16, allocator: Allocator) !Wtf16 {
        return .{ .slice = try allocator.dupe(u16, self.slice) };
    }

    /// Does a potentially lossy conversion from WTF-16 to UTF-8.
    pub fn formatUtf8(self: Wtf16) std.fmt.Alt([]const w.WCHAR, formatWtf16AsUtf8) {
        return .{ .data = self.slice };
    }
};

/// A WTF-16 encoded zero-terminated string, with the endianness of the host system.
pub const Wtf16Z = struct {
    slice: [:0]const w.WCHAR,

    pub fn wtf16ZCast(slice: [:0]const w.WCHAR) Wtf16Z {
        return .{ .slice = slice };
    }

    /// Does a potentially lossy conversion from WTF-16 to UTF-8.
    pub fn formatUtf8(self: Wtf16Z) std.fmt.Alt([]const w.WCHAR, formatWtf16AsUtf8) {
        return .{ .data = self.slice };
    }
};

fn formatWtf16AsUtf8(slice: []const w.WCHAR, writer: *Io.Writer) Io.Writer.Error!void {
    switch (cpu_endian) {
        .little => try writer.print("{f}", .{std.unicode.fmtUtf16Le(slice)}),
        .big => @compileError("TODO big endian"),
    }
}

pub const Database = struct {
    sync_dir: w.HANDLE,
    sync_dir_io: Io.Dir,

    file_path_arena: std.heap.ArenaAllocator.State = .{},
    all_known_files: FileHashMap(Entry) = .empty,
    files_needing_sync: FileHashMap(void) = .empty,

    allocator: Allocator,
    mutex: Io.Mutex, // TODO: Replace with RwLock
    debug: Debug,

    pub const Entry = struct {
        hash: network.FileHash,
        modified_time: w.LARGE_INTEGER,
        size: w.LARGE_INTEGER, // TODO: Store as an unsigned integer
    };

    pub fn FileHashMap(comptime V: type) type {
        const Context = struct {
            pub fn hash(_: @This(), self: Wtf16) u32 {
                // TODO: Better hashing
                // TODO: Case insensitivity
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

    pub fn init(sync_dir_path: Wtf16Z, io: Io, sync_dir_path_wtf8: []const u8, allocator: Allocator) !Database {
        if (!std.fs.path.isAbsoluteWindowsWtf16(sync_dir_path.slice)) return error.NonAbsoluteSyncDirPath;
        const normalized = try w.wToPrefixedFileW(null, sync_dir_path.slice);
        const sync_dir = try openDir(null, .wtf16Cast(normalized.span()));
        errdefer w.CloseHandle(sync_dir);

        const sync_dir_io = try Io.Dir.cwd().openDir(io, sync_dir_path_wtf8, .{});
        errdefer comptime unreachable;

        return .{
            .sync_dir = sync_dir,
            .sync_dir_io = sync_dir_io,

            .file_path_arena = .{},
            .all_known_files = .empty,
            .files_needing_sync = .empty,

            .allocator = allocator,
            .mutex = .init,
            .debug = .{},
        };
    }

    pub fn deinit(db: *Database, io: Io) void {
        w.CloseHandle(db.sync_dir);
        db.sync_dir_io.close(io);

        db.all_known_files.deinit(db.allocator);
        db.files_needing_sync.deinit(db.allocator);
        var file_path_arena = db.file_path_arena.promote(db.allocator);
        file_path_arena.deinit();

        db.* = undefined;
    }

    /// Must be called with a lock.
    fn createOrUpdateEntry(
        db: *Database,
        path: Wtf16,
        information: *const NtQueryInformation,
        hash: *const network.FileHash,
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

    fn checkMetadata(
        db: *Database,
        metadata: *const network.IncomingFileMetadata,
        file_path_buffer: *align(@alignOf(w.WCHAR)) const network.FilePathBuffer,
        io: Io,
    ) !struct {
        Wtf16,
        enum { equals, differs },
    } {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        // TODO: normalize path
        const path: Wtf16 = switch (metadata.path_encoding) {
            .wtf16le => switch (cpu_endian) {
                .little => .wtf16Cast(@ptrCast(file_path_buffer[0..metadata.path_len_bytes])),
                .big => @compileError("TODO big endian"),
            },
        };

        var file_path_arena = db.file_path_arena.promote(db.allocator);
        defer db.file_path_arena = file_path_arena.state;
        const path_copied = try path.dupe(file_path_arena.allocator());

        const entry = db.all_known_files.getPtr(path);
        if (entry != null and
            entry.?.size == metadata.file_size and
            std.mem.eql(u8, &entry.?.hash.blake3, &metadata.hash.blake3))
        {
            return .{ path_copied, .equals };
        } else {
            return .{ path_copied, .differs };
        }
    }

    pub const SendFileError = w.WaitForSingleObjectError;

    fn sendFile(
        _: *const Database,
        handle: w.HANDLE,
        send_file: *const Host.Transaction.Data.SendFile,
        writer: *Io.Writer,
    ) !void {
        var iosb: w.IO_STATUS_BLOCK = undefined;
        var written: w.LARGE_INTEGER = 0;
        while (written < send_file.size) {
            const buffer = buffer: {
                const slice = try writer.writableSliceGreedy(1);
                break :buffer slice[0..@min(slice.len, std.math.maxInt(w.ULONG))];
            };
            const status = w.ntdll.NtReadFile(
                handle,
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
                    try w.WaitForSingleObject(handle, w.INFINITE);
                    continue :sw iosb.u.Status;
                },
                else => return w.unexpectedStatus(status),
            }
        }
        assert(written == send_file.size);
    }

    pub const ReceiveFileError = w.WaitForSingleObjectError;

    fn receiveFile(
        db: *Database,
        receive_file: *const Host.Transaction.Data.ReceiveFile,
        reader: *Io.Reader,
        io: Io,
    ) !void {
        const handle = try openFile(db.sync_dir, receive_file.path, .creating);
        defer w.CloseHandle(handle);

        var read: w.LARGE_INTEGER = 0;
        var iosb: w.IO_STATUS_BLOCK = undefined;
        while (read < receive_file.size) {
            const buffer = buffer: {
                const slice = try reader.peekGreedy(1);
                break :buffer slice[0..@min(slice.len, std.math.maxInt(w.ULONG))];
            };
            const status = w.ntdll.NtWriteFile(
                handle,
                null,
                null,
                null,
                &iosb,
                buffer.ptr,
                @intCast(buffer.len),
                &read,
                null,
            );
            sw: switch (status) {
                .SUCCESS => {
                    reader.toss(iosb.Information);
                    read += @intCast(iosb.Information);
                },
                .PENDING => {
                    try w.WaitForSingleObject(handle, w.INFINITE);
                    continue :sw iosb.u.Status;
                },
                else => return w.unexpectedStatus(status),
            }
        }
        assert(read == receive_file.size);

        const information = blk: {
            var information: w.FILE.BASIC_INFORMATION = undefined;
            const status = w.ntdll.NtQueryInformationFile(
                handle,
                &iosb,
                &information,
                @sizeOf(@TypeOf(information)),
                .Basic,
            );
            sw: switch (status) {
                .SUCCESS => break :blk information,
                .PENDING => {
                    try w.WaitForSingleObject(handle, w.INFINITE);
                    continue :sw iosb.u.Status;
                },
                else => return w.unexpectedStatus(status),
            }
        };

        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        try db.all_known_files.putNoClobber(db.allocator, receive_file.path, .{
            .hash = receive_file.hash,
            .modified_time = information.ChangeTime,
            .size = receive_file.size,
        });
    }

    pub const Debug = struct {
        /// Must be called with a lock.
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

        /// Must be called with a lock.
        pub fn printFilesNeedingSync(debug: *const Debug, writer: *Io.Writer) !void {
            const db: *const Database = @alignCast(@fieldParentPtr("debug", debug));

            var it = db.files_needing_sync.iterator();
            while (it.next()) |entry| {
                try writer.print("{f}\n", .{entry.key_ptr.formatUtf8()});
            }
        }

        /// Must be called with a lock.
        pub fn hostTransferFile(debug: *const Debug, index: usize, io: Io, q: *Host.TxQueue) !void {
            const db: *const Database = @alignCast(@fieldParentPtr("debug", debug));

            const entry = blk: {
                var it = db.all_known_files.iterator();
                for (0..index) |_| _ = it.next().?;
                break :blk it.next().?;
            };
            const transaction_data: Host.Transaction.Data = .{
                .send_file = .{
                    .state = .send_metadata,
                    .path = entry.key_ptr.*,
                    .size = entry.value_ptr.size,
                    .hash = entry.value_ptr.hash,
                },
            };
            try q.putOne(io, transaction_data);
        }
    };
};

const FullScanContext = struct {
    pending_dirs: std.ArrayList(Wtf16),
    pending_dir_names: std.heap.ArenaAllocator.State,
    sub_path: std.ArrayList(w.WCHAR),
    component_delimeters: std.ArrayList(u16),
    open_dir_handles: std.ArrayList(w.HANDLE),

    fn init(db: *const Database, allocator: Allocator) !FullScanContext {
        var open_dir_handles: std.ArrayList(w.HANDLE) = .empty;
        errdefer open_dir_handles.deinit(allocator);
        try open_dir_handles.append(allocator, db.sync_dir);

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
            const file = try openFile(dir, name, .reading);
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

pub fn completeScan(db: *Database, io: Io, allocator: Allocator) !void {
    try db.mutex.lock(io);
    defer db.mutex.unlock(io);

    var ctx = try FullScanContext.init(db, allocator);
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
fn openDir(parent: ?w.HANDLE, path: Wtf16) !w.HANDLE {
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

fn openFile(parent: ?w.HANDLE, path: Wtf16, purpose: enum { reading, creating }) !w.HANDLE {
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
            .GENERIC = switch (purpose) {
                .reading => .{ .READ = true },
                .creating => .{ .READ = true, .WRITE = true },
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
        switch (purpose) {
            .reading => .OPEN,
            .creating => .OVERWRITE_IF,
        },
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

fn computeFileHash(file: w.HANDLE, file_size: w.LARGE_INTEGER) !network.FileHash {
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

    var result: network.FileHash = undefined;
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

pub const Host = struct {
    next_tx_id: ?std.meta.Tag(network.TransactionId),
    /// Maps transaction IDs to indeces with `txs`.
    tx_id_index_map: std.AutoArrayHashMapUnmanaged(network.TransactionId, void),
    txs: std.MultiArrayList(Transaction),
    outgoing_tx_count: std.atomic.Value(u32),
    allocator: Allocator,
    mutex: Io.Mutex,

    db: *Database,
    debug: Debug,

    pub const Debug = struct {
        name: ?[]const u8 = null,
    };

    pub const Transaction = struct {
        direction: Direction,
        data: Data,
        peer_tx_id: network.TransactionId,

        pub const Direction = enum { outgoing, incoming };

        pub const Data = union(enum) {
            send_file: SendFile,
            receive_file: ReceiveFile,

            pub const SendFile = struct {
                state: State,
                path: Wtf16,
                size: w.LARGE_INTEGER,
                hash: network.FileHash,

                pub const State = enum {
                    send_metadata,
                    receive_decision,
                    send_file_contents,
                    receive_result,
                };
            };

            pub const ReceiveFile = struct {
                state: State,
                path: Wtf16,
                size: w.LARGE_INTEGER,
                hash: network.FileHash,

                pub const State = union(enum) {
                    send_decision: SendDecision,
                    receive_file_contents,
                    send_result: SendResult,

                    pub const SendDecision = enum { accept, decline };
                    pub const SendResult = enum { success, failure };
                };
            };
        };
    };

    pub const TxQueue = Io.Queue(Transaction.Data);

    pub fn init(db: *Database, allocator: Allocator, debug: Debug) Host {
        return .{
            .next_tx_id = 0,
            .tx_id_index_map = .empty,
            .txs = .empty,
            .outgoing_tx_count = .init(0),
            .allocator = allocator,
            .mutex = .init,

            .db = db,
            .debug = debug,
        };
    }

    pub fn deinit(host: *Host) void {
        host.tx_id_index_map.deinit(host.allocator);
        host.txs.deinit(host.allocator);
        host.* = undefined;
    }

    const AddOutgoingTxError = error{NoMoreTransactions} || Allocator.Error || Io.Cancelable;

    fn addOutgoingTx(
        host: *Host,
        io: Io,
        data: Transaction.Data,
        peer_tx_id: network.TransactionId,
    ) AddOutgoingTxError!void {
        try host.mutex.lock(io);
        defer host.mutex.unlock(io);

        const next_tx_id = host.next_tx_id orelse return error.NoMoreTransactions;
        host.next_tx_id = std.math.add(std.meta.Tag(network.TransactionId), next_tx_id, 1) catch null;
        errdefer host.next_tx_id = next_tx_id;

        const gop = try host.tx_id_index_map.getOrPut(host.allocator, @enumFromInt(next_tx_id));
        assert(!gop.found_existing);
        errdefer host.tx_id_index_map.orderedRemoveAt(gop.index);

        try host.txs.insert(host.allocator, gop.index, .{
            .direction = .outgoing,
            .data = data,
            .peer_tx_id = peer_tx_id,
        });
        errdefer comptime unreachable;

        host.incrementOutgoingTxCount(io);
    }

    fn incrementOutgoingTxCount(host: *Host, io: Io) void {
        const previous_send_count = host.outgoing_tx_count.fetchAdd(1, .seq_cst);
        if (previous_send_count == 0) io.futexWake(u32, &host.outgoing_tx_count.raw, 1);
    }

    fn flipTransaction(
        host: *Host,
        comptime to: Transaction.Direction,
        tx_id: network.TransactionId,
        comptime tag: std.meta.FieldEnum(Transaction.Data),
        new_state: @FieldType(Transaction.Data, @tagName(tag)).State,
        /// If non-null, the peer tx id will be replaced with this value.
        peer_tx_id: ?network.TransactionId,
        io: Io,
    ) !void {
        try host.mutex.lock(io);
        defer host.mutex.unlock(io);

        const index = host.tx_id_index_map.getIndex(tx_id).?;
        const txs = host.txs.slice();
        const data = &txs.items(.data)[index];
        @field(data, @tagName(tag)).state = new_state;
        if (peer_tx_id) |id| txs.items(.peer_tx_id)[index] = id;

        const from = &txs.items(.direction)[index];
        switch (to) {
            .outgoing => {
                assert(from.* == .incoming);
                from.* = .outgoing;
                host.incrementOutgoingTxCount(io);
            },
            .incoming => {
                assert(from.* == .outgoing);
                from.* = .incoming;
                _ = host.outgoing_tx_count.fetchSub(1, .seq_cst);
            },
        }
    }

    fn deleteTransaction(
        host: *Host,
        io: Io,
        tx_id: network.TransactionId,
        expected_direction: Transaction.Direction,
    ) !void {
        try host.mutex.lock(io);
        defer host.mutex.unlock(io);

        const index = host.tx_id_index_map.getIndex(tx_id).?;
        assert(host.txs.items(.direction)[index] == expected_direction);
        host.tx_id_index_map.orderedRemoveAt(index);
        host.txs.orderedRemove(index);

        if (expected_direction == .outgoing) {
            _ = host.outgoing_tx_count.fetchSub(1, .seq_cst);
        }
    }

    fn debugLog(host: *const Host, comptime fmt: []const u8, args: anytype) void {
        if (host.debug.name) |name| {
            wave.log.debug("(host:{s}) " ++ fmt, .{name} ++ args);
        } else {
            wave.log.debug(fmt, args);
        }
    }

    fn logMessage(
        host: *const Host,
        direction: Transaction.Direction,
        tx_id: network.TransactionId,
        action: network.Action,
        peer_tx_id: network.TransactionId,
    ) void {
        switch (direction) {
            .outgoing => host.debugLog(
                "{s} tx#{f} {s} -> peer tx#{f}",
                .{ @tagName(direction), tx_id, @tagName(action), peer_tx_id },
            ),
            .incoming => host.debugLog(
                "{s} tx#{f} <- peer tx#{f} {s}",
                .{ @tagName(direction), tx_id, peer_tx_id, @tagName(action) },
            ),
        }
    }

    pub const RunError = Io.ConcurrentError || Io.Cancelable;

    pub const RunResult = struct {
        read_tx_queue_result: ReadTxQueueError!void,
        outgoing_result: OutgoingError!void,
        incoming_result: IncomingError!void,
    };

    pub fn run(
        host: *Host,
        io: Io,
        tx_queue: *TxQueue,
        reader: *Io.Reader,
        writer: *Io.Writer,
    ) RunError!RunResult {
        defer tx_queue.close(io);

        var read_queue = try io.concurrent(readTxQueue, .{ host, io, tx_queue });
        defer read_queue.cancel(io) catch {};
        var outgoing = try io.concurrent(sendOutgoingTxs, .{ host, io, writer });
        defer outgoing.cancel(io) catch {};
        var incoming = try io.concurrent(receiveIncomingTxs, .{ host, io, reader });
        defer incoming.cancel(io) catch {};

        host.debugLog("started", .{});
        _ = try io.select(.{
            .read_queue = &read_queue,
            .outgoing = &outgoing,
            .incoming = &incoming,
        });

        return .{
            .read_tx_queue_result = read_queue.await(io),
            .outgoing_result = outgoing.await(io),
            .incoming_result = incoming.await(io),
        };
    }

    pub const ReadTxQueueError = Io.QueueClosedError || AddOutgoingTxError;

    fn readTxQueue(host: *Host, io: Io, tx_queue: *TxQueue) ReadTxQueueError!void {
        while (true) {
            const data = try tx_queue.getOne(io);
            try host.addOutgoingTx(io, data, .new);
        }
    }

    pub const OutgoingError = Io.Writer.Error || Io.Cancelable || Database.SendFileError;

    fn sendOutgoingTxs(host: *Host, io: Io, writer: *Io.Writer) OutgoingError!void {
        errdefer {
            if (@errorReturnTrace()) |trace| {
                host.debugLog("{f}", .{std.debug.FormatStackTrace{ .stack_trace = trace.* }});
            }
        }

        while (true) {
            // TODO: Learn a thing or two about atomic orderings and pick something other than seq_cst
            while (host.outgoing_tx_count.load(.seq_cst) == 0) {
                try io.futexWait(u32, &host.outgoing_tx_count.raw, 0);
            }

            const data, const tx_id, const peer_tx_id = blk: {
                try host.mutex.lock(io);
                defer host.mutex.unlock(io);

                const txs = host.txs.slice();
                for (txs.items(.direction), 0..) |direction, index| {
                    if (direction == .outgoing) break :blk .{
                        txs.items(.data)[index],
                        host.tx_id_index_map.keys()[index],
                        txs.items(.peer_tx_id)[index],
                    };
                }
                unreachable;
            };

            switch (data) {
                .send_file => |*send_file| try host.outgoingSendFile(
                    send_file,
                    tx_id,
                    peer_tx_id,
                    io,
                    writer,
                ),
                .receive_file => |*receive_file| try host.outgoingReceiveFile(
                    receive_file,
                    tx_id,
                    peer_tx_id,
                    io,
                    writer,
                ),
            }
        }
    }

    fn outgoingSendFile(
        host: *Host,
        send_file: *const Transaction.Data.SendFile,
        tx_id: network.TransactionId,
        peer_tx_id: network.TransactionId,
        io: Io,
        writer: *Io.Writer,
    ) !void {
        const next_state: Transaction.Data.SendFile.State = blk: switch (send_file.state) {
            .send_metadata => {
                host.logMessage(.outgoing, tx_id, .transfer_file_metadata, peer_tx_id);

                const file_size = std.math.cast(network.FileSize, send_file.size) orelse
                    std.debug.panic(
                        "TODO: File too large to transfer: '{f}' with size {}",
                        .{ send_file.path.formatUtf8(), send_file.size },
                    );
                try network.sendTransactionId(writer, peer_tx_id);
                try network.sendTransactionId(writer, tx_id);
                try network.sendAction(writer, .transfer_file_metadata);
                try network.sendFileMetadata(
                    writer,
                    switch (cpu_endian) {
                        .big => @compileError("TODO big endian"),
                        .little => .wtf16le,
                    },
                    @ptrCast(send_file.path.slice),
                    file_size,
                    &send_file.hash,
                );
                try writer.flush();
                break :blk .receive_decision;
            },
            .send_file_contents => {
                host.logMessage(.outgoing, tx_id, .transfer_file_contents, peer_tx_id);

                // TODO: Probably a good idea to make Database act as a middleman for opening files
                const handle = try openFile(host.db.sync_dir, send_file.path, .reading);
                defer w.CloseHandle(handle);
                try network.sendTransactionId(writer, peer_tx_id);
                try network.sendTransactionId(writer, tx_id);
                try network.sendAction(writer, .transfer_file_contents);
                try host.db.sendFile(handle, send_file, writer);
                try writer.flush();
                break :blk .receive_result;
            },
            .receive_decision, .receive_result => unreachable,
        };

        try host.flipTransaction(.incoming, tx_id, .send_file, next_state, null, io);
    }

    fn outgoingReceiveFile(
        host: *Host,
        receive_file: *const Transaction.Data.ReceiveFile,
        tx_id: network.TransactionId,
        peer_tx_id: network.TransactionId,
        io: Io,
        writer: *Io.Writer,
    ) !void {
        switch (receive_file.state) {
            .send_decision => |send_decision| {
                const actual_tx_id: network.TransactionId, const action: network.Action = switch (send_decision) {
                    .accept => .{ tx_id, .transfer_file_accept },
                    .decline => .{ .new, .transfer_file_decline },
                };
                host.logMessage(.outgoing, tx_id, action, peer_tx_id);

                try network.sendTransactionId(writer, peer_tx_id);
                try network.sendTransactionId(writer, actual_tx_id);
                try network.sendAction(writer, action);
                try writer.flush();

                switch (send_decision) {
                    .accept => {
                        try host.flipTransaction(.incoming, tx_id, .receive_file, .receive_file_contents, null, io);
                    },
                    .decline => try host.deleteTransaction(io, tx_id, .outgoing),
                }
            },
            .send_result => |send_result| {
                const action: network.Action = switch (send_result) { // TODO
                    .success => .transfer_file_success,
                    .failure => .transfer_file_failure,
                };
                host.logMessage(.outgoing, tx_id, action, peer_tx_id);

                try network.sendTransactionId(writer, peer_tx_id);
                try network.sendTransactionId(writer, tx_id);
                try network.sendAction(writer, action);
                try writer.flush();

                try host.deleteTransaction(io, tx_id, .outgoing);
            },
            .receive_file_contents => unreachable,
        }
    }

    pub const IncomingError = error{
        InvalidTxId,
        InvalidPeerTxId,
        WrongTxId,
        WrongPeerTxId,
        InvalidAction,
    } || Io.Reader.StreamError || Io.Cancelable || Allocator.Error || AddOutgoingTxError || Database.ReceiveFileError;

    fn receiveIncomingTxs(host: *Host, io: Io, reader: *Io.Reader) IncomingError!void {
        errdefer {
            if (@errorReturnTrace()) |trace| {
                host.debugLog("{f}", .{std.debug.FormatStackTrace{ .stack_trace = trace.* }});
            }
        }

        while (true) {
            const tx_id = try network.receiveTransactionId(reader) orelse break;
            const peer_tx_id = try network.receiveTransactionId(reader) orelse return error.InvalidPeerTxId;
            const action = try network.receiveAction(reader);
            host.logMessage(.incoming, tx_id, action, peer_tx_id);

            switch (action) {
                .transfer_file_metadata => {
                    if (tx_id != .new) return error.InvalidTxId;
                    try host.newIncomingReceiveFile(peer_tx_id, io, reader);
                    continue;
                },
                else => {},
            }

            const data = blk: {
                try host.mutex.lock(io);
                defer host.mutex.unlock(io);

                const index = host.tx_id_index_map.getIndex(tx_id) orelse return error.WrongTxId;
                const txs = host.txs.slice();
                switch (txs.items(.direction)[index]) {
                    .outgoing => return error.InvalidTxId,
                    .incoming => {},
                }
                const expected_peer_tx_id = txs.items(.peer_tx_id)[index];
                if (expected_peer_tx_id != .new and expected_peer_tx_id != peer_tx_id) return error.WrongPeerTxId;

                break :blk txs.items(.data)[index];
            };

            switch (data) {
                .send_file => |*send_file| try host.incomingSendFile(
                    send_file,
                    tx_id,
                    peer_tx_id,
                    action,
                    io,
                ),
                .receive_file => |*receive_file| try host.incomingReceiveFile(
                    receive_file,
                    tx_id,
                    action,
                    io,
                    reader,
                ),
            }
        }
    }

    fn newIncomingReceiveFile(
        host: *Host,
        peer_tx_id: network.TransactionId,
        io: Io,
        reader: *Io.Reader,
    ) !void {
        var file_path_buffer: network.FilePathBuffer align(@alignOf(w.WCHAR)) = undefined;
        const metadata = try network.receiveFileMetadata(reader, &file_path_buffer);
        const file_path, const comparison = try host.db.checkMetadata(&metadata, &file_path_buffer, io);

        const decision: Transaction.Data.ReceiveFile.State.SendDecision =
            switch (comparison) {
                .equals => .decline,
                .differs => .accept,
            };

        const data: Transaction.Data = .{
            .receive_file = .{
                .state = .{ .send_decision = decision },
                .path = file_path,
                .size = @as(w.LARGE_INTEGER, @intCast(metadata.file_size)),
                .hash = metadata.hash,
            },
        };
        try host.addOutgoingTx(io, data, peer_tx_id);
    }

    fn incomingSendFile(
        host: *Host,
        send_file: *const Transaction.Data.SendFile,
        tx_id: network.TransactionId,
        peer_tx_id: network.TransactionId,
        action: network.Action,
        io: Io,
    ) !void {
        switch (send_file.state) {
            .receive_decision => switch (action) {
                .transfer_file_accept => {
                    try host.flipTransaction(.outgoing, tx_id, .send_file, .send_file_contents, peer_tx_id, io);
                },
                .transfer_file_decline => try host.deleteTransaction(io, tx_id, .incoming),
                else => return error.InvalidAction,
            },
            .receive_result => {
                switch (action) {
                    .transfer_file_success, .transfer_file_failure => try host.deleteTransaction(io, tx_id, .incoming),
                    else => return error.InvalidAction,
                }
            },
            else => unreachable,
        }
    }

    fn incomingReceiveFile(
        host: *Host,
        receive_file: *const Transaction.Data.ReceiveFile,
        tx_id: network.TransactionId,
        action: network.Action,
        io: Io,
        reader: *Io.Reader,
    ) !void {
        switch (receive_file.state) {
            .receive_file_contents => switch (action) {
                .transfer_file_contents => {
                    try host.db.receiveFile(receive_file, reader, io);

                    try host.flipTransaction(.outgoing, tx_id, .receive_file, .{ .send_result = .success }, null, io);
                },
                else => return error.InvalidAction,
            },
            .send_decision, .send_result => unreachable,
        }
    }
};
