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

    pub fn init(sync_dir_path: Wtf16, io: Io, sync_dir_path_wtf8: []const u8, allocator: Allocator) !Database {
        if (!std.fs.path.isAbsoluteWindowsWtf16(sync_dir_path.slice)) return error.NonAbsoluteSyncDirPath;
        const sync_dir = blk: {
            // TODO: Proper Win32 -> NT path conversion
            const normalized = try std.mem.concat(allocator, w.WCHAR, &.{ wtf16("\\??\\"), sync_dir_path.slice });
            defer allocator.free(normalized);
            break :blk try openDir(null, .wtf16Cast(normalized));
        };
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
                .little => .wtf16Cast(@ptrCast(file_path_buffer[0..metadata.path_byte_count])),
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

    fn openFileReadOnly(db: *const Database, io: Io, path: Wtf16) !w.HANDLE {
        // try db.mutex.lock(io);
        // defer db.mutex.unlock(io);
        _ = .{ db, io };
        return openFile(db.sync_dir, path, .read);
    }

    fn createFile(db: *const Database, io: Io, path: Wtf16, file_size: w.LARGE_INTEGER) !w.HANDLE {
        // try db.mutex.lock(io);
        // defer db.mutex.unlock(io);
        _ = .{ db, io };
        return openFile(
            db.sync_dir,
            path,
            .{ .create = .{ .initial_size = file_size } },
        );
    }

    fn closeFile(_: *const Database, file: w.HANDLE) void {
        w.CloseHandle(file);
    }

    fn updateReceivedFile(
        db: *Database,
        io: Io,
        handle: w.HANDLE,
        path: Wtf16,
        hash: *const network.FileHash,
        file_size: w.LARGE_INTEGER,
    ) !void {
        const information = blk: {
            var iosb: w.IO_STATUS_BLOCK = undefined;
            var information: w.FILE.BASIC_INFORMATION = undefined;
            const status = w.ntdll.NtQueryInformationFile(
                handle,
                &iosb,
                &information,
                @sizeOf(@TypeOf(information)),
                .Basic,
            );
            switch (status) {
                .SUCCESS => break :blk information,
                else => return w.unexpectedStatus(status),
            }
        };

        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        try db.all_known_files.put(db.allocator, path, .{
            .hash = hash.*,
            .modified_time = information.ChangeTime,
            .size = file_size,
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
            // const transaction_data: TxData = .{
            //     .send_file = .{
            //         .state = .send_metadata,
            //         .path = entry.key_ptr.*,
            //         .size = entry.value_ptr.size,
            //         .hash = entry.value_ptr.hash,
            //     },
            // };
            const transaction_data: TxData = .{
                .send_new_file = .{
                    .state = .send_path,
                    .path = entry.key_ptr.*,
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
            const file = try openFile(dir, name, .read);
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
        switch (status) {
            .NO_MORE_FILES => break,
            .BUFFER_OVERFLOW => return error.NtBufferOverflow,
            .SUCCESS => if (io_status_block.Information == 0) return error.NtBufferOverflow,
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
    const path_byte_count: w.USHORT = @intCast(@as([]const u8, @ptrCast(path.slice)).len);
    var unicode_string: w.UNICODE_STRING = .{
        .Length = path_byte_count,
        .MaximumLength = path_byte_count,
        .Buffer = @constCast(path.slice.ptr),
    };
    const object_attributes: w.OBJECT.ATTRIBUTES = .{
        .Length = @sizeOf(w.OBJECT.ATTRIBUTES),
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
            .IO = .SYNCHRONOUS_NONALERT,
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

const OpenFileOptions = union(enum) {
    read,
    create: struct {
        initial_size: w.LARGE_INTEGER,
    },
};

fn openFile(parent: ?w.HANDLE, path: Wtf16, options: OpenFileOptions) !w.HANDLE {
    errdefer wave.log.err("Failed to open file: {f}\n", .{path.formatUtf8()});

    var handle: w.HANDLE = undefined;
    const path_byte_count: w.USHORT = @intCast(@as([]const u8, @ptrCast(path.slice)).len);
    var unicode_string: w.UNICODE_STRING = .{
        .Length = path_byte_count,
        .MaximumLength = path_byte_count,
        .Buffer = @constCast(path.slice.ptr),
    };
    const object_attributes: w.OBJECT.ATTRIBUTES = .{
        .Length = @sizeOf(w.OBJECT.ATTRIBUTES),
        .RootDirectory = parent,
        .ObjectName = &unicode_string,
        .Attributes = .{
            .CASE_INSENSITIVE = true,
        },
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    var iosb: w.IO_STATUS_BLOCK = undefined;

    const status = switch (options) {
        .read => w.ntdll.NtOpenFile(
            &handle,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true },
            },
            &object_attributes,
            &iosb,
            .{ .READ = true },
            .{
                .NON_DIRECTORY_FILE = true,
                .IO = .SYNCHRONOUS_NONALERT,
            },
        ),
        .create => |*create| w.ntdll.NtCreateFile(
            &handle,
            .{
                .STANDARD = .{ .SYNCHRONIZE = true },
                .GENERIC = .{ .READ = true, .WRITE = true },
            },
            &object_attributes,
            &iosb,
            &create.initial_size,
            .{ .NORMAL = true },
            .{},
            .OVERWRITE_IF,
            .{
                .NON_DIRECTORY_FILE = true,
                .IO = .SYNCHRONOUS_NONALERT,
            },
            null,
            0,
        ),
    };

    switch (status) {
        .SUCCESS => return handle,
        else => return w.unexpectedStatus(status),
    }
}

const SendFileError = Io.Writer.Error || Io.UnexpectedError;

fn sendFile(
    writer: *Io.Writer,
    handle: w.HANDLE,
    file_size: w.LARGE_INTEGER,
) SendFileError!void {
    // TODO: Actually use sendfile or whatever it is on Windows
    var iosb: w.IO_STATUS_BLOCK = undefined;
    var written: w.LARGE_INTEGER = 0;
    while (written < file_size) {
        const buffer = buffer: {
            const slice = try writer.writableSliceGreedy(1);
            break :buffer slice[0..@min(
                slice.len,
                @as(w.ULARGE_INTEGER, @intCast(file_size - written)),
                std.math.maxInt(w.ULONG),
            )];
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
        switch (status) {
            .SUCCESS => {
                writer.advance(iosb.Information);
                written += @intCast(iosb.Information);
            },
            else => return w.unexpectedStatus(status),
        }
    }
    if (written != file_size) return error.Unexpected;
}

const ReceiveFileError = Io.Reader.Error || Io.UnexpectedError;

fn receiveFile(
    reader: *Io.Reader,
    handle: w.HANDLE,
    file_size: w.LARGE_INTEGER,
) ReceiveFileError!void {
    // TODO: Actually use sendfile or whatever it is on Windows
    var read: w.LARGE_INTEGER = 0;
    var iosb: w.IO_STATUS_BLOCK = undefined;
    while (read < file_size) {
        const buffer = buffer: {
            const slice = try reader.peekGreedy(1);
            break :buffer slice[0..@min(
                slice.len,
                @as(w.ULARGE_INTEGER, @intCast(file_size - read)),
                std.math.maxInt(w.ULONG),
            )];
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
        switch (status) {
            .SUCCESS => {
                reader.toss(iosb.Information);
                read += @intCast(iosb.Information);
            },
            else => return w.unexpectedStatus(status),
        }
    }
    if (read != file_size) return error.Unexpected;
}

fn computeFileHash(file: w.HANDLE, file_size: w.LARGE_INTEGER) !network.FileHash {
    var iosb: w.IO_STATUS_BLOCK = undefined;
    var buffer: [64 * 1024]u8 = undefined;
    var written: w.LARGE_INTEGER = 0;
    var hash: std.crypto.hash.Blake3 = .init(.{});

    while (written < file_size) {
        const status = w.ntdll.NtReadFile(file, null, null, null, &iosb, &buffer, buffer.len, &written, null);
        switch (status) {
            .SUCCESS => {
                hash.update((&buffer)[0..iosb.Information]);
                written += @intCast(iosb.Information);
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
    tx: Transaction,
    db: *Database,
    debug: Debug,

    pub const Debug = struct {
        name: ?[]const u8 = null,
    };

    pub const Transaction = struct {
        // This is align(4) so that we can `futexWait` on it.
        direction: std.atomic.Value(Direction) align(4),
        data: TxData,
        peer_tx_id: network.TransactionId,

        pub const Direction = enum(u32) { not_in_use, init, outgoing, incoming };
    };

    pub const TxQueue = Io.Queue(TxData);

    pub fn init(db: *Database, debug: Debug) Host {
        return .{
            .tx = .{
                .direction = .init(.not_in_use),
                .data = undefined,
                .peer_tx_id = undefined,
            },
            .db = db,
            .debug = debug,
        };
    }

    pub fn deinit(host: *Host) void {
        host.* = undefined;
    }

    pub const RunError = Io.ConcurrentError || Io.Cancelable;

    pub const Diagnostics = struct {
        read_tx_queue: ?ReadTxQueueError = null,
        outgoing: ?OutgoingError = null,
        incoming: ?IncomingError = null,
    };

    /// Blocks until the `Host` is finished running.
    pub fn run(
        host: *Host,
        diag: ?*Diagnostics,
        io: Io,
        tx_queue: *TxQueue,
        reader: *Io.Reader,
        writer: *Io.Writer,
    ) RunError!void {
        const ns = struct {
            const SelectUnion = union(enum) {
                read_tx_queue: ReadTxQueueError!void,
                outgoing: OutgoingError!void,
                incoming: IncomingError!void,
            };

            fn addToDiagnostics(d: ?*Diagnostics, u: SelectUnion) void {
                const ptr = d orelse return;
                switch (u) {
                    inline else => |payload, tag| {
                        @field(ptr, @tagName(tag)) = if (payload) |_| null else |err| err;
                    },
                }
            }
        };

        var select_buffer: [3]ns.SelectUnion = undefined;
        var select = Io.Select(ns.SelectUnion).init(io, &select_buffer);
        defer while (select.cancel()) |result| ns.addToDiagnostics(diag, result);

        try select.concurrent(.read_tx_queue, readTxQueue, .{ host, tx_queue, io });
        try select.concurrent(.outgoing, sendOutgoingTxs, .{ host, writer, io });
        try select.concurrent(.incoming, receiveIncomingTxs, .{ host, reader, io });

        host.debugLog("started", .{});
        ns.addToDiagnostics(diag, try select.await());
    }

    pub const ReadTxQueueError = Io.QueueClosedError || Io.Cancelable || AddOutgoingTxError;

    fn readTxQueue(host: *Host, tx_queue: *TxQueue, io: Io) ReadTxQueueError!void {
        defer tx_queue.close(io);
        while (true) {
            const data = try tx_queue.getOne(io);
            try host.addOutgoingTx(io, data, null);
        }
    }

    pub const OutgoingError = Io.Writer.Error || Io.Cancelable || SendFileError;

    fn sendOutgoingTxs(host: *Host, writer: *Io.Writer, io: Io) OutgoingError!void {
        while (true) {
            var direction = host.tx.direction.load(.monotonic);
            while (direction != .outgoing) {
                try io.futexWait(Transaction.Direction, &host.tx.direction.raw, direction);
                direction = host.tx.direction.load(.monotonic);
            }

            const tx_id: network.TransactionId = @enumFromInt(0); // TODO hardcoded value
            switch (host.tx.data) {
                .send_new_file => |*send_new_file| switch (send_new_file.state) {
                    .send_path => try send_new_file.sendPath(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_decision => unreachable,
                },
                .receive_new_file => |*receive_new_file| {
                    try receive_new_file.sendDecision(host, tx_id, host.tx.peer_tx_id, io, writer);
                },
                .send_file => |*send_file| switch (send_file.state) {
                    .send_metadata => try send_file.sendMetadata(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .send_file_contents => try send_file.sendFileContents(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_decision, .receive_result => unreachable,
                },
                .receive_file => |*receive_file| switch (receive_file.state) {
                    .send_decision => try receive_file.sendDecision(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .send_result => try receive_file.sendResult(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_file_contents => unreachable,
                },
            }
        }
    }

    pub const IncomingError = error{
        InvalidTxId,
        InvalidPeerTxId,
        WrongTxId,
        WrongPeerTxId,
        InvalidAction,
        InvalidHeader,
    } || wave.network.ReceiveActionError || wave.network.ReceiveFileMetadataError || Io.Reader.StreamError ||
        Io.Cancelable || Allocator.Error || AddOutgoingTxError || ReceiveFileError;

    fn receiveIncomingTxs(host: *Host, reader: *Io.Reader, io: Io) IncomingError!void {
        while (true) {
            const header = try network.receiveMessageHeader(reader);
            if (header.tag == .disconnect) break;
            const action = try network.receiveAction(reader);
            host.logMessage(.incoming, header.tx_id, action, header.peer_tx_id);

            switch (header.tag) {
                .disconnect => unreachable,
                .new_tx => {
                    if (header.tx_id != .invalid) return error.InvalidTxId;
                    if (header.peer_tx_id == .invalid) return error.InvalidPeerTxId;
                    switch (action) {
                        .new_file_init => {
                            try TxData.ReceiveNewFile.newTx(host, header.peer_tx_id, io, reader);
                        },
                        .transfer_file_metadata => {
                            try TxData.ReceiveFile.newTx(host, header.peer_tx_id, io, reader);
                        },
                        else => return error.InvalidAction,
                    }
                },
                .new_tx_reply => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
                    if (host.tx.direction.load(.monotonic) != .incoming) return error.InvalidTxId;
                    if (host.tx.peer_tx_id != .invalid) return error.WrongPeerTxId;

                    switch (host.tx.data) {
                        .send_new_file => |*send_new_file| switch (send_new_file.state) {
                            .receive_decision => {
                                try send_new_file.receiveDecision(
                                    host,
                                    reader,
                                    io,
                                    header.tx_id,
                                    header.peer_tx_id,
                                    action,
                                );
                            },
                            .send_path => unreachable,
                        },
                        .receive_new_file => unreachable,
                        .send_file => |*send_file| switch (send_file.state) {
                            .receive_decision => {
                                try send_file.receiveDecision(
                                    host,
                                    reader,
                                    io,
                                    header.tx_id,
                                    header.peer_tx_id,
                                    action,
                                );
                            },
                            .receive_result => return error.InvalidHeader,
                            .send_metadata, .send_file_contents => unreachable,
                        },
                        .receive_file => |*receive_file| switch (receive_file.state) {
                            .receive_file_contents => return error.InvalidHeader,
                            .send_decision, .send_result => unreachable,
                        },
                    }
                },
                .existing_tx => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
                    if (host.tx.direction.load(.monotonic) != .incoming) return error.InvalidTxId;
                    if (header.peer_tx_id != .invalid) return error.WrongPeerTxId;

                    switch (host.tx.data) {
                        .send_new_file => |*send_new_file| switch (send_new_file.state) {
                            .receive_decision => return error.InvalidHeader,
                            .send_path => unreachable,
                        },
                        .receive_new_file => unreachable,
                        .send_file => |*send_file| switch (send_file.state) {
                            .receive_decision => return error.InvalidHeader,
                            .receive_result => {
                                try send_file.receiveResult(host, reader, io, header.tx_id, action);
                            },
                            .send_metadata, .send_file_contents => unreachable,
                        },
                        .receive_file => |*receive_file| switch (receive_file.state) {
                            .receive_file_contents => {
                                try receive_file.receiveFileContents(host, reader, io, header.tx_id, action);
                            },
                            .send_decision, .send_result => unreachable,
                        },
                    }
                },
            }
        }
    }

    const AddOutgoingTxError = error{NoTxSlotsAvailable};

    fn addOutgoingTx(
        host: *Host,
        io: Io,
        data: TxData,
        peer_tx_id: ?network.TransactionId,
    ) AddOutgoingTxError!void {
        if (host.tx.direction.cmpxchgStrong(.not_in_use, .init, .acquire, .monotonic) != null) {
            return error.NoTxSlotsAvailable;
        }
        host.tx.data = data;
        host.tx.peer_tx_id = peer_tx_id orelse .invalid;
        host.tx.direction.store(.outgoing, .release);
        io.futexWake(Transaction.Direction, &host.tx.direction.raw, 1);
    }

    fn flipTransaction(
        host: *Host,
        comptime to: Transaction.Direction,
        tx_id: network.TransactionId,
        io: Io,
    ) void {
        assert(@intFromEnum(tx_id) == 0); // TODO: hardcoded value
        const from = &host.tx.direction;
        switch (to) {
            .not_in_use, .init => unreachable,
            .outgoing => {
                assert(from.swap(to, .release) == .incoming);
                io.futexWake(Transaction.Direction, &from.raw, 1);
            },
            .incoming => {
                assert(from.swap(to, .release) == .outgoing);
            },
        }
    }

    fn deleteTransaction(host: *Host, tx_id: network.TransactionId, expected_direction: Transaction.Direction) void {
        assert(@intFromEnum(tx_id) == 0); // TODO
        host.tx.data = undefined;
        host.tx.peer_tx_id = undefined;
        assert(host.tx.direction.swap(.not_in_use, .release) == expected_direction);
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
            .not_in_use, .init => unreachable,
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
};

pub const TxData = union(enum) {
    send_new_file: SendNewFile,
    receive_new_file: ReceiveNewFile,

    send_file: SendFile,
    receive_file: ReceiveFile,

    pub const SendNewFile = struct {
        state: State,
        path: Wtf16,

        pub const State = enum {
            send_path,
            receive_decision,
        };

        fn sendPath(
            send_new_file: *SendNewFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(send_new_file.state == .send_path);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .new_file_init;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTx(writer, tx_id);
            try network.sendAction(writer, action);
            try network.sendNewFilePath(
                writer,
                switch (cpu_endian) {
                    .big => @compileError("TODO big endian"),
                    .little => .wtf16le,
                },
                @ptrCast(send_new_file.path.slice),
            );
            try writer.flush();

            send_new_file.state = .receive_decision;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveDecision(
            send_new_file: *const SendNewFile,
            host: *Host,
            reader: *Io.Reader,
            _: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(send_new_file.state == .receive_decision);
            if (peer_tx_id != .invalid) return error.InvalidPeerTxId;

            switch (action) {
                .new_file_response => {
                    const file_id = try network.receiveFileId(reader);
                    host.debugLog("received file id: {}\n", .{file_id});
                    host.deleteTransaction(tx_id, .incoming);
                },
                else => return error.InvalidAction,
            }
        }
    };

    pub const ReceiveNewFile = struct {
        file_id: network.FileId,

        fn newTx(
            host: *Host,
            peer_tx_id: network.TransactionId,
            io: Io,
            reader: *Io.Reader,
        ) !void {
            var file_path_buffer: network.FilePathBuffer align(@alignOf(w.WCHAR)) = undefined;
            const path_info = try network.receiveNewFilePath(reader, &file_path_buffer);
            _ = path_info;

            const data: TxData = .{
                .receive_new_file = .{
                    .file_id = 0, // TODO hardcoded value
                },
            };
            try host.addOutgoingTx(io, data, peer_tx_id);
        }

        fn sendDecision(
            receive_new_file: *const ReceiveNewFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            _: Io,
            writer: *Io.Writer,
        ) !void {
            assert(peer_tx_id != .invalid);

            const action: network.Action = .new_file_response;
            const outgoing_tx_id: network.TransactionId = .invalid;
            host.logMessage(.outgoing, outgoing_tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTxReply(writer, outgoing_tx_id, peer_tx_id);
            try network.sendAction(writer, action);
            try network.sendFileId(writer, receive_new_file.file_id);
            try writer.flush();

            host.deleteTransaction(tx_id, .outgoing);
        }
    };

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

        fn sendMetadata(
            send_file: *SendFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(send_file.state == .send_metadata);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .transfer_file_metadata;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            const file_size = std.math.cast(network.FileSize, send_file.size) orelse
                std.debug.panic(
                    "TODO: File too large to transfer: '{f}' with size {}",
                    .{ send_file.path.formatUtf8(), send_file.size },
                );
            try network.sendMessageHeaderNewTx(writer, tx_id);
            try network.sendAction(writer, action);
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

            send_file.state = .receive_decision;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveDecision(
            send_file: *SendFile,
            host: *Host,
            _: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(send_file.state == .receive_decision);

            switch (action) {
                .transfer_file_accept => {
                    if (peer_tx_id == .invalid) return error.WrongPeerTxId;
                    send_file.state = .send_file_contents;
                    host.tx.peer_tx_id = peer_tx_id;
                    host.flipTransaction(.outgoing, tx_id, io);
                },
                .transfer_file_decline => {
                    if (peer_tx_id != .invalid) return error.WrongPeerTxId;
                    host.deleteTransaction(tx_id, .incoming);
                },
                else => return error.InvalidAction,
            }
        }

        fn sendFileContents(
            send_file: *SendFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(send_file.state == .send_file_contents);

            const action: network.Action = .transfer_file_contents;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            const handle = try host.db.openFileReadOnly(io, send_file.path);
            defer host.db.closeFile(handle);

            try network.sendMessageHeaderExistingTx(writer, peer_tx_id);
            try network.sendAction(writer, action);
            try sendFile(writer, handle, send_file.size);
            try writer.flush();

            send_file.state = .receive_result;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveResult(
            _: *const SendFile,
            host: *Host,
            _: *Io.Reader,
            _: Io,
            tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            switch (action) {
                .transfer_file_success, .transfer_file_failure => host.deleteTransaction(tx_id, .incoming),
                else => return error.InvalidAction,
            }
        }
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

        fn newTx(
            host: *Host,
            peer_tx_id: network.TransactionId,
            io: Io,
            reader: *Io.Reader,
        ) !void {
            var file_path_buffer: network.FilePathBuffer align(@alignOf(w.WCHAR)) = undefined;
            const metadata = try network.receiveFileMetadata(reader, &file_path_buffer);
            const file_path, const comparison = try host.db.checkMetadata(&metadata, &file_path_buffer, io);

            const decision: State.SendDecision =
                switch (comparison) {
                    .equals => .decline,
                    .differs => .accept,
                };

            const data: TxData = .{
                .receive_file = .{
                    .state = .{ .send_decision = decision },
                    .path = file_path,
                    .size = @as(w.LARGE_INTEGER, @intCast(metadata.file_size)),
                    .hash = metadata.hash,
                },
            };
            try host.addOutgoingTx(io, data, peer_tx_id);
        }

        fn sendDecision(
            receive_file: *ReceiveFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(receive_file.state == .send_decision);
            assert(peer_tx_id != .invalid);

            const actual_tx_id: network.TransactionId, const action: network.Action =
                switch (receive_file.state.send_decision) {
                    .accept => .{ tx_id, .transfer_file_accept },
                    .decline => .{ .invalid, .transfer_file_decline },
                };
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTxReply(writer, actual_tx_id, peer_tx_id);
            try network.sendAction(writer, action);
            try writer.flush();

            switch (receive_file.state.send_decision) {
                .accept => {
                    receive_file.state = .receive_file_contents;
                    host.flipTransaction(.incoming, tx_id, io);
                },
                .decline => host.deleteTransaction(tx_id, .outgoing),
            }
        }

        fn receiveFileContents(
            receive_file: *ReceiveFile,
            host: *Host,
            reader: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(receive_file.state == .receive_file_contents);
            switch (action) {
                .transfer_file_contents => {
                    const handle = try host.db.createFile(io, receive_file.path, receive_file.size);
                    defer host.db.closeFile(handle);
                    try receiveFile(reader, handle, receive_file.size);
                    try host.db.updateReceivedFile(
                        io,
                        handle,
                        receive_file.path,
                        &receive_file.hash,
                        receive_file.size,
                    );

                    receive_file.state = .{ .send_result = .success };
                    host.flipTransaction(.outgoing, tx_id, io);
                },
                else => return error.InvalidAction,
            }
        }

        fn sendResult(
            receive_file: *const ReceiveFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            _: Io,
            writer: *Io.Writer,
        ) !void {
            assert(receive_file.state == .send_result);
            assert(peer_tx_id != .invalid);

            const action: network.Action = switch (receive_file.state.send_result) {
                .success => .transfer_file_success,
                .failure => .transfer_file_failure,
            };
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderExistingTx(writer, peer_tx_id);
            try network.sendAction(writer, action);
            try writer.flush();

            host.deleteTransaction(tx_id, .outgoing);
        }
    };
};
