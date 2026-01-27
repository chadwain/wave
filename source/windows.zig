const std = @import("std");
const assert = std.debug.assert;
const panic = std.debug.panic;
const w = std.os.windows;
const wtf16 = std.unicode.wtf8ToWtf16LeStringLiteral;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const wave = @import("wave.zig");
const network = wave.network;

/// A WTF-16 encoded string, with the endianness of the host system.
pub const Wtf16 = struct {
    slice: []const w.WCHAR,

    pub fn wtf16Cast(slice: []const w.WCHAR) Wtf16 {
        return .{ .slice = slice };
    }

    pub fn byteLen(self: Wtf16) usize {
        return self.slice.len * @sizeOf(w.WCHAR);
    }

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

    pub fn formatUtf8(self: Wtf16Z) std.fmt.Alt([]const w.WCHAR, formatWtf16AsUtf8) {
        return .{ .data = self.slice };
    }
};

fn formatWtf16AsUtf8(slice: []const w.WCHAR, writer: *Io.Writer) Io.Writer.Error!void {
    switch (comptime @import("builtin").cpu.arch.endian()) {
        .little => try writer.print("{f}", .{std.unicode.fmtUtf16Le(slice)}),
        .big => @compileError("TODO big endian"),
    }
}

pub const Database = struct {
    sync_dir: w.HANDLE,
    allocator: Allocator,
    file_path_arena: std.heap.ArenaAllocator.State = .{},
    all_known_files: FileHashMap(Entry) = .empty,
    files_needing_sync: FileHashMap(void) = .empty,
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

    pub fn init(sync_dir_path: Wtf16Z, allocator: Allocator) !Database {
        const sync_dir = try openSyncDir(sync_dir_path);
        errdefer comptime unreachable;
        return .{
            .sync_dir = sync_dir,
            .allocator = allocator,
            .file_path_arena = .{},
            .all_known_files = .empty,
            .files_needing_sync = .empty,
            .debug = .{},
        };
    }

    pub fn deinit(db: *Database) void {
        w.CloseHandle(db.sync_dir);
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

        pub fn clientTransferFile(debug: *const Debug, io: Io, client: *Client, index: usize) !void {
            const db: *const Database = @alignCast(@fieldParentPtr("debug", debug));
            const entry = blk: {
                var it = db.all_known_files.iterator();
                for (0..index) |_| _ = it.next().?;
                break :blk it.next().?;
            };
            const transaction: Client.Transaction = .{
                .transfer_file = .{
                    .peer_id = .new,
                    .state = .send_metadata,
                    .path = entry.key_ptr.*,
                    .size = entry.value_ptr.size,
                    .hash = entry.value_ptr.hash,
                },
            };
            try client.insertTransaction(io, transaction, .send);
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

pub fn completeScan(db: *Database, allocator: Allocator) !void {
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

pub const Client = struct {
    send_task: Io.Future(@typeInfo(@TypeOf(send)).@"fn".return_type.?),
    receive_task: Io.Future(@typeInfo(@TypeOf(receive)).@"fn".return_type.?),
    transactions: std.AutoArrayHashMapUnmanaged(network.TransactionId, Transaction),
    next_tx_id: ?std.meta.Tag(network.TransactionId),
    transaction_owner: std.ArrayList(TransactionOwner),
    send_count: std.atomic.Value(u32),
    receive_count: std.atomic.Value(u32),
    transactions_mutex: Io.Mutex,
    allocator: Allocator,
    db: *const Database,

    pub const TransactionOwner = enum { send, receive };

    pub const Transaction = union(enum) {
        transfer_file: TransferFile,
        receive_file: ReceiveFile,

        const TransferFile = struct {
            peer_id: network.TransactionId,
            state: State,
            path: Wtf16,
            size: w.LARGE_INTEGER,
            hash: network.FileHash,

            const State = enum { send_metadata, receive_decision, send_file_contents, receive_confirmation };
        };

        const ReceiveFile = struct {
            peer_id: network.TransactionId,
            state: State,
            path: Wtf16,
            size: w.LARGE_INTEGER,
            hash: network.FileHash,

            const State = union(enum) {
                send_decision: enum { yes, no },
                receive_file_contents,
                send_confirmation,
            };
        };
    };

    pub fn init(db: *const Database, allocator: Allocator) Client {
        return .{
            .send_task = undefined,
            .receive_task = undefined,
            .transactions = .empty,
            .next_tx_id = 0,
            .transaction_owner = .empty,
            .send_count = .init(0),
            .receive_count = .init(0),
            .transactions_mutex = .init,
            .allocator = allocator,
            .db = db,
        };
    }

    pub fn deinit(client: *Client) void {
        client.transactions.deinit(client.allocator);
        client.transaction_owner.deinit(client.allocator);
        client.* = undefined;
    }

    pub fn insertTransaction(client: *Client, io: Io, transaction: Transaction, owner: TransactionOwner) !void {
        try client.transactions_mutex.lock(io);
        defer client.transactions_mutex.unlock(io);

        const next_tx_id = client.next_tx_id orelse return error.OutOfTransactionIds;
        client.next_tx_id = std.math.add(std.meta.Tag(network.TransactionId), next_tx_id, 1) catch null;
        errdefer client.next_tx_id = next_tx_id;

        const gop = try client.transactions.getOrPut(client.allocator, @enumFromInt(next_tx_id));
        assert(!gop.found_existing);
        errdefer client.transactions.orderedRemoveAt(gop.index);
        gop.value_ptr.* = transaction;

        try client.transaction_owner.insert(client.allocator, gop.index, owner);
        errdefer comptime unreachable;

        switch (owner) {
            .send => client.addSendTransaction(io),
            .receive => _ = client.receive_count.fetchAdd(1, .seq_cst),
        }
    }

    fn addSendTransaction(client: *Client, io: Io) void {
        const previous_send_count = client.send_count.fetchAdd(1, .seq_cst);
        if (previous_send_count == 0) io.futexWake(u32, &client.send_count.raw, 1);
    }

    pub fn start(client: *Client, io: Io, in: *Io.Reader, out: *Io.Writer) !void {
        var send_task = try io.concurrent(send, .{ client, io, out });
        errdefer send_task.cancel(io) catch {};
        const receive_task = try io.concurrent(receive, .{ client, io, in });
        errdefer comptime unreachable;

        client.send_task = send_task;
        client.receive_task = receive_task;
    }

    pub fn stop(client: *Client, io: Io) void {
        client.send_task.cancel(io) catch {};
        client.receive_task.cancel(io) catch {};
        client.send_task = undefined;
        client.receive_task = undefined;
    }

    fn getTransaction(client: *Client, io: Io, comptime owner: TransactionOwner) !usize {
        try client.transactions_mutex.lock(io);
        defer client.transactions_mutex.unlock(io);

        for (0..client.transactions.count()) |tx_index| {
            if (client.transaction_owner.items[tx_index] == owner) {
                return tx_index;
            }
        }
        unreachable;
    }

    fn send(client: *Client, io: Io, writer: *Io.Writer) !void {
        while (true) {
            // TODO: Learn a thing or two about atomic orderings and pick something other than seq_cst
            while (client.send_count.load(.seq_cst) == 0) {
                try io.futexWait(u32, &client.send_count.raw, 0);
            }

            const transaction_index = try client.getTransaction(io, .send);
            const transaction_id = client.transactions.keys()[transaction_index];
            const transaction = client.transactions.values()[transaction_index];
            _ = client.send_count.fetchSub(1, .seq_cst);

            switch (transaction) {
                .transfer_file => |*transfer_file| try client.sendTransferFileTransaction(
                    transaction_id,
                    transfer_file,
                    io,
                    writer,
                ),
                .receive_file => |*receive_file| try client.sendReceiveFileTransaction(
                    transaction_id,
                    receive_file,
                    io,
                    writer,
                ),
            }
        }
    }

    fn sendTransferFileTransaction(
        client: *Client,
        transaction_id: network.TransactionId,
        transfer_file: *const Transaction.TransferFile,
        io: Io,
        writer: *Io.Writer,
    ) !void {
        const next_state: Transaction.TransferFile.State = blk: switch (transfer_file.state) {
            .send_metadata => {
                errdefer std.debug.panic("TODO: Client send error", .{});
                const file_size = std.math.cast(network.FileSize, transfer_file.size) orelse
                    std.debug.panic(
                        "TODO: File too large to transfer: '{f}' with size {}",
                        .{ transfer_file.path.formatUtf8(), transfer_file.size },
                    );
                try network.sendTransactionId(writer, .new);
                try network.sendTransactionId(writer, transaction_id);
                try network.sendAction(writer, .transfer_file_metadata);
                try network.sendTransferFileMetadata(
                    writer,
                    .wtf16le,
                    @ptrCast(transfer_file.path.slice),
                    file_size,
                    &transfer_file.hash,
                );
                try writer.flush();
                break :blk .receive_decision;
            },
            .send_file_contents => {
                errdefer std.debug.panic("TODO: Client send error", .{});
                // TODO: Probably a good idea to make Database act as a middleman for opening files
                const handle = try openFile(client.db.sync_dir, transfer_file.path);
                defer w.CloseHandle(handle);
                try network.sendTransactionId(writer, transfer_file.peer_id);
                try network.sendTransactionId(writer, transaction_id);
                try network.sendAction(writer, .transfer_file_contents);

                var iosb: w.IO_STATUS_BLOCK = undefined;
                var written: w.LARGE_INTEGER = 0;
                while (written < transfer_file.size) {
                    const buffer = buffer: {
                        const slice = try writer.writableSliceGreedy(1);
                        break :buffer slice[0..@min(slice.len, std.math.maxInt(u32))];
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
                assert(written == transfer_file.size);
                try writer.flush();
                break :blk .receive_confirmation;
            },
            .receive_decision, .receive_confirmation => unreachable,
        };

        try client.transactions_mutex.lock(io);
        defer client.transactions_mutex.unlock(io);

        const gop = client.transactions.getOrPutAssumeCapacity(transaction_id);
        assert(gop.found_existing);
        gop.value_ptr.transfer_file.state = next_state;
        client.transaction_owner.items[gop.index] = .receive;
        _ = client.receive_count.fetchAdd(1, .seq_cst);
    }

    fn sendReceiveFileTransaction(
        client: *Client,
        transaction_id: network.TransactionId,
        receive_file: *const Transaction.ReceiveFile,
        io: Io,
        writer: *Io.Writer,
    ) !void {
        switch (receive_file.state) {
            .send_decision => |send_decision| {
                errdefer std.debug.panic("TODO: Client send error", .{});
                try network.sendTransactionId(writer, receive_file.peer_id);
                try network.sendTransactionId(writer, transaction_id);
                try network.sendAction(writer, switch (send_decision) {
                    .yes => .transfer_file_decision_yes,
                    .no => .transfer_file_decision_no,
                });
                try writer.flush();

                try client.transactions_mutex.lock(io);
                defer client.transactions_mutex.unlock(io);

                const tx_index = client.transactions.getIndex(transaction_id).?;
                client.transactions.values()[tx_index].receive_file.state = .receive_file_contents;
                client.transaction_owner.items[tx_index] = .receive;
                _ = client.receive_count.fetchAdd(1, .seq_cst);
            },
            .send_confirmation => {
                errdefer std.debug.panic("TODO: Client send error", .{});
                try network.sendTransactionId(writer, receive_file.peer_id);
                try network.sendTransactionId(writer, transaction_id);
                try network.sendAction(writer, .transfer_file_confirmation);

                try client.transactions_mutex.lock(io);
                defer client.transactions_mutex.unlock(io);

                const tx_index = client.transactions.getIndex(transaction_id).?;
                client.transactions.orderedRemoveAt(tx_index);
                assert(client.transaction_owner.orderedRemove(tx_index) == .send);
            },
            .receive_file_contents => unreachable,
        }
    }

    fn receive(client: *Client, io: Io, reader: *Io.Reader) !void {
        while (true) {
            const tx_id = try network.receiveTransactionId(reader) orelse break;
            const peer_tx_id = try network.receiveTransactionId(reader) orelse panic("bad tx id", .{});
            const action = try network.receiveAction(reader);

            switch (action) {
                .transfer_file_metadata => {
                    if (tx_id != .new) panic("invalid tx id", .{});
                    try client.receiveTransferFileMetadataAction(io, reader, peer_tx_id);
                    continue;
                },
                else => {},
            }

            const transaction = blk: {
                try client.transactions_mutex.lock(io);
                defer client.transactions_mutex.unlock(io);

                const transaction_index = client.transactions.getIndex(tx_id) orelse panic("nonexistent transaction", .{});
                switch (client.transaction_owner.items[transaction_index]) {
                    .send => panic("transaction is in the send state", .{}),
                    .receive => {},
                }
                break :blk client.transactions.values()[transaction_index];
            };
            _ = client.receive_count.fetchSub(1, .seq_cst);

            switch (transaction) {
                .transfer_file => |*transfer_file| try client.receiveTransferFileTransaction(
                    tx_id,
                    transfer_file,
                    io,
                    action,
                    peer_tx_id,
                ),
                .receive_file => |*receive_file| try client.receiveReceiveFileTransaction(
                    tx_id,
                    receive_file,
                    io,
                    reader,
                    action,
                    peer_tx_id,
                ),
            }
        }
    }

    fn receiveTransferFileMetadataAction(
        client: *Client,
        io: Io,
        reader: *Io.Reader,
        peer_tx_id: network.TransactionId,
    ) !void {
        var file_path_buffer: [256]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&file_path_buffer);
        const metadata = try network.receiveTransferFileMetadata(reader, fba.allocator());
        const transaction: Transaction = .{
            .receive_file = .{
                .peer_id = peer_tx_id,
                .state = .{ .send_decision = .yes },
                .path = .wtf16Cast(&.{}),
                .size = @as(w.LARGE_INTEGER, @intCast(metadata.file_size)),
                .hash = metadata.hash,
            },
        };
        try client.insertTransaction(io, transaction, .send);
    }

    fn receiveTransferFileTransaction(
        client: *Client,
        tx_id: network.TransactionId,
        transfer_file: *const Transaction.TransferFile,
        io: Io,
        action: network.Action,
        peer_tx_id: network.TransactionId,
    ) !void {
        if (peer_tx_id != transfer_file.peer_id) panic("mismatched peer id", .{});

        switch (transfer_file.state) {
            .receive_decision => switch (action) {
                .transfer_file_decision_no => {
                    try client.transactions_mutex.lock(io);
                    defer client.transactions_mutex.unlock(io);

                    const tx_index = client.transactions.getIndex(tx_id).?;
                    client.transactions.orderedRemoveAt(tx_index);
                    assert(client.transaction_owner.orderedRemove(tx_index) == .receive);
                },
                .transfer_file_decision_yes => {
                    try client.transactions_mutex.lock(io);
                    defer client.transactions_mutex.unlock(io);

                    const tx_index = client.transactions.getIndex(tx_id).?;
                    client.transactions.values()[tx_index].transfer_file.state = .send_file_contents;
                    client.transaction_owner.items[tx_index] = .send;
                    client.addSendTransaction(io);
                },
                else => panic("invalid server action", .{}),
            },
            .receive_confirmation => switch (action) {
                .transfer_file_confirmation => {
                    try client.transactions_mutex.lock(io);
                    defer client.transactions_mutex.unlock(io);

                    const tx_index = client.transactions.getIndex(tx_id).?;
                    client.transactions.orderedRemoveAt(tx_index);
                    assert(client.transaction_owner.orderedRemove(tx_index) == .receive);
                },
                else => panic("invalid server action", .{}),
            },
            else => unreachable,
        }
    }

    fn receiveReceiveFileTransaction(
        client: *Client,
        tx_id: network.TransactionId,
        receive_file: *const Transaction.ReceiveFile,
        io: Io,
        reader: *Io.Reader,
        action: network.Action,
        peer_tx_id: network.TransactionId,
    ) !void {
        if (peer_tx_id != receive_file.peer_id) panic("mismatched peer id", .{});

        switch (receive_file.state) {
            .receive_file_contents => switch (action) {
                .transfer_file_contents => {
                    reader.discardAll(@intCast(receive_file.size)) catch |err| switch (err) {
                        error.ReadFailed => |e| return e,
                        error.EndOfStream => panic("file transfer failed", .{}),
                    };

                    try client.transactions_mutex.lock(io);
                    defer client.transactions_mutex.unlock(io);

                    const tx_index = client.transactions.getIndex(tx_id).?;
                    client.transactions.values()[tx_index].receive_file.state = .send_confirmation;
                    client.transaction_owner.items[tx_index] = .send;
                    client.addSendTransaction(io);
                },
                else => panic("invalid action", .{}),
            },
            .send_decision, .send_confirmation => unreachable,
        }
    }
};
