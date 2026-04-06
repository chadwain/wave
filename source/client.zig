const std = @import("std");
const assert = std.debug.assert;
const w = std.os.windows;
const wtf16 = std.unicode.wtf8ToWtf16LeStringLiteral;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const wave = @import("wave.zig");
const network = wave.network;
const Wtf16 = wave.windows.Wtf16;
const Win32RelativePathHashMap = wave.windows.Win32RelativePathHashMap;

const cpu_endian = @import("builtin").cpu.arch.endian();

pub const Database = struct {
    sync_dir: w.HANDLE,
    sync_dir_io: Io.Dir,
    allocator: Allocator,
    mutex: Io.Mutex, // TODO: Compare with RwLock
    debug: Debug,

    file_path_arena: std.heap.ArenaAllocator.State,
    file_id_map: Win32RelativePathHashMap(network.FileId),

    client_known_files: Win32RelativePathHashMap(ClientFileEntry),
    awaiting_sync_files: Win32RelativePathHashMap(void), // TODO change to a key value type of `FileId`
    new_files: Win32RelativePathHashMap(void),
    deleted_files: std.ArrayList(struct { Wtf16, network.FileId }),
    scan_arena: std.heap.ArenaAllocator.State,

    // Database-Host synchronization fields
    alert: std.atomic.Value(Alert),
    host_state: std.atomic.Value(Host.State),
    out_path: Wtf16,
    out_file_id: network.FileId,
    out_metadata: FileMetadata,

    pub const Alert = enum(u32) { off, on };

    pub const FileMetadata = struct {
        local_file_id: w.LARGE_INTEGER,
        hash: network.FileHash,
        modified_time: w.LARGE_INTEGER,
        size: w.ULARGE_INTEGER,
    };

    pub const ClientFileState = enum { normal, untracked };

    pub const ClientFileEntry = struct {
        state: ClientFileState,
        metadata: FileMetadata,
    };

    pub fn init(sync_dir_path: Wtf16, io: Io, allocator: Allocator) !Database {
        if (cpu_endian != .little) @compileError("TODO big endian");
        switch (std.fs.path.getWin32PathType(u16, sync_dir_path.slice)) {
            .drive_absolute => {},
            else => {
                // TODO: Potentially support more path types
                return error.NotADriveAbsoluteSyncDirPath;
            },
        }
        const sync_dir = blk: {
            // TODO: Proper Win32 -> NT path conversion
            const normalized = try std.mem.concat(allocator, w.WCHAR, &.{ wtf16("\\??\\"), sync_dir_path.slice });
            defer allocator.free(normalized);
            break :blk try wave.windows.openDir(null, .wtf16Cast(normalized));
        };
        errdefer w.CloseHandle(sync_dir);

        const sync_dir_path_wtf8 = try sync_dir_path.toWtf8Path();
        const sync_dir_io = try Io.Dir.cwd().openDir(io, sync_dir_path_wtf8.slice(), .{});
        errdefer comptime unreachable;

        return .{
            .sync_dir = sync_dir,
            .sync_dir_io = sync_dir_io,
            .allocator = allocator,
            .mutex = .init,
            .debug = .{},

            .file_path_arena = .{},
            .file_id_map = .empty,

            .client_known_files = .empty,
            .awaiting_sync_files = .empty,
            .new_files = .empty,
            .deleted_files = .empty,
            .scan_arena = .{},

            .alert = .init(.off),
            .host_state = .init(.{}),
            .out_path = undefined,
            .out_file_id = undefined,
            .out_metadata = undefined,
        };
    }

    pub fn deinit(db: *Database, io: Io) void {
        w.CloseHandle(db.sync_dir);
        db.sync_dir_io.close(io);

        var file_path_arena = db.file_path_arena.promote(db.allocator);
        file_path_arena.deinit();
        db.file_id_map.deinit(db.allocator);

        db.client_known_files.deinit(db.allocator);
        db.awaiting_sync_files.deinit(db.allocator);
        db.new_files.deinit(db.allocator);
        db.deleted_files.deinit(db.allocator);
        var scan_arena = db.scan_arena.promote(db.allocator);
        scan_arena.deinit();

        db.* = undefined;
    }

    pub fn run(db: *Database, io: Io) !void {
        var stderr = Io.File.stderr().writer(io, &.{});

        const clock: Io.Clock = .boot;
        const max_wait_time = Io.Clock.Duration{ .raw = .fromSeconds(8), .clock = clock };
        var next_scan_time = Io.Clock.Timestamp.now(io, clock);

        while (true) {
            // If enough time has passed, do a scan
            if (Io.Clock.Timestamp.now(io, .boot).compare(.gte, next_scan_time)) {
                try completeScan(db, io);
                try stderr.interface.writeAll("Scan complete\n");
                try db.debug.printFilesNeedingSync(&stderr.interface, io);
                next_scan_time = Io.Clock.Timestamp.now(io, clock).addDuration(max_wait_time);
                continue;
            }

            { // Look for events to send to the host
                try db.mutex.lock(io);
                defer db.mutex.unlock(io);

                if (db.new_files.count() != 0 and db.acquireHostEvent() != null) {
                    var it = db.new_files.keyIterator();
                    const path = it.next().?;
                    const file_info = db.client_known_files.get(path.*).?;
                    assert(file_info.state == .normal);

                    db.out_path = path.*;
                    db.new_files.removeByPtr(path);

                    db.releaseHostEvent(.get_global_file_id);
                    io.futexWake(Host.State, &db.host_state.raw, 1);
                    continue;
                } else if (db.awaiting_sync_files.count() != 0 and db.acquireHostEvent() != null) {
                    var it = db.awaiting_sync_files.keyIterator();
                    const path = it.next().?;
                    const file_info = db.client_known_files.get(path.*).?;
                    assert(file_info.state == .normal);

                    db.out_file_id = db.file_id_map.get(path.*).?;
                    db.out_path = path.*;
                    db.out_metadata = file_info.metadata;
                    db.awaiting_sync_files.removeByPtr(path);

                    db.releaseHostEvent(.sync_file);
                    io.futexWake(Host.State, &db.host_state.raw, 1);
                    continue;
                } else if (db.deleted_files.items.len != 0 and db.acquireHostEvent() != null) {
                    const path, const file_id = db.deleted_files.swapRemove(db.deleted_files.items.len - 1);

                    db.out_file_id = file_id;
                    db.out_path = path;

                    db.releaseHostEvent(.delete_file);
                    io.futexWake(Host.State, &db.host_state.raw, 1);
                }
            }

            db.alert.store(.off, .release);
            try io.futexWaitTimeout(Alert, &db.alert.raw, .off, .{ .deadline = next_scan_time });
        }
    }

    fn sendAlert(db: *Database, io: Io) void {
        db.alert.store(.on, .release);
        io.futexWake(Alert, &db.alert.raw, 1);
    }

    fn acquireHostEvent(db: *Database) ?void {
        var host_state = db.host_state.load(.monotonic);
        while (host_state.event == .none) {
            var new_host_state = host_state;
            new_host_state.event = .acquired;
            host_state = db.host_state.cmpxchgWeak(host_state, new_host_state, .acquire, .monotonic) orelse break;
        } else return null;
    }

    fn releaseHostEvent(db: *Database, event: Host.State.Event) void {
        var host_state = db.host_state.load(.monotonic);
        while (true) {
            assert(host_state.event == .acquired);
            var new_host_state = host_state;
            new_host_state.event = event;
            host_state = db.host_state.cmpxchgWeak(host_state, new_host_state, .release, .monotonic) orelse break;
        }
    }

    // client
    /// Must be called with a lock.
    fn updateLocalFile(
        db: *Database,
        path: Wtf16,
        information: *const NtQueryInformation,
        hash: *const network.FileHash,
        untracked: bool,
    ) !void {
        const size = std.math.cast(w.ULARGE_INTEGER, information.EndOfFile) orelse return error.Unexpected;

        const metadata = FileMetadata{
            .local_file_id = information.FileId,
            .hash = hash.*,
            .modified_time = information.ChangeTime,
            .size = size,
        };

        const gop = try db.client_known_files.getOrPut(db.allocator, path);
        if (gop.found_existing) {
            if (untracked) {
                gop.value_ptr.* = .{ .state = .untracked, .metadata = metadata };
                return;
            }

            if (gop.value_ptr.metadata.local_file_id == metadata.local_file_id and
                gop.value_ptr.metadata.size == metadata.size and
                gop.value_ptr.metadata.hash.eql(&metadata.hash)) return;

            try db.awaiting_sync_files.put(db.allocator, gop.key_ptr.*, {});
            errdefer comptime unreachable;
        } else {
            errdefer db.client_known_files.removeByPtr(gop.key_ptr);

            var file_path_arena = db.file_path_arena.promote(db.allocator);
            defer db.file_path_arena = file_path_arena.state;
            const file_path_allocator = file_path_arena.allocator();

            gop.key_ptr.* = try path.dupe(file_path_allocator);
            errdefer file_path_allocator.free(gop.key_ptr.slice);

            if (untracked) {
                gop.value_ptr.* = .{ .state = .untracked, .metadata = metadata };
                return;
            }

            try db.new_files.put(db.allocator, gop.key_ptr.*, {});
            errdefer comptime unreachable;
        }

        gop.value_ptr.* = .{ .state = .normal, .metadata = metadata };
    }

    // client
    /// Must be called with a lock.
    /// `path` must be a path to a tracked file
    fn deleteLocalFile(db: *Database, path: Wtf16) !void {
        try db.deleted_files.ensureUnusedCapacity(db.allocator, 1);
        errdefer comptime unreachable;

        assert(db.client_known_files.remove(path));
        const file_id = db.file_id_map.fetchRemove(path).?.value;
        db.deleted_files.appendAssumeCapacity(.{ path, file_id });
    }

    // client
    fn setNewFileId(db: *Database, path: Wtf16, global_file_id: network.FileId, io: Io) !void {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        try db.file_id_map.putNoClobber(db.allocator, path, global_file_id);

        try db.awaiting_sync_files.put(db.allocator, path, {});
        // TODO: send alert here?
    }

    fn markFileAsSynced(db: *Database, path: Wtf16) void {
        // TODO do something here
        _ = .{ db, path };
    }

    fn openFileReadOnly(db: *const Database, path: Wtf16) !w.HANDLE {
        return wave.windows.openFile(db.sync_dir, path, .read);
    }

    fn closeFile(_: *const Database, file: w.HANDLE) void {
        w.CloseHandle(file);
    }

    pub const Debug = struct {
        pub fn printKnownFiles(debug: *Debug, writer: *Io.Writer, io: Io) !void {
            const db: *Database = @alignCast(@fieldParentPtr("debug", debug));
            try db.mutex.lock(io);
            defer db.mutex.unlock(io);

            try writer.writeAll("Tracked files\n");
            var it = db.client_known_files.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.state) {
                    .normal => {},
                    .untracked => continue,
                }
                try writer.print(
                    "{f}: hash({f}) modified({}) size({})\n",
                    .{
                        entry.key_ptr.formatUtf8(),
                        entry.value_ptr.metadata.hash,
                        entry.value_ptr.metadata.modified_time,
                        entry.value_ptr.metadata.size,
                    },
                );
            }

            try writer.writeAll("\nUntracked files\n");
            it = db.client_known_files.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.state) {
                    .normal => continue,
                    .untracked => {},
                }
                try writer.print("{f}\n", .{entry.key_ptr.formatUtf8()});
            }
        }

        pub fn printFilesNeedingSync(debug: *Debug, writer: *Io.Writer, io: Io) !void {
            const db: *Database = @alignCast(@fieldParentPtr("debug", debug));
            try db.mutex.lock(io);
            defer db.mutex.unlock(io);

            try writer.writeAll("Locally new files\n");
            var it1 = db.new_files.iterator();
            while (it1.next()) |entry| {
                try writer.print("\t{f}\n", .{entry.key_ptr.formatUtf8()});
            }

            try writer.writeAll("\nLocally updated files\n");
            var it2 = db.awaiting_sync_files.iterator();
            while (it2.next()) |entry| {
                try writer.print("\t{f}\n", .{entry.key_ptr.formatUtf8()});
            }

            try writer.writeAll("\n");
        }

        pub fn hostTransferFile(debug: *Debug, index: usize, io: Io) !void {
            const db: *Database = @alignCast(@fieldParentPtr("debug", debug));
            try db.mutex.lock(io);
            defer db.mutex.unlock(io);

            const entry = blk: {
                var it = db.client_known_files.keyIterator();
                for (0..index) |_| _ = it.next().?;
                break :blk it.next().?.*;
            };
            try db.awaiting_sync_files.put(db.allocator, entry, {});
            db.sendAlert(io);
        }
    };
};

const FullScanContext = struct {
    arena: *std.heap.ArenaAllocator,
    pending_dirs: std.ArrayList(Wtf16),
    sub_path: std.ArrayList(w.WCHAR),
    component_delimeters: std.ArrayList(u16),
    open_dir_handles: std.ArrayList(w.HANDLE),
    known_files_copy: Win32RelativePathHashMap(void),

    fn init(db: *const Database, arena: *std.heap.ArenaAllocator) !FullScanContext {
        const allocator = arena.allocator();

        var open_dir_handles: std.ArrayList(w.HANDLE) = .empty;
        try open_dir_handles.append(allocator, db.sync_dir);

        var known_files_copy: Win32RelativePathHashMap(void) = .empty;
        try known_files_copy.ensureTotalCapacity(allocator, db.client_known_files.count());
        var it = db.client_known_files.iterator();
        while (it.next()) |entry| {
            switch (entry.value_ptr.state) {
                .normal => known_files_copy.putAssumeCapacityNoClobber(entry.key_ptr.*, {}),
                .untracked => {},
            }
        }

        return .{
            .arena = arena,
            .pending_dirs = .empty,
            .sub_path = .empty,
            .component_delimeters = .empty,
            .open_dir_handles = open_dir_handles,
            .known_files_copy = known_files_copy,
        };
    }

    fn deinit(ctx: *FullScanContext) void {
        for (ctx.open_dir_handles.items[1..]) |handle| {
            w.CloseHandle(handle);
        }
        ctx.* = undefined;
    }

    fn enterDir(ctx: *FullScanContext, dir_path: Wtf16) !void {
        const allocator = ctx.arena.allocator();
        try ctx.component_delimeters.append(allocator, @intCast(ctx.sub_path.items.len));
        try ctx.sub_path.appendSlice(allocator, dir_path.slice);
        try ctx.sub_path.appendSlice(allocator, comptime wtf16("\\"));

        const parent_dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
        const dir = try wave.windows.openDir(parent_dir, dir_path);
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
        const untracked = @as(w.ULONG, @bitCast(rejected)) & @as(w.ULONG, @bitCast(information.FileAttributes)) != 0;

        if (information.FileAttributes.DIRECTORY) {
            if (untracked) return;
            const allocator = ctx.arena.allocator();
            const copied_name = try name.dupe(allocator);
            try ctx.pending_dirs.append(allocator, copied_name);
        } else {
            const allocator = ctx.arena.allocator();
            const component_delimeter_index = ctx.sub_path.items.len;
            defer ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
            try ctx.sub_path.appendSlice(allocator, name.slice);
            const path: Wtf16 = .wtf16Cast(ctx.sub_path.items);

            // TODO: Do not compute the hash right now
            const dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
            const file = try wave.windows.openFile(dir, name, .read);
            defer w.CloseHandle(file);
            const hash = try computeFileHash(file, information.EndOfFile);

            try db.updateLocalFile(path, information, &hash, untracked);
            _ = ctx.known_files_copy.remove(path);
        }
    }

    fn deleteFiles(ctx: *FullScanContext, db: *Database) !void {
        var it = ctx.known_files_copy.keyIterator();
        while (it.next()) |path| try db.deleteLocalFile(path.*);
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

pub fn completeScan(db: *Database, io: Io) !void {
    try db.mutex.lock(io);
    defer db.mutex.unlock(io);

    var arena = db.scan_arena.promote(db.allocator);
    defer {
        _ = arena.reset(.retain_capacity);
        db.scan_arena = arena.state;
    }

    var ctx = try FullScanContext.init(db, &arena);
    defer ctx.deinit();

    try scanOneDirectory(db, &ctx);
    while (ctx.pending_dirs.items.len > 0) {
        const dir_path_ptr = &ctx.pending_dirs.items[ctx.pending_dirs.items.len - 1];
        if (dir_path_ptr.slice.len == 0) {
            _ = ctx.pending_dirs.pop();
            ctx.exitDir();
            continue;
        }

        const dir_path = dir_path_ptr.*;
        dir_path_ptr.* = .wtf16Cast(&.{});
        try ctx.enterDir(dir_path);
        try scanOneDirectory(db, &ctx);
    }

    try ctx.deleteFiles(db);
}

fn scanOneDirectory(db: *Database, ctx: *FullScanContext) !void {
    const dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
    var buffer: [64 * 1024]u8 align(@alignOf(NtQueryInformation)) = undefined;
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

            if (info.FileNameLength > w.NAME_MAX or
                std.mem.eql(w.WCHAR, file_name.slice, comptime wtf16(".")) or
                std.mem.eql(w.WCHAR, file_name.slice, comptime wtf16(".."))) continue;

            try ctx.addObject(db, file_name, info);
        }
    }
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

pub const Host = struct {
    tx: Transaction,
    // TODO: Don't store this here, instead make it an argument to `run`
    db: *Database,
    debug: Debug,

    pub const Debug = struct {
        name: ?[]const u8 = null,
    };

    pub const Transaction = struct {
        data: TxData,
        peer_tx_id: network.TransactionId,
    };

    pub const State = packed struct(u32) {
        tx: TxStatus = .init,
        event: Event = .none,
        padding: u27 = 0,

        pub const TxStatus = enum(u2) {
            /// The TX is free to use.
            init,
            /// The TX is locked and being initialized.
            acquired,
            /// The TX is locked and owned by the outgoing task.
            outgoing,
            /// The TX is locked and owned by the incoming task.
            incoming,
        };

        pub const Event = enum(u3) {
            none,
            acquired,
            get_global_file_id,
            sync_file,
            delete_file,
        };
    };

    pub fn init(db: *Database, debug: Debug) Host {
        return .{
            .tx = .{
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
        outgoing: ?OutgoingError = null,
        incoming: ?IncomingError = null,
    };

    /// Blocks until the `Host` is finished running.
    pub fn run(
        host: *Host,
        diag: ?*Diagnostics,
        io: Io,
        reader: *Io.Reader,
        writer: *Io.Writer,
    ) RunError!void {
        const ns = struct {
            const SelectUnion = union(enum) {
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

        var select_buffer: [2]ns.SelectUnion = undefined;
        var select = Io.Select(ns.SelectUnion).init(io, &select_buffer);
        defer while (select.cancel()) |result| ns.addToDiagnostics(diag, result);

        try select.concurrent(.outgoing, sendOutgoingTxs, .{ host, writer, io });
        try select.concurrent(.incoming, receiveIncomingTxs, .{ host, reader, io });

        host.debugLog("started", .{});
        ns.addToDiagnostics(diag, try select.await());
    }

    pub const OutgoingError = Io.Writer.Error || Io.Cancelable || wave.windows.SendFileError;

    fn sendOutgoingTxs(host: *Host, writer: *Io.Writer, io: Io) OutgoingError!void {
        while (true) {
            while (true) {
                const state = host.db.host_state.load(.monotonic);
                if (state.tx == .outgoing) break;
                host.handleEvents(state, io) orelse
                    try io.futexWait(State, &host.db.host_state.raw, state);
            }

            const tx_id: network.TransactionId = @enumFromInt(0); // TODO hardcoded value
            switch (host.tx.data) {
                .out_new_file => |*out_new_file| switch (out_new_file.state) {
                    .send_path => try out_new_file.sendPath(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_decision => unreachable,
                },
                .out_file_contents => |*out_file_contents| switch (out_file_contents.state) {
                    .send_metadata => try out_file_contents.sendMetadata(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .send_file_contents => try out_file_contents.sendFileContents(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_decision, .receive_result => unreachable,
                },
                .out_delete_file => |*out_delete_file| switch (out_delete_file.state) {
                    .send_file_id => try out_delete_file.sendFileId(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_confirmation => unreachable,
                },
            }
        }
    }

    /// Returns null if no event was handled.
    fn handleEvents(host: *Host, state: State, io: Io) ?void {
        switch (state.event) {
            .none, .acquired => return null,
            .get_global_file_id => {
                const tx_id = host.acquireUnusedTx() catch |err| switch (err) {
                    error.NoTxSlotsAvailable => return null,
                };
                assert(@intFromEnum(tx_id) == 0); // TODO hardcoded value
                host.debugLog("getting global file id for new file: {f}", .{host.db.out_path.formatUtf8()});

                host.tx.data = .{
                    .out_new_file = .{
                        .state = .send_path,
                        .path = host.db.out_path,
                    },
                };
                host.tx.peer_tx_id = .invalid;

                host.db.out_path = undefined;
            },
            .sync_file => {
                const tx_id = host.acquireUnusedTx() catch |err| switch (err) {
                    error.NoTxSlotsAvailable => return null,
                };
                assert(@intFromEnum(tx_id) == 0); // TODO hardcoded value
                host.debugLog("syncing file: {f}", .{host.db.out_path.formatUtf8()});

                host.tx.data = .{
                    .out_file_contents = .{
                        .state = .send_metadata,
                        .file_id = host.db.out_file_id,
                        .path = host.db.out_path,
                        .size = host.db.out_metadata.size,
                        .hash = host.db.out_metadata.hash,
                    },
                };
                host.tx.peer_tx_id = .invalid;

                host.db.out_file_id = undefined;
                host.db.out_path = undefined;
                host.db.out_metadata = undefined;
            },
            .delete_file => {
                const tx_id = host.acquireUnusedTx() catch |err| switch (err) {
                    error.NoTxSlotsAvailable => return null,
                };
                assert(@intFromEnum(tx_id) == 0); // TODO hardcoded value
                host.debugLog("deleting file: {f}", .{host.db.out_path.formatUtf8()});

                host.tx.data = .{
                    .out_delete_file = .{
                        .state = .send_file_id,
                        .file_id = host.db.out_file_id,
                        .path = host.db.out_path,
                    },
                };
                host.tx.peer_tx_id = .invalid;

                host.db.out_file_id = undefined;
                host.db.out_path = undefined;
            },
        }

        var old_state = state;
        while (true) {
            var new_state = state;
            new_state.tx = .outgoing;
            new_state.event = .none;
            old_state = host.db.host_state.cmpxchgWeak(old_state, new_state, .release, .monotonic) orelse break;
        }
        host.db.sendAlert(io);
    }

    pub const IncomingError = error{
        InvalidTxId,
        InvalidPeerTxId,
        WrongTxId,
        WrongPeerTxId,
        InvalidAction,
        InvalidHeader,
    } || network.ReceiveActionError || network.ReceiveFileMetadataError || network.ReceiveNewFilePathError ||
        Io.Cancelable || Allocator.Error || AddOutgoingTxError || wave.windows.ReceiveFileError;

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
                        else => return error.InvalidAction,
                    }
                },
                .new_tx_reply => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
                    // TODO There is a chance that this line can be reached before the send task flips the TX to incoming
                    if (host.db.host_state.load(.monotonic).tx != .incoming) return error.InvalidTxId;
                    if (host.tx.peer_tx_id != .invalid) return error.WrongPeerTxId;

                    switch (host.tx.data) {
                        .out_new_file => |*out_new_file| switch (out_new_file.state) {
                            .receive_decision => {
                                try out_new_file.receiveDecision(
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
                        .out_file_contents => |*out_file_contents| switch (out_file_contents.state) {
                            .receive_decision => {
                                try out_file_contents.receiveDecision(
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
                        .out_delete_file => |*out_delete_file| switch (out_delete_file.state) {
                            .send_file_id => unreachable,
                            .receive_confirmation => try out_delete_file.receiveConfirmation(
                                host,
                                reader,
                                io,
                                header.tx_id,
                                header.peer_tx_id,
                                action,
                            ),
                        },
                    }
                },
                .existing_tx => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
                    // TODO There is a chance that this line can be reached before the send task flips the TX to incoming
                    if (host.db.host_state.load(.monotonic).tx != .incoming) return error.InvalidTxId;
                    if (header.peer_tx_id != .invalid) return error.WrongPeerTxId;

                    switch (host.tx.data) {
                        .out_new_file => |*out_new_file| switch (out_new_file.state) {
                            .receive_decision => return error.InvalidHeader,
                            .send_path => unreachable,
                        },
                        .out_file_contents => |*out_file_contents| switch (out_file_contents.state) {
                            .receive_decision => return error.InvalidHeader,
                            .receive_result => {
                                try out_file_contents.receiveResult(host, reader, io, header.tx_id, action);
                            },
                            .send_metadata, .send_file_contents => unreachable,
                        },
                        .out_delete_file => |*out_delete_file| switch (out_delete_file.state) {
                            .send_file_id => unreachable,
                            .receive_confirmation => return error.InvalidHeader,
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
        // TODO Make non-nullable
        peer_tx_id: ?network.TransactionId,
    ) AddOutgoingTxError!void {
        _ = try host.acquireUnusedTx();

        host.tx.data = data;
        host.tx.peer_tx_id = peer_tx_id orelse .invalid;

        host.releaseNewTxStatus(.acquired, .outgoing);
        io.futexWake(State, &host.db.host_state.raw, 1);
    }

    fn flipTransaction(
        host: *Host,
        comptime to: State.TxStatus,
        tx_id: network.TransactionId,
        io: Io,
    ) void {
        assert(@intFromEnum(tx_id) == 0); // TODO: hardcoded value
        switch (to) {
            .init, .acquired => unreachable,
            .outgoing => {
                host.releaseNewTxStatus(.incoming, to);
                io.futexWake(State, &host.db.host_state.raw, 1);
            },
            .incoming => {
                host.releaseNewTxStatus(.outgoing, to);
            },
        }
    }

    fn deleteTransaction(host: *Host, tx_id: network.TransactionId, expected_status: State.TxStatus, io: Io) void {
        assert(@intFromEnum(tx_id) == 0); // TODO hardcoded value
        host.tx.data = undefined;
        host.tx.peer_tx_id = undefined;
        host.releaseNewTxStatus(expected_status, .init);

        switch (expected_status) {
            .init, .acquired => unreachable,
            .outgoing => {},
            .incoming => io.futexWake(State, &host.db.host_state.raw, 1),
        }
    }

    fn acquireUnusedTx(host: *Host) !network.TransactionId {
        var old_state = host.db.host_state.load(.monotonic);
        while (old_state.tx == .init) {
            var new_state = old_state;
            new_state.tx = .acquired;
            old_state = host.db.host_state.cmpxchgWeak(old_state, new_state, .acquire, .monotonic) orelse break;
        } else return error.NoTxSlotsAvailable;
        return @enumFromInt(0); // TODO hardcoded value
    }

    fn releaseNewTxStatus(host: *Host, expected: State.TxStatus, new: State.TxStatus) void {
        var old_state = host.db.host_state.load(.monotonic);
        while (true) {
            assert(old_state.tx == expected);
            var new_state = old_state;
            new_state.tx = new;
            old_state = host.db.host_state.cmpxchgWeak(old_state, new_state, .release, .monotonic) orelse break;
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
        tx_status: Host.State.TxStatus,
        tx_id: network.TransactionId,
        action: network.Action,
        peer_tx_id: network.TransactionId,
    ) void {
        switch (tx_status) {
            .init, .acquired => unreachable,
            .outgoing => host.debugLog(
                "{s} tx#{f} {s} -> peer tx#{f}",
                .{ @tagName(tx_status), tx_id, @tagName(action), peer_tx_id },
            ),
            .incoming => host.debugLog(
                "{s} tx#{f} <- peer tx#{f} {s}",
                .{ @tagName(tx_status), tx_id, peer_tx_id, @tagName(action) },
            ),
        }
    }
};

pub const TxData = union(enum) {
    out_new_file: OutNewFile,
    out_file_contents: OutFileContents,
    out_delete_file: OutDeleteFile,

    pub const OutNewFile = struct {
        state: State,
        path: Wtf16,

        pub const State = enum {
            send_path,
            receive_decision,
        };

        fn sendPath(
            out_new_file: *OutNewFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(out_new_file.state == .send_path);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .client_new_file;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTx(writer, tx_id);
            try network.sendAction(writer, action);
            try network.sendNewFilePath(
                writer,
                switch (cpu_endian) {
                    .big => @compileError("TODO big endian"),
                    .little => .wtf16le,
                },
                @ptrCast(out_new_file.path.slice),
            );
            try writer.flush();

            out_new_file.state = .receive_decision;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveDecision(
            out_new_file: *const OutNewFile,
            host: *Host,
            reader: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(out_new_file.state == .receive_decision);
            if (peer_tx_id != .invalid) return error.InvalidPeerTxId;

            switch (action) {
                .server_registered_new_file => {
                    const file_id = try network.receiveFileId(reader);
                    host.debugLog("received file id {} for file {f}\n", .{ file_id, out_new_file.path.formatUtf8() });
                    try host.db.setNewFileId(out_new_file.path, file_id, io);
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                .server_cant_register_new_files => {
                    host.debugLog("server can't register file {f}\n", .{out_new_file.path.formatUtf8()});
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                .server_new_file_exists => {
                    host.debugLog("new file already exists: {f}\n", .{out_new_file.path.formatUtf8()});
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                else => return error.InvalidAction,
            }
        }
    };

    pub const OutFileContents = struct {
        state: State,
        file_id: network.FileId,
        path: Wtf16,
        size: w.ULARGE_INTEGER,
        hash: network.FileHash,

        pub const State = enum {
            send_metadata,
            receive_decision,
            send_file_contents,
            receive_result,
        };

        fn sendMetadata(
            out_file_contents: *OutFileContents,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(out_file_contents.state == .send_metadata);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .transfer_file_metadata;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            const file_size = std.math.cast(network.FileSize, out_file_contents.size) orelse
                std.debug.panic(
                    "TODO: File too large to transfer: '{f}' with size {}",
                    .{ out_file_contents.path.formatUtf8(), out_file_contents.size },
                );
            try network.sendMessageHeaderNewTx(writer, tx_id);
            try network.sendAction(writer, action);
            try network.sendFileMetadata(writer, out_file_contents.file_id, file_size, &out_file_contents.hash);
            try writer.flush();

            out_file_contents.state = .receive_decision;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveDecision(
            out_file_contents: *OutFileContents,
            host: *Host,
            _: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(out_file_contents.state == .receive_decision);

            switch (action) {
                .transfer_file_accept => {
                    if (peer_tx_id == .invalid) return error.WrongPeerTxId;
                    out_file_contents.state = .send_file_contents;
                    host.tx.peer_tx_id = peer_tx_id;
                    host.flipTransaction(.outgoing, tx_id, io);
                },
                .transfer_file_decline => {
                    if (peer_tx_id != .invalid) return error.WrongPeerTxId;
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                else => return error.InvalidAction,
            }
        }

        fn sendFileContents(
            out_file_contents: *OutFileContents,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(out_file_contents.state == .send_file_contents);

            const action: network.Action = .transfer_file_contents;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            const handle = try host.db.openFileReadOnly(out_file_contents.path);
            defer host.db.closeFile(handle);

            try network.sendMessageHeaderExistingTx(writer, peer_tx_id);
            try network.sendAction(writer, action);
            try wave.windows.sendFile(writer, handle, out_file_contents.size);
            try writer.flush();

            out_file_contents.state = .receive_result;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveResult(
            out_file_contents: *const OutFileContents,
            host: *Host,
            _: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            switch (action) {
                .transfer_file_success => {
                    host.db.markFileAsSynced(out_file_contents.path);
                },
                .transfer_file_failure => {
                    // TODO mark file as failed to sync
                    host.db.markFileAsSynced(out_file_contents.path);
                },
                else => return error.InvalidAction,
            }
            host.deleteTransaction(tx_id, .incoming, io);
        }
    };

    pub const OutDeleteFile = struct {
        state: enum { send_file_id, receive_confirmation },
        file_id: network.FileId,
        path: Wtf16,

        fn sendFileId(
            out_delete_file: *OutDeleteFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(out_delete_file.state == .send_file_id);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .delete_file;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTx(writer, tx_id);
            try network.sendAction(writer, action);
            try network.sendFileId(writer, out_delete_file.file_id);
            try writer.flush();

            out_delete_file.state = .receive_confirmation;
            host.flipTransaction(.incoming, tx_id, io);
        }

        fn receiveConfirmation(
            out_delete_file: *OutDeleteFile,
            host: *Host,
            _: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(out_delete_file.state == .receive_confirmation);
            if (peer_tx_id != .invalid) return error.WrongPeerTxId;

            switch (action) {
                .delete_file_confirm => {
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                else => return error.InvalidAction,
            }
        }
    };
};
