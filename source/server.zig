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

    file_path_arena: std.heap.ArenaAllocator.State,
    file_id_map: Win32RelativePathHashMap(network.FileId),
    next_file_id: ?std.meta.Tag(network.FileId),
    known_files: std.AutoHashMapUnmanaged(network.FileId, FileEntry),

    host_state: std.atomic.Value(Host.State),

    pub const FileMetadata = struct {
        local_file_id: w.LARGE_INTEGER,
        hash: network.FileHash,
        modified_time: w.LARGE_INTEGER,
        size: w.ULARGE_INTEGER,
    };

    pub const FileState = enum { unsynced, synced };

    pub const FileEntry = struct {
        path: Wtf16,
        state: FileState,
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

            .file_path_arena = .{},
            .file_id_map = .empty,
            .next_file_id = 1,
            .known_files = .empty,

            .host_state = .init(.{}),
        };
    }

    pub fn deinit(db: *Database, io: Io) void {
        w.CloseHandle(db.sync_dir);
        db.sync_dir_io.close(io);

        var file_path_arena = db.file_path_arena.promote(db.allocator);
        file_path_arena.deinit();

        db.file_id_map.deinit(db.allocator);
        db.known_files.deinit(db.allocator);

        db.* = undefined;
    }

    const NewFileResult = union(enum) {
        file_id: network.FileId,
        file_already_exists,
        exhausted_file_ids,
    };

    fn newFile(db: *Database, path: Wtf16, io: Io) !NewFileResult {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        const gop = try db.file_id_map.getOrPut(db.allocator, path);
        if (gop.found_existing) return .file_already_exists;
        errdefer db.file_id_map.removeByPtr(gop.key_ptr);

        const file_id_tag = db.next_file_id orelse return .exhausted_file_ids;
        db.next_file_id = std.math.add(std.meta.Tag(network.FileId), file_id_tag, 1) catch null;
        errdefer db.next_file_id = file_id_tag;
        const file_id: network.FileId = @enumFromInt(file_id_tag);

        var file_path_arena = db.file_path_arena.promote(db.allocator);
        defer db.file_path_arena = file_path_arena.state;
        const path_copy = try path.dupe(file_path_arena.allocator());
        errdefer file_path_arena.allocator().free(path_copy.slice);

        try db.known_files.ensureUnusedCapacity(db.allocator, 1);
        errdefer comptime unreachable;

        db.known_files.putAssumeCapacityNoClobber(file_id, .{
            .path = path_copy,
            .state = .unsynced,
            .metadata = undefined,
        });
        gop.key_ptr.* = path_copy;
        gop.value_ptr.* = file_id;

        return .{ .file_id = file_id };
    }

    const CheckMetadataResult = union(enum) {
        file_exists: struct {
            path: Wtf16,
            comparison: enum { equals, differs },
        },
        file_is_uninitialized: struct {
            path: Wtf16,
        },
        file_doesnt_exist,
    };

    fn checkMetadata(
        db: *Database,
        metadata: *const network.IncomingFileMetadata,
        io: Io,
    ) !CheckMetadataResult {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        const entry = db.known_files.getPtr(metadata.file_id) orelse return .file_doesnt_exist;
        switch (entry.state) {
            .unsynced => return .{ .file_is_uninitialized = .{ .path = entry.path } },
            .synced => {},
        }
        const equals =
            entry.metadata.size == metadata.file_size and
            std.mem.eql(u8, &entry.metadata.hash.blake3, &metadata.hash.blake3);

        return .{ .file_exists = .{
            .path = entry.path,
            .comparison = if (equals) .equals else .differs,
        } };
    }

    fn openFileReadOnly(db: *const Database, path: Wtf16) !w.HANDLE {
        return wave.windows.openFile(db.sync_dir, path, .read);
    }

    const CreateFileError = Io.Dir.CreateDirPathError || Wtf16.ToWtf8PathError || error{EmptyPath};

    // TODO create temporary files instead
    fn createFile(db: *const Database, io: Io, path: Wtf16, file_size: w.LARGE_INTEGER) CreateFileError!w.HANDLE {
        // TODO janky
        const path_wtf8 = try path.toWtf8Path();
        var it = std.fs.path.componentIterator(path_wtf8.slice());
        _ = it.last() orelse return error.EmptyPath;
        if (it.previous()) |previous| {
            try db.sync_dir_io.createDirPath(io, previous.path);
        }

        return wave.windows.openFile(
            db.sync_dir,
            path,
            .{ .create = .{ .initial_size = file_size } },
        );
    }

    fn closeFile(_: *const Database, file: w.HANDLE) void {
        w.CloseHandle(file);
    }

    fn finishReceiveFileContents(
        db: *Database,
        io: Io,
        handle: w.HANDLE,
        file_id: network.FileId,
        hash: *const network.FileHash,
        file_size: w.LARGE_INTEGER,
    ) !void {
        const basic_information = blk: {
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
        const internal_information = blk: {
            var iosb: w.IO_STATUS_BLOCK = undefined;
            var information: w.FILE.INTERNAL_INFORMATION = undefined;
            const status = w.ntdll.NtQueryInformationFile(
                handle,
                &iosb,
                &information,
                @sizeOf(@TypeOf(information)),
                .Internal,
            );
            switch (status) {
                .SUCCESS => break :blk information,
                else => return w.unexpectedStatus(status),
            }
        };

        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        const entry = db.known_files.getPtr(file_id).?;
        entry.metadata = .{
            .local_file_id = internal_information.IndexNumber,
            .hash = hash.*,
            .modified_time = basic_information.ChangeTime,
            .size = @intCast(file_size),
        };
        entry.state = .synced;
    }

    const DeleteGlobalFileResult = union(enum) {
        success,
        unknown_file,
        delete_file_err: Io.Dir.DeleteFileError,
    };

    fn deleteGlobalFile(db: *Database, file_id: network.FileId, io: Io) !DeleteGlobalFileResult {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        const entry = db.known_files.fetchRemove(file_id) orelse return .unknown_file;
        assert(db.file_id_map.fetchRemove(entry.value.path).?.value == file_id);
        switch (entry.value.state) {
            .synced, .unsynced => {},
        }
        // TODO janky, use NT functions
        const path_wtf8 = try entry.value.path.toWtf8Path();
        if (db.sync_dir_io.deleteFile(io, path_wtf8.slice())) |_| {
            return .success;
        } else |err| {
            return .{ .delete_file_err = err };
        }
    }
};

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
        padding: u30 = 0,

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
                try io.futexWait(State, &host.db.host_state.raw, state);
            }

            const tx_id: network.TransactionId = @enumFromInt(0); // TODO hardcoded value
            switch (host.tx.data) {
                .in_new_file => |*in_new_file| {
                    try in_new_file.sendDecision(host, tx_id, host.tx.peer_tx_id, io, writer);
                },
                .in_file_contents => |*in_file_contents| switch (in_file_contents.state) {
                    .send_decision => try in_file_contents.sendDecision(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .send_result => try in_file_contents.sendResult(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_file_contents => unreachable,
                },
                .in_delete_file => |*in_delete_file| {
                    try in_delete_file.sendConfirmation(host, tx_id, host.tx.peer_tx_id, io, writer);
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
    } || network.ReceiveActionError || network.ReceiveFileMetadataError || network.ReceiveNewFilePathError ||
        Io.Cancelable || Allocator.Error || AddOutgoingTxError || wave.windows.ReceiveFileError || Database.CreateFileError;

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
                        .client_new_file => {
                            try TxData.InNewFile.newTx(host, header.peer_tx_id, io, reader);
                        },
                        .transfer_file_metadata => {
                            try TxData.InFileContents.newTx(host, header.peer_tx_id, io, reader);
                        },
                        .delete_file => {
                            try TxData.InDeleteFile.newTx(host, header.peer_tx_id, io, reader);
                        },
                        else => return error.InvalidAction,
                    }
                },
                .new_tx_reply => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
                    // TODO There is a chance that this line can be reached before the send task flips the TX to incoming
                    if (host.db.host_state.load(.monotonic).tx != .incoming) return error.InvalidTxId;
                    if (host.tx.peer_tx_id != .invalid) return error.WrongPeerTxId;

                    switch (host.tx.data) {
                        .in_new_file => unreachable,
                        .in_file_contents => |*in_file_contents| switch (in_file_contents.state) {
                            .receive_file_contents => return error.InvalidHeader,
                            .send_decision, .send_result => unreachable,
                        },
                        .in_delete_file => unreachable,
                    }
                },
                .existing_tx => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
                    // TODO There is a chance that this line can be reached before the send task flips the TX to incoming
                    if (host.db.host_state.load(.monotonic).tx != .incoming) return error.InvalidTxId;
                    if (header.peer_tx_id != .invalid) return error.WrongPeerTxId;

                    switch (host.tx.data) {
                        .in_new_file => unreachable,
                        .in_file_contents => |*in_file_contents| switch (in_file_contents.state) {
                            .receive_file_contents => {
                                try in_file_contents.receiveFileContents(host, reader, io, header.tx_id, action);
                            },
                            .send_decision, .send_result => unreachable,
                        },
                        .in_delete_file => unreachable,
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
        // TODO switch to using simple atomic stores/loads
        var old_state = host.db.host_state.load(.monotonic);
        while (old_state.tx == .init) {
            var new_state = old_state;
            new_state.tx = .acquired;
            old_state = host.db.host_state.cmpxchgWeak(old_state, new_state, .acquire, .monotonic) orelse break;
        } else return error.NoTxSlotsAvailable;
        return @enumFromInt(0); // TODO hardcoded value
    }

    fn releaseNewTxStatus(host: *Host, expected: State.TxStatus, new: State.TxStatus) void {
        // TODO switch to using simple atomic stores/loads
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
    in_new_file: InNewFile,
    in_file_contents: InFileContents,
    in_delete_file: InDeleteFile,

    pub const InNewFile = struct {
        data: Database.NewFileResult,

        fn newTx(
            host: *Host,
            peer_tx_id: network.TransactionId,
            io: Io,
            reader: *Io.Reader,
        ) !void {
            var file_path_buffer: network.FilePathBuffer align(@alignOf(w.WCHAR)) = undefined;
            const path_info = try network.receiveNewFilePath(reader, &file_path_buffer);
            // TODO ensure it's a relative path
            const path: Wtf16 = switch (path_info.path_encoding) {
                .wtf16le => switch (cpu_endian) {
                    .big => @compileError("TODO big endian"),
                    .little => .wtf16Cast(@ptrCast(file_path_buffer[0..path_info.path_byte_count])),
                },
            };
            const data: TxData = .{
                .in_new_file = .{
                    .data = try host.db.newFile(path, io),
                },
            };
            try host.addOutgoingTx(io, data, peer_tx_id);
        }

        fn sendDecision(
            in_new_file: *const InNewFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(peer_tx_id != .invalid);

            const outgoing_tx_id: network.TransactionId = .invalid;
            switch (in_new_file.data) {
                .file_id => |file_id| {
                    const action: network.Action = .server_registered_new_file;
                    host.logMessage(.outgoing, outgoing_tx_id, action, peer_tx_id);

                    try network.sendMessageHeaderNewTxReply(writer, outgoing_tx_id, peer_tx_id);
                    try network.sendAction(writer, action);
                    try network.sendFileId(writer, file_id);
                },
                .file_already_exists => {
                    const action: network.Action = .server_new_file_exists;
                    host.logMessage(.outgoing, outgoing_tx_id, action, peer_tx_id);

                    try network.sendMessageHeaderNewTxReply(writer, outgoing_tx_id, peer_tx_id);
                    try network.sendAction(writer, action);
                },
                .exhausted_file_ids => {
                    const action: network.Action = .server_cant_register_new_files;
                    host.logMessage(.outgoing, outgoing_tx_id, action, peer_tx_id);

                    try network.sendMessageHeaderNewTxReply(writer, outgoing_tx_id, peer_tx_id);
                    try network.sendAction(writer, action);
                },
            }
            try writer.flush();

            host.deleteTransaction(tx_id, .outgoing, io);
        }
    };

    pub const InFileContents = struct {
        state: State,
        file_id: network.FileId,
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
            const metadata = try network.receiveFileMetadata(reader);
            const path: Wtf16, const decision: State.SendDecision = switch (try host.db.checkMetadata(&metadata, io)) {
                .file_exists => |res| .{
                    res.path, switch (res.comparison) {
                        .equals => .decline,
                        .differs => .accept,
                    },
                },
                .file_is_uninitialized => |res| .{ res.path, .accept },
                .file_doesnt_exist => std.debug.panic("TODO", .{}),
            };
            const data: TxData = .{
                .in_file_contents = .{
                    .state = .{ .send_decision = decision },
                    .file_id = metadata.file_id,
                    .path = path,
                    .size = @as(w.LARGE_INTEGER, @intCast(metadata.file_size)),
                    .hash = metadata.hash,
                },
            };
            try host.addOutgoingTx(io, data, peer_tx_id);
        }

        fn sendDecision(
            in_file_contents: *InFileContents,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(in_file_contents.state == .send_decision);
            assert(peer_tx_id != .invalid);

            const actual_tx_id: network.TransactionId, const action: network.Action =
                switch (in_file_contents.state.send_decision) {
                    .accept => .{ tx_id, .transfer_file_accept },
                    .decline => .{ .invalid, .transfer_file_decline },
                };
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTxReply(writer, actual_tx_id, peer_tx_id);
            try network.sendAction(writer, action);
            try writer.flush();

            switch (in_file_contents.state.send_decision) {
                .accept => {
                    in_file_contents.state = .receive_file_contents;
                    host.flipTransaction(.incoming, tx_id, io);
                },
                .decline => host.deleteTransaction(tx_id, .outgoing, io),
            }
        }

        fn receiveFileContents(
            in_file_contents: *InFileContents,
            host: *Host,
            reader: *Io.Reader,
            io: Io,
            tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(in_file_contents.state == .receive_file_contents);
            switch (action) {
                .transfer_file_contents => {
                    const handle = try host.db.createFile(io, in_file_contents.path, in_file_contents.size);
                    defer host.db.closeFile(handle);
                    try wave.windows.receiveFile(reader, handle, in_file_contents.size);
                    try host.db.finishReceiveFileContents(
                        io,
                        handle,
                        in_file_contents.file_id,
                        &in_file_contents.hash,
                        in_file_contents.size,
                    );

                    in_file_contents.state = .{ .send_result = .success };
                    host.flipTransaction(.outgoing, tx_id, io);
                },
                else => return error.InvalidAction,
            }
        }

        fn sendResult(
            in_file_contents: *const InFileContents,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            assert(in_file_contents.state == .send_result);
            assert(peer_tx_id != .invalid);

            const action: network.Action = switch (in_file_contents.state.send_result) {
                .success => .transfer_file_success,
                .failure => .transfer_file_failure,
            };
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderExistingTx(writer, peer_tx_id);
            try network.sendAction(writer, action);
            try writer.flush();

            host.deleteTransaction(tx_id, .outgoing, io);
        }
    };

    pub const InDeleteFile = struct {
        fn newTx(
            host: *Host,
            peer_tx_id: network.TransactionId,
            io: Io,
            reader: *Io.Reader,
        ) !void {
            const file_id = try network.receiveFileId(reader);
            switch (try host.db.deleteGlobalFile(file_id, io)) {
                .success => {},
                .unknown_file, .delete_file_err => std.debug.panic("TODO", .{}),
            }

            const data: TxData = .{
                .in_delete_file = .{},
            };
            try host.addOutgoingTx(io, data, peer_tx_id);
        }

        fn sendConfirmation(
            _: *InDeleteFile,
            host: *Host,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            io: Io,
            writer: *Io.Writer,
        ) !void {
            const action: network.Action = .delete_file_confirm;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            try network.sendMessageHeaderNewTxReply(writer, .invalid, peer_tx_id);
            try network.sendAction(writer, action);
            try writer.flush();

            host.deleteTransaction(tx_id, .outgoing, io);
        }
    };
};
