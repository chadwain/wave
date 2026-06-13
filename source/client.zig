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
const Win32RelativePathArrayHashMap = wave.windows.Win32RelativePathArrayHashMap;

const cpu_endian = @import("builtin").cpu.arch.endian();

pub const Database = struct {
    sync_dir: w.HANDLE,
    sync_dir_io: Io.Dir,
    debug: Debug,

    mutex: Io.Mutex, // TODO: Compare with RwLock

    // Begin fields protected by mutex

    allocator: Allocator,
    path_arena: std.heap.ArenaAllocator.State,
    scan_arena: std.heap.ArenaAllocator.State,
    tree: Tree,

    // End fields protected by mutex

    // Database-Host synchronization fields
    alert: std.atomic.Value(Alert),
    host_state: std.atomic.Value(Host.State),
    out_path: Wtf16,
    out_file_id: network.FileId,
    out_metadata: struct {
        size: w.ULARGE_INTEGER,
        hash: network.FileHash,
    },

    pub const Alert = enum(u32) { off, on };

    /// A re-representation of the contents of the sync directory.
    pub const Tree = struct {
        files: Win32RelativePathHashMap(Info),
        /// Applies to all files
        parent: Win32RelativePathHashMap(?Wtf16),
        /// Applies only to directories
        children: Win32RelativePathHashMap(std.ArrayList(Wtf16)),
        /// Applies only to regular files
        meta: Win32RelativePathHashMap(Metadata),
        /// Applies only to regular files
        hash: Win32RelativePathHashMap(network.FileHash),
        // TODO this should have `network.FileId` as a key
        new_events: Win32RelativePathArrayHashMap(Event),
        // TODO this should have `network.FileId` as a key
        in_progress_events: Win32RelativePathArrayHashMap(Event),

        fn deinit(tree: *Tree, allocator: Allocator) void {
            var it = tree.children.valueIterator();
            while (it.next()) |list| list.deinit(allocator);

            tree.files.deinit(allocator);
            tree.parent.deinit(allocator);
            tree.children.deinit(allocator);
            tree.meta.deinit(allocator);
            tree.hash.deinit(allocator);
            tree.new_events.deinit(allocator);
            tree.in_progress_events.deinit(allocator);

            tree.* = undefined;
        }

        pub const Info = struct {
            directory: bool,
            status: Status,
            local_file_id: w.LARGE_INTEGER,
            global_file_id: network.FileId,
        };

        pub const Status = enum {
            /// A file which was previously untracked and is now known to exist.
            ///
            /// global_file_id is undefined
            /// hash is undefined
            new,
            /// A file which is being tracked.
            tracked,
            /// A file which is being tracked, and is now known to be deleted from the filesystem.
            /// Deleting this file from the server will remove it from the database, but
            /// if the file is found once again, it may return to the "tracked" state instead.
            ///
            /// meta is undefined
            /// hash is undefined
            pending_deletion,
            /// A file whose existence is known, but will not be synced to the server for one or more reasons.
            ///
            /// meta is undefined
            /// global_file_id is undefined
            /// hash is undefined
            untracked,
        };

        pub const Metadata = struct {
            modified_time: w.LARGE_INTEGER,
            size: w.ULARGE_INTEGER,
        };

        pub const Event = enum {
            new,
            modified,
            deleted,
        };

        fn addNewRegularFile(
            tree: *Tree,
            allocator: Allocator,
            path: Wtf16,
            parent: ?Wtf16,
            local_file_id: w.LARGE_INTEGER,
            meta: Metadata,
        ) !void {
            try tree.files.ensureUnusedCapacity(allocator, 1);
            try tree.parent.ensureUnusedCapacity(allocator, 1);
            try tree.meta.ensureUnusedCapacity(allocator, 1);
            try tree.hash.ensureUnusedCapacity(allocator, 1);

            try tree.new_events.putNoClobber(allocator, path, .new);
            errdefer comptime unreachable;

            const gop = tree.files.getOrPutAssumeCapacity(path);
            if (gop.found_existing) std.debug.panic("TODO addNewRegularFile file already exists", .{});
            gop.value_ptr.* = .{
                .directory = false,
                .status = .new,
                .local_file_id = local_file_id,
                .global_file_id = undefined,
            };
            tree.parent.putAssumeCapacityNoClobber(path, parent);
            tree.meta.putAssumeCapacityNoClobber(path, meta);
            tree.hash.putAssumeCapacityNoClobber(path, undefined);
        }

        fn updateNewRegularFile(
            tree: *Tree,
            path: Wtf16,
            local_file_id: w.LARGE_INTEGER,
            meta: Metadata,
        ) void {
            const info = tree.files.getPtr(path).?;
            info.local_file_id = local_file_id;
            tree.meta.getPtr(path).?.* = meta;
        }

        fn addUntrackedRegularFile(
            tree: *Tree,
            allocator: Allocator,
            path: Wtf16,
            parent: ?Wtf16,
            local_file_id: w.LARGE_INTEGER,
        ) !void {
            try tree.files.ensureUnusedCapacity(allocator, 1);
            try tree.parent.ensureUnusedCapacity(allocator, 1);
            try tree.meta.ensureUnusedCapacity(allocator, 1);
            try tree.hash.ensureUnusedCapacity(allocator, 1);

            errdefer comptime unreachable;

            const gop = tree.files.getOrPutAssumeCapacity(path);
            if (gop.found_existing) std.debug.panic("TODO addUntrackedRegularFile file already exists", .{});
            gop.value_ptr.* = .{
                .directory = false,
                .status = .untracked,
                .local_file_id = local_file_id,
                .global_file_id = undefined,
            };
            tree.parent.putAssumeCapacityNoClobber(path, parent);
            tree.meta.putAssumeCapacityNoClobber(path, undefined);
            tree.hash.putAssumeCapacityNoClobber(path, undefined);
        }

        fn changeUntrackedRegularFileToNew(
            tree: *Tree,
            allocator: Allocator,
            path: Wtf16,
            local_file_id: w.LARGE_INTEGER,
            meta: Metadata,
        ) !void {
            const info = tree.files.getEntry(path).?;

            assert(!tree.in_progress_events.contains(path));
            try tree.new_events.putNoClobber(allocator, info.key_ptr.*, .new);
            errdefer comptime unreachable;

            info.value_ptr.status = .new;
            info.value_ptr.local_file_id = local_file_id;
            tree.meta.getPtr(path).?.* = meta;
        }

        fn updateTrackedRegularFile(
            tree: *Tree,
            allocator: Allocator,
            path: Wtf16,
            local_file_id: w.LARGE_INTEGER,
            meta: Metadata,
            hash: *const network.FileHash,
        ) !void {
            const info = tree.files.getEntry(path).?;
            const meta_ptr = tree.meta.getPtr(path).?;
            const hash_ptr = tree.hash.getPtr(path).?;

            if (info.value_ptr.local_file_id == local_file_id and
                meta_ptr.size == meta.size and
                hash_ptr.eql(hash)) return;

            if (tree.in_progress_events.contains(path)) std.debug.panic("TODO file was modified while having an event: {f}", .{path.formatUtf8()});
            try tree.new_events.putNoClobber(allocator, info.key_ptr.*, .modified);
            errdefer comptime unreachable;

            info.value_ptr.local_file_id = local_file_id;
            meta_ptr.* = meta;
            hash_ptr.* = hash.*;
        }

        fn deleteTrackedRegularFile(
            tree: *Tree,
            allocator: Allocator,
            path: Wtf16,
        ) !void {
            const info = tree.files.getEntry(path).?;

            if (tree.in_progress_events.contains(path)) std.debug.panic("TODO file was deleted while having an event: {f}", .{path.formatUtf8()});
            try tree.new_events.putNoClobber(allocator, info.key_ptr.*, .deleted);
            errdefer comptime unreachable;

            info.value_ptr.status = .pending_deletion;
            tree.meta.getPtr(path).?.* = undefined;
            tree.hash.getPtr(path).?.* = undefined;
        }
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
            .debug = .{},

            .mutex = .init,
            .allocator = allocator,
            .path_arena = .{},
            .scan_arena = .{},
            .tree = .{
                .files = .empty,
                .parent = .empty,
                .children = .empty,
                .meta = .empty,
                .hash = .empty,
                .new_events = .empty,
                .in_progress_events = .empty,
            },

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

        var path_arena = db.path_arena.promote(db.allocator);
        path_arena.deinit();
        var scan_arena = db.scan_arena.promote(db.allocator);
        scan_arena.deinit();

        db.tree.deinit(db.allocator);

        db.* = undefined;
    }

    pub fn run(db: *Database, io: Io) !void {
        var stderr = Io.File.stderr().writer(io, &.{});

        const clock: Io.Clock = .boot;
        const max_wait_time = Io.Clock.Duration{ .raw = .fromSeconds(8), .clock = clock };
        var next_scan_time = Io.Clock.Timestamp.now(io, clock); // First scan happens immediately

        while (true) {
            // If enough time has passed, do a scan
            if (Io.Clock.Timestamp.now(io, .boot).compare(.gte, next_scan_time)) {
                try scan.run(db, io);
                try stderr.interface.writeAll("Scan complete\n");
                try db.debug.printFileEvents(&stderr.interface, io);
                try stderr.interface.flush();
                next_scan_time = Io.Clock.Timestamp.now(io, clock).addDuration(max_wait_time);
                continue;
            }

            if (db.sendHostEvents(io)) {
                continue;
            } else |err| switch (err) {
                error.NoEvents => {},
                error.OutOfMemory, error.Canceled => |e| return e,
            }

            db.alert.store(.off, .release);
            try io.futexWaitTimeout(Alert, &db.alert.raw, .off, .{ .deadline = next_scan_time });
        }
    }

    fn sendHostEvents(db: *Database, io: Io) (error{NoEvents} || Allocator.Error || Io.Cancelable)!void {
        const host_event: Host.State.Event = blk: {
            // TODO no mutex
            try db.mutex.lock(io);
            defer db.mutex.unlock(io);

            if (db.tree.new_events.count() == 0) return error.NoEvents;
            try db.tree.in_progress_events.ensureUnusedCapacity(db.allocator, 1);
            db.acquireHostEvent() orelse return error.NoEvents;
            errdefer comptime unreachable;

            const kv = db.tree.new_events.pop().?;
            const info = db.tree.files.get(kv.key).?;
            assert(!info.directory);
            db.tree.in_progress_events.putAssumeCapacityNoClobber(kv.key, kv.value);
            switch (kv.value) {
                .new => {
                    switch (info.status) {
                        .new => {},
                        .tracked, .pending_deletion, .untracked => unreachable,
                    }
                    db.out_path = kv.key;
                    break :blk .get_global_file_id;
                },
                .modified => {
                    switch (info.status) {
                        .tracked => {},
                        .new, .untracked, .pending_deletion => unreachable,
                    }
                    db.out_file_id = info.global_file_id;
                    db.out_path = kv.key;
                    db.out_metadata = .{
                        .size = db.tree.meta.get(kv.key).?.size,
                        .hash = db.tree.hash.get(kv.key).?,
                    };
                    break :blk .sync_file;
                },
                .deleted => {
                    switch (info.status) {
                        .pending_deletion => {},
                        .new, .tracked, .untracked => unreachable,
                    }
                    db.out_file_id = info.global_file_id;
                    db.out_path = kv.key;
                    break :blk .delete_file;
                },
            }
        };

        db.releaseHostEvent(host_event);
        io.futexWake(Host.State, &db.host_state.raw, 1);
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

    pub fn manualScan(db: *Database, io: Io) !void {
        try scan.run(db, io);
    }

    // called from Host
    fn setNewFileId(db: *Database, path: Wtf16, global_file_id: network.FileId, io: Io) !void {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        assert(db.tree.in_progress_events.fetchSwapRemove(path).?.value == .new);

        const info = db.tree.files.getPtr(path) orelse
            std.debug.panic("received file id for unknown file: {f}", .{path.formatUtf8()});
        // TODO make sure this is actually the same file that the event was created for
        switch (info.status) {
            .new => {},
            .tracked, .pending_deletion, .untracked => std.debug.panic("TODO: handle new file id for non-new file", .{}),
        }

        // TODO: create a Database event that will compute the hash later
        const hash = blk: {
            const file = try wave.windows.openFile(db.sync_dir, path, .read);
            defer w.CloseHandle(file);

            const Information = w.FILE.STANDARD_INFORMATION;
            var information: Information = undefined;
            var iosb: w.IO_STATUS_BLOCK = undefined;
            const status = w.ntdll.NtQueryInformationFile(file, &iosb, &information, @sizeOf(Information), .Standard);
            switch (status) {
                .SUCCESS => {},
                else => return w.unexpectedStatus(status),
            }

            break :blk try computeFileHash(file, information.EndOfFile);
        };

        try db.tree.new_events.ensureUnusedCapacity(db.allocator, 1);
        errdefer comptime unreachable;

        info.status = .tracked;
        info.global_file_id = global_file_id;
        db.tree.hash.getPtr(path).?.* = hash;
        db.tree.new_events.putAssumeCapacityNoClobber(path, .modified);

        db.sendAlert(io);
    }

    // called from Host
    fn confirmDeleteFile(db: *Database, path: Wtf16, io: Io) !void {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        assert(db.tree.in_progress_events.fetchSwapRemove(path).?.value == .deleted);

        const info = db.tree.files.getEntry(path) orelse
            std.debug.panic("received delete confirmation for unknown file: {f}", .{path.formatUtf8()});
        // TODO make sure this is actually the same file that the event was created for
        switch (info.value_ptr.status) {
            .pending_deletion => {},
            .new, .tracked, .untracked => std.debug.panic("TODO: handle new file id for non-pending-delete file", .{}),
        }

        db.tree.files.removeByPtr(info.key_ptr);
    }

    // called from Host
    fn markFileAsSynced(db: *Database, path: Wtf16, io: Io) !void {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        assert(db.tree.in_progress_events.fetchSwapRemove(path).?.value == .modified);
    }

    fn openFileReadOnly(db: *const Database, path: Wtf16) !w.HANDLE {
        return wave.windows.openFile(db.sync_dir, path, .read);
    }

    fn closeFile(_: *const Database, file: w.HANDLE) void {
        w.CloseHandle(file);
    }

    pub const Debug = struct {
        pub fn printFileEntries(debug: *Debug, writer: *Io.Writer, io: Io) !void {
            const db: *Database = @alignCast(@fieldParentPtr("debug", debug));
            try db.mutex.lock(io);
            defer db.mutex.unlock(io);

            try writer.writeAll("Tracked files\n");
            var it = db.tree.files.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.status) {
                    .tracked => {},
                    .new, .pending_deletion, .untracked => continue,
                }
                const meta = db.tree.meta.get(entry.key_ptr.*).?;
                try writer.print(
                    "{f}: modified({}) size({}) hash({?f})\n",
                    .{
                        entry.key_ptr.formatUtf8(),
                        meta.modified_time,
                        meta.size,
                        db.tree.hash.get(entry.key_ptr.*),
                    },
                );
            }

            try writer.writeAll("New files\n");
            it = db.tree.files.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.status) {
                    .new => {},
                    .tracked, .pending_deletion, .untracked => continue,
                }
                const meta = db.tree.meta.get(entry.key_ptr.*).?;
                try writer.print(
                    "{f}: modified({}) size({})\n",
                    .{
                        entry.key_ptr.formatUtf8(),
                        meta.modified_time,
                        meta.size,
                    },
                );
            }

            try writer.writeAll("\nUntracked files\n");
            it = db.tree.files.iterator();
            while (it.next()) |entry| {
                switch (entry.value_ptr.status) {
                    .new, .tracked => continue,
                    .pending_deletion, .untracked => {},
                }
                try writer.print("{f}\n", .{entry.key_ptr.formatUtf8()});
            }

            try writer.writeAll("\n");
        }

        pub fn printFileEvents(debug: *Debug, writer: *Io.Writer, io: Io) !void {
            const db: *Database = @alignCast(@fieldParentPtr("debug", debug));
            try db.mutex.lock(io);
            defer db.mutex.unlock(io);

            inline for (&[_]struct { Tree.Event, []const u8 }{
                .{ .new, "Locally new files:\n" },
                .{ .modified, "Locally modified files:\n" },
                .{ .deleted, "Locally deleted files:\n" },
            }) |item| {
                const status, const text = item;
                try writer.writeAll(text);
                {
                    var it = db.tree.new_events.iterator();
                    while (it.next()) |entry| {
                        if (entry.value_ptr.* != status) continue;
                        try writer.print("\t{f}\n", .{entry.key_ptr.formatUtf8()});
                    }
                }
                {
                    var it = db.tree.in_progress_events.iterator();
                    while (it.next()) |entry| {
                        if (entry.value_ptr.* != status) continue;
                        try writer.print("\t{f} (P)\n", .{entry.key_ptr.formatUtf8()});
                    }
                }
            }
        }
    };
};

const scan = struct {
    const Context = struct {
        arena: *std.heap.ArenaAllocator,
        pending_dirs: std.ArrayList(Wtf16),
        sub_path: std.ArrayList(w.WCHAR),
        component_delimeters: std.ArrayList(u16),
        open_dir_handles: std.ArrayList(w.HANDLE),
        parent_paths: std.ArrayList(?Wtf16),
        set_of_tracked_files: SetOfTrackedFiles,

        const SetOfTrackedFiles = Win32RelativePathHashMap(struct {
            status: Database.Tree.Status,
            already_seen: bool,
        });
    };

    fn initContext(db: *const Database, arena: *std.heap.ArenaAllocator) !Context {
        const allocator = arena.allocator();

        var parent_paths: std.ArrayList(?Wtf16) = .empty;
        try parent_paths.append(allocator, null);

        var open_dir_handles: std.ArrayList(w.HANDLE) = .empty;
        try open_dir_handles.append(allocator, db.sync_dir);

        var set_of_tracked_files: Context.SetOfTrackedFiles = .empty;
        try set_of_tracked_files.ensureTotalCapacity(allocator, db.tree.files.count());
        var it = db.tree.files.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.directory) continue;
            const status = entry.value_ptr.status;
            set_of_tracked_files.putAssumeCapacityNoClobber(entry.key_ptr.*, .{ .status = status, .already_seen = false });
        }

        return .{
            .arena = arena,
            .pending_dirs = .empty,
            .sub_path = .empty,
            .component_delimeters = .empty,
            .open_dir_handles = open_dir_handles,
            .parent_paths = parent_paths,
            .set_of_tracked_files = set_of_tracked_files,
        };
    }

    fn deinitContext(ctx: *Context) void {
        for (ctx.open_dir_handles.items[1..]) |handle| {
            w.CloseHandle(handle);
        }
        ctx.* = undefined;
    }

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

    fn run(db: *Database, io: Io) !void {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        var arena = db.scan_arena.promote(db.allocator);
        defer {
            _ = arena.reset(.retain_capacity);
            db.scan_arena = arena.state;
        }

        var ctx = try initContext(db, &arena);
        defer deinitContext(&ctx);

        try scanOneDirectory(db, &ctx);
        while (ctx.pending_dirs.items.len > 0) {
            const dir_path_ptr = &ctx.pending_dirs.items[ctx.pending_dirs.items.len - 1];
            if (dir_path_ptr.slice.len == 0) {
                _ = ctx.pending_dirs.pop();
                exitDir(&ctx);
                continue;
            }

            const dir_path = dir_path_ptr.*;
            dir_path_ptr.* = .{ .slice = &.{} };
            try enterDir(&ctx, db, dir_path);
            try scanOneDirectory(db, &ctx);
        }

        try deleteFiles(db, &ctx);
    }

    fn scanOneDirectory(db: *Database, ctx: *Context) !void {
        const dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
        var buffer: [64 * 1024]u8 align(@alignOf(NtQueryInformation)) = undefined;
        var io_status_block: w.IO_STATUS_BLOCK = undefined;
        var restart_scan: w.BOOLEAN = .TRUE;

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
                .FALSE,
                null,
                restart_scan,
            );
            switch (status) {
                .NO_MORE_FILES => break,
                .BUFFER_OVERFLOW => return error.NtBufferOverflow,
                .SUCCESS => if (io_status_block.Information == 0) return error.NtBufferOverflow,
                else => return w.unexpectedStatus(status),
            }
            restart_scan = .FALSE;

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

                try processFile(db, ctx, file_name, info);
            }
        }
    }

    fn processFile(
        db: *Database,
        ctx: *Context,
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
        // TODO: Use @backingInt https://codeberg.org/ziglang/zig/issues/35602
        const set_to_untracked = @as(w.ULONG, @bitCast(rejected)) & @as(w.ULONG, @bitCast(information.FileAttributes)) != 0;

        if (information.FileAttributes.DIRECTORY) {
            if (set_to_untracked) return;

            const component_count: wave.PathComponentCount = @intCast(ctx.open_dir_handles.items.len - 1); // Don't count the sync dir itself as a component.
            if (component_count == wave.max_path_components) return; // TODO: track the folder, but don't track its contents.

            const allocator = ctx.arena.allocator();
            const copied_name = try name.dupe(allocator);
            try ctx.pending_dirs.append(allocator, copied_name);
        } else {
            const allocator = ctx.arena.allocator();
            const component_delimeter_index = ctx.sub_path.items.len;
            defer ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
            try ctx.sub_path.appendSlice(allocator, name.slice);
            const path: Wtf16 = .wtf16Cast(ctx.sub_path.items);

            try processRegularFile(db, ctx, path, information, set_to_untracked);
        }
    }

    fn enterDir(ctx: *Context, db: *Database, dir_path: Wtf16) !void {
        const delimeter = comptime wtf16("\\");
        const allocator = ctx.arena.allocator();
        try ctx.component_delimeters.ensureTotalCapacity(allocator, 1);
        try ctx.sub_path.ensureUnusedCapacity(allocator, dir_path.slice.len + delimeter.len);
        try ctx.parent_paths.ensureUnusedCapacity(allocator, 1);
        try ctx.open_dir_handles.ensureUnusedCapacity(allocator, 1);

        ctx.component_delimeters.appendAssumeCapacity(@intCast(ctx.sub_path.items.len));
        ctx.sub_path.appendSliceAssumeCapacity(dir_path.slice);
        const parent_path_temp = ctx.sub_path.items;
        ctx.sub_path.appendSliceAssumeCapacity(delimeter);

        var path_arena = db.path_arena.promote(db.allocator);
        defer db.path_arena = path_arena.state;
        const key = db.tree.files.getKey(.wtf16Cast(parent_path_temp));
        const parent_path = key orelse Wtf16.wtf16Cast(try path_arena.allocator().dupe(w.WCHAR, parent_path_temp));
        errdefer if (key == null) path_arena.allocator().free(parent_path.slice);
        ctx.parent_paths.appendAssumeCapacity(parent_path);

        const parent_dir = ctx.open_dir_handles.items[ctx.open_dir_handles.items.len - 1];
        const dir = try wave.windows.openDir(parent_dir, dir_path);
        errdefer comptime unreachable;
        ctx.open_dir_handles.appendAssumeCapacity(dir);
    }

    fn exitDir(ctx: *Context) void {
        const component_delimeter_index = ctx.component_delimeters.pop().?;
        ctx.sub_path.shrinkRetainingCapacity(component_delimeter_index);
        _ = ctx.parent_paths.pop();
        const dir = ctx.open_dir_handles.pop().?;
        w.CloseHandle(dir);
    }

    fn processRegularFile(
        db: *Database,
        ctx: *Context,
        path: Wtf16,
        information: *const NtQueryInformation,
        set_to_untracked: bool,
    ) !void {
        const local_file_id = information.FileId;
        const size = std.math.cast(w.ULARGE_INTEGER, information.EndOfFile) orelse return error.Unexpected;
        const meta = Database.Tree.Metadata{
            .modified_time = information.ChangeTime,
            .size = size,
        };

        const allocator = ctx.arena.allocator();
        const gop = try ctx.set_of_tracked_files.getOrPut(allocator, path);
        if (gop.found_existing) {
            if (gop.value_ptr.already_seen) std.debug.panic("TODO saw file more than once while scanning: {f}", .{path.formatUtf8()});
            gop.value_ptr.already_seen = true;

            switch (gop.value_ptr.status) {
                .new => {
                    if (set_to_untracked) std.debug.panic("TODO set a new file to untracked: {f}", .{path.formatUtf8()});
                    db.tree.updateNewRegularFile(path, local_file_id, meta);
                },
                .untracked => {
                    if (set_to_untracked) return;
                    try db.tree.changeUntrackedRegularFileToNew(db.allocator, path, local_file_id, meta);
                    gop.value_ptr.status = .new;
                },
                .pending_deletion => {
                    if (set_to_untracked) return;
                    std.debug.panic("TODO: file was created while pending deletion: {f}", .{path.formatUtf8()});
                },
                .tracked => {
                    if (set_to_untracked) {
                        try db.tree.deleteTrackedRegularFile(db.allocator, path);
                        gop.value_ptr.status = .pending_deletion;
                    } else {
                        // TODO: mark the file's hash as stale, compute it later
                        const hash = blk: {
                            const file = try wave.windows.openFile(db.sync_dir, path, .read);
                            defer w.CloseHandle(file);
                            break :blk try computeFileHash(file, information.EndOfFile);
                        };

                        try db.tree.updateTrackedRegularFile(db.allocator, path, local_file_id, meta, &hash);
                    }
                },
            }
        } else {
            errdefer ctx.set_of_tracked_files.removeByPtr(gop.key_ptr);
            var path_arena = db.path_arena.promote(db.allocator);
            defer db.path_arena = path_arena.state;
            const file_path_allocator = path_arena.allocator();

            const path_copy = try path.dupe(file_path_allocator);
            errdefer file_path_allocator.free(path_copy.slice);

            gop.key_ptr.* = path_copy;
            gop.value_ptr.* = .{ .status = undefined, .already_seen = true };

            const parent = ctx.parent_paths.getLast();
            if (set_to_untracked) {
                try db.tree.addUntrackedRegularFile(db.allocator, path_copy, parent, local_file_id);
                gop.value_ptr.status = .untracked;
            } else {
                try db.tree.addNewRegularFile(db.allocator, path_copy, parent, local_file_id, meta);
                gop.value_ptr.status = .new;
            }
        }
    }

    fn deleteFiles(db: *Database, ctx: *Context) !void {
        var it = ctx.set_of_tracked_files.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.already_seen) continue;
            const path = entry.key_ptr.*;
            switch (entry.value_ptr.status) {
                .new => std.debug.panic("TODO delete a new file: {f}", .{path.formatUtf8()}),
                .tracked => try db.tree.deleteTrackedRegularFile(db.allocator, path),
                .pending_deletion => {},
                .untracked => std.debug.panic("TODO delete and untracked file: {f}", .{path.formatUtf8()}),
            }
        }
    }
};

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
    // TODO: the file could have been modified by another thread, making this assertion false; consider locking
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
        send_error: ?SendMessagesError = null,
        recv_error: ?ReceiveMessagesError = null,
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
                send_error: SendMessagesError!void,
                recv_error: ReceiveMessagesError!void,
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

        try select.concurrent(.send_error, sendMessages, .{ host, .init(writer), io });
        try select.concurrent(.recv_error, receiveMessages, .{ host, .init(reader), io });

        host.debugLog("started", .{});
        ns.addToDiagnostics(diag, try select.await());
    }

    pub const SendMessagesError = Io.Writer.Error || Io.Cancelable || wave.windows.SendFileError;

    fn sendMessages(host: *Host, writer: network.Writer, io: Io) SendMessagesError!void {
        // TODO: Send an initial message containing protocol version, etc.
        // TODO: Send a nonce value with each transaction
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

    pub const ReceiveMessagesError = error{
        InvalidTxId,
        InvalidPeerTxId,
        WrongTxId,
        WrongPeerTxId,
        InvalidAction,
        InvalidHeader,
    } || network.Reader.ReceiveActionError || network.Reader.ReceiveFileMetadataError || network.Reader.ReceiveNewFilePathError || network.Reader.ReceiveResolvePathResponseError ||
        Io.Cancelable || Allocator.Error || AddOutgoingTxError || wave.windows.ReceiveFileError;

    fn receiveMessages(host: *Host, reader: network.Reader, io: Io) ReceiveMessagesError!void {
        while (true) {
            const header = try reader.receiveMessageHeader();
            if (header.tag == .disconnect) break;
            const action = try reader.receiveAction();
            host.logMessage(.incoming, header.tx_id, action, header.peer_tx_id);

            switch (header.tag) {
                .disconnect => unreachable,
                .new_tx => {
                    if (header.tx_id != .invalid) return error.InvalidTxId;
                    if (header.peer_tx_id == .invalid) return error.InvalidPeerTxId;
                    return error.InvalidAction;
                },
                .new_tx_reply => {
                    if (@intFromEnum(header.tx_id) != 0) return error.WrongTxId; // TODO: hardcoded value
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
        // TODO: This function might need to be `acq_rel` instead of `release`
        assert(@intFromEnum(tx_id) == 0); // TODO: hardcoded value
        switch (to) {
            .init, .acquired => comptime unreachable,
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
            writer: network.Writer,
        ) !void {
            assert(out_new_file.state == .send_path);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .resolve_path;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            out_new_file.state = .receive_decision;
            host.flipTransaction(.incoming, tx_id, io);

            try writer.sendMessageHeaderNewTx(tx_id);
            try writer.sendAction(action);
            try writer.sendFileKind(.regular); // TODO hardcoded value
            try writer.sendNewFilePath(
                switch (cpu_endian) {
                    .big => @compileError("TODO big endian"),
                    .little => .wtf16le,
                },
                @ptrCast(out_new_file.path.slice),
            );
            try writer.flush();
        }

        fn receiveDecision(
            out_new_file: *const OutNewFile,
            host: *Host,
            reader: network.Reader,
            io: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(out_new_file.state == .receive_decision);
            if (peer_tx_id != .invalid) return error.InvalidPeerTxId;
            if (action != .resolve_path_response) return error.InvalidAction;

            const response = try reader.receiveResolvePathResponse();
            switch (response) {
                .success => {
                    const num_path_components = blk: {
                        const Iterator = std.fs.path.ComponentIterator(.windows, u16);
                        var it = Iterator.init(out_new_file.path.slice);
                        var count: u64 = 0;
                        while (it.next()) |_| count += 1;
                        break :blk count;
                    };
                    assert(num_path_components > 0);
                    const file_id = try reader.receiveFileId();
                    for (0..num_path_components - 1) |_| {
                        // TODO dont discard
                        _ = try reader.receiveFileId();
                    }

                    host.debugLog("received file id {} for file {f}\n", .{ @intFromEnum(file_id), out_new_file.path.formatUtf8() });
                    try host.db.setNewFileId(out_new_file.path, file_id, io);
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                else => {
                    host.debugLog("error '{s}' while resolving path {f}\n", .{ @tagName(response), out_new_file.path.formatUtf8() });
                    host.deleteTransaction(tx_id, .incoming, io);
                },
            }
        }
    };

    pub const OutFileContents = struct {
        state: State,
        file_id: network.FileId,
        path: Wtf16, // TODO: this field shouldn't be needed
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
            writer: network.Writer,
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

            out_file_contents.state = .receive_decision;
            host.flipTransaction(.incoming, tx_id, io);

            try writer.sendMessageHeaderNewTx(tx_id);
            try writer.sendAction(action);
            try writer.sendFileMetadata(out_file_contents.file_id, file_size, &out_file_contents.hash);
            try writer.flush();
        }

        fn receiveDecision(
            out_file_contents: *OutFileContents,
            host: *Host,
            _: network.Reader,
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
            writer: network.Writer,
        ) !void {
            assert(out_file_contents.state == .send_file_contents);

            const action: network.Action = .transfer_file_contents;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            const handle = try host.db.openFileReadOnly(out_file_contents.path);
            defer host.db.closeFile(handle);

            out_file_contents.state = .receive_result;
            host.flipTransaction(.incoming, tx_id, io);

            try writer.sendMessageHeaderExistingTx(peer_tx_id);
            try writer.sendAction(action);
            try wave.windows.sendFile(writer.io, handle, out_file_contents.size);
            try writer.flush();
        }

        fn receiveResult(
            out_file_contents: *const OutFileContents,
            host: *Host,
            _: network.Reader,
            io: Io,
            tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            switch (action) {
                .transfer_file_success => {
                    try host.db.markFileAsSynced(out_file_contents.path, io);
                    host.debugLog("successfully synced file: {f}\n", .{out_file_contents.path.formatUtf8()});
                },
                .transfer_file_failure => {
                    // TODO mark file as failed to sync
                    try host.db.markFileAsSynced(out_file_contents.path, io);
                    host.debugLog("failed to sync file: {f}\n", .{out_file_contents.path.formatUtf8()});
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
            writer: network.Writer,
        ) !void {
            assert(out_delete_file.state == .send_file_id);
            assert(peer_tx_id == .invalid);

            const action: network.Action = .delete_file;
            host.logMessage(.outgoing, tx_id, action, peer_tx_id);

            out_delete_file.state = .receive_confirmation;
            host.flipTransaction(.incoming, tx_id, io);

            try writer.sendMessageHeaderNewTx(tx_id);
            try writer.sendAction(action);
            try writer.sendFileId(out_delete_file.file_id);
            try writer.flush();
        }

        fn receiveConfirmation(
            out_delete_file: *OutDeleteFile,
            host: *Host,
            _: network.Reader,
            io: Io,
            tx_id: network.TransactionId,
            peer_tx_id: network.TransactionId,
            action: network.Action,
        ) !void {
            assert(out_delete_file.state == .receive_confirmation);
            if (peer_tx_id != .invalid) return error.WrongPeerTxId;

            switch (action) {
                .delete_file_confirm => {
                    try host.db.confirmDeleteFile(out_delete_file.path, io);
                    host.deleteTransaction(tx_id, .incoming, io);
                },
                else => return error.InvalidAction,
            }
        }
    };
};
