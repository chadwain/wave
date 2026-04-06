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

    fn formatWtf16AsUtf8(slice: []const w.WCHAR, writer: *Io.Writer) Io.Writer.Error!void {
        switch (cpu_endian) {
            .little => try writer.print("{f}", .{std.unicode.fmtUtf16Le(slice)}),
            .big => @compileError("TODO big endian"),
        }
    }

    const Wtf8Path = struct {
        buffer: [max_len]u8,
        len: u16,

        const max_len = w.MAX_PATH * 4;

        fn slice(path: *const Wtf8Path) []const u8 {
            return (&path.buffer)[0..path.len];
        }
    };

    const ToWtf8PathError = error{PathTooLong};

    fn toWtf8Path(self: Wtf16) ToWtf8PathError!Wtf8Path {
        if (cpu_endian != .little) @compileError("TODO big endian");
        const len = std.unicode.calcWtf8Len(self.slice);
        if (len > Wtf8Path.max_len) return error.PathTooLong;
        var path: Wtf8Path = .{ .buffer = undefined, .len = @intCast(len) };
        assert(std.unicode.wtf16LeToWtf8(&path.buffer, self.slice) == len);
        return path;
    }
};

pub const Database = struct {
    // Server and Client fields
    sync_dir: w.HANDLE,
    sync_dir_io: Io.Dir,
    allocator: Allocator,
    mutex: Io.Mutex, // TODO: Compare with RwLock
    debug: Debug,

    // Server and Client fields
    file_path_arena: std.heap.ArenaAllocator.State,
    file_id_map: Win32RelativePathHashMap(network.FileId),

    // Server only
    next_file_id: ?std.meta.Tag(network.FileId),
    server_known_files: std.AutoHashMapUnmanaged(network.FileId, ServerFileEntry),

    // Client only
    client_known_files: Win32RelativePathHashMap(ClientFileEntry),
    awaiting_sync_files: Win32RelativePathHashMap(void), // TODO change to a key value type of `FileId`
    new_files: Win32RelativePathHashMap(void),
    deleted_files: std.ArrayList(struct { Wtf16, network.FileId }),
    scan_arena: std.heap.ArenaAllocator.State,

    // Database-Host synchronization fields (client only)
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

    pub const ServerFileState = enum { unsynced, synced };

    pub const ServerFileEntry = struct {
        path: Wtf16,
        state: ServerFileState,
        metadata: FileMetadata,
    };

    pub fn Win32RelativePathHashMap(comptime V: type) type {
        // TODO: hash and eql functions don't agree on path normalization rules
        const Context = struct {
            pub fn hash(_: @This(), self: Wtf16) u32 {
                // TODO: more efficient hashing
                var hasher = std.hash.Wyhash.init(0);
                for (self.slice) |c| {
                    // TODO get a userspace implementation of RtlUpcaseUnicodeChar
                    const uppercase = w.ntdll.RtlUpcaseUnicodeChar(c);
                    std.hash.autoHash(&hasher, uppercase);
                }
                return @truncate(hasher.final());
            }

            pub fn eql(_: @This(), a: Wtf16, b: Wtf16) bool {
                // TODO get a userspace implementation of RtlEqualUnicodeString
                return w.ntdll.RtlEqualUnicodeString(&.init(a.slice), &.init(b.slice), w.TRUE) == w.TRUE;
            }
        };
        return std.HashMapUnmanaged(Wtf16, V, Context, std.hash_map.default_max_load_percentage);
    }

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
            break :blk try openDir(null, .wtf16Cast(normalized));
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

            .next_file_id = 1,
            .server_known_files = .empty,

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

        db.server_known_files.deinit(db.allocator);

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

    const NewFileResult = union(enum) {
        file_id: network.FileId,
        file_already_exists,
        exhausted_file_ids,
    };

    // server
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

        try db.server_known_files.ensureUnusedCapacity(db.allocator, 1);
        errdefer comptime unreachable;

        db.server_known_files.putAssumeCapacityNoClobber(file_id, .{
            .path = path_copy,
            .state = .unsynced,
            .metadata = undefined,
        });
        gop.key_ptr.* = path_copy;
        gop.value_ptr.* = file_id;

        return .{ .file_id = file_id };
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

    // server
    fn checkMetadata(
        db: *Database,
        metadata: *const network.IncomingFileMetadata,
        io: Io,
    ) !CheckMetadataResult {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        const entry = db.server_known_files.getPtr(metadata.file_id) orelse return .file_doesnt_exist;
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
        return openFile(db.sync_dir, path, .read);
    }

    const CreateFileError = Io.Dir.CreateDirPathError || Wtf16.ToWtf8PathError || error{EmptyPath};

    // server
    // TODO create temporary files instead
    fn createFile(db: *const Database, io: Io, path: Wtf16, file_size: w.LARGE_INTEGER) CreateFileError!w.HANDLE {
        // TODO janky
        const path_wtf8 = try path.toWtf8Path();
        var it = std.fs.path.componentIterator(path_wtf8.slice());
        _ = it.last() orelse return error.EmptyPath;
        if (it.previous()) |previous| {
            try db.sync_dir_io.createDirPath(io, previous.path);
        }

        return openFile(
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

        const entry = db.server_known_files.getPtr(file_id).?;
        entry.metadata = .{
            .local_file_id = internal_information.IndexNumber,
            .hash = hash.*,
            .modified_time = basic_information.ChangeTime,
            .size = @intCast(file_size),
        };
        entry.state = .synced;
    }

    const ServerDeleteGlobalFileResult = union(enum) {
        success,
        unknown_file,
        delete_file_err: Io.Dir.DeleteFileError,
    };

    fn serverDeleteGlobalFile(db: *Database, file_id: network.FileId, io: Io) !ServerDeleteGlobalFileResult {
        try db.mutex.lock(io);
        defer db.mutex.unlock(io);

        const entry = db.server_known_files.fetchRemove(file_id) orelse return .unknown_file;
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
    known_files_copy: Database.Win32RelativePathHashMap(void),

    fn init(db: *const Database, arena: *std.heap.ArenaAllocator) !FullScanContext {
        const allocator = arena.allocator();

        var open_dir_handles: std.ArrayList(w.HANDLE) = .empty;
        try open_dir_handles.append(allocator, db.sync_dir);

        var known_files_copy: Database.Win32RelativePathHashMap(void) = .empty;
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
            const file = try openFile(dir, name, .read);
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

/// Opens a directory capable of async operations and being waited on.
fn openDir(parent: ?w.HANDLE, path: Wtf16) !w.HANDLE {
    var handle: w.HANDLE = undefined;
    var unicode_string = w.UNICODE_STRING.init(path.slice);
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
    var unicode_string = w.UNICODE_STRING.init(path.slice);
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
    file_size: w.ULARGE_INTEGER,
) SendFileError!void {
    // TODO: Actually use sendfile or whatever it is on Windows
    var iosb: w.IO_STATUS_BLOCK = undefined;
    var written: w.LARGE_INTEGER = 0;
    while (written < file_size) {
        const buffer = buffer: {
            const slice = try writer.writableSliceGreedy(1);
            break :buffer slice[0..@min(
                slice.len,
                file_size - @as(w.ULARGE_INTEGER, @intCast(written)),
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

// pub fn watch(sync_dir: w.HANDLE, io: Io) !void {
//     const buffer_size = 64 * 1024;
//     var buffer align(@alignOf(w.DWORD)) = @as([buffer_size]w.BYTE, undefined);
//     const notify_filters: w.FileNotifyChangeFilter = .{ .file_name = true, .dir_name = true, .last_write = true };
//     var overlapped = std.mem.zeroes(w.OVERLAPPED);

//     main: while (true) {
//         { // TODO: Try to call ReadDirectoryChanges immediately after GetOverlappedResult so that we don't miss changes
//             var bytes_returned: w.DWORD = undefined;
//             const res = w.kernel32.ReadDirectoryChangesW(
//                 sync_dir,
//                 &buffer,
//                 buffer_size,
//                 w.TRUE,
//                 notify_filters,
//                 &bytes_returned,
//                 &overlapped,
//                 null,
//             );
//             if (res == 0) return error.ReadDirectoryChanges;
//         }

//         const bytes_transferred: w.DWORD = blk: while (true) {
//             try io.sleep(.fromSeconds(1), .cpu_thread);

//             var bytes_transferred: w.DWORD = undefined;
//             const res = w.kernel32.GetOverlappedResult(sync_dir, &overlapped, &bytes_transferred, w.FALSE);
//             switch (res) {
//                 w.FALSE => switch (w.GetLastError()) {
//                     .IO_INCOMPLETE => continue,
//                     else => |err| {
//                         std.debug.print("Windows error: {s}\n", .{@tagName(err)});
//                         return error.GetOverlappedResult;
//                     },
//                 },
//                 else => {},
//             }
//             if (bytes_transferred == 0) {
//                 std.debug.print("Couldn't read directory changes\n", .{});
//                 continue :main;
//             }
//             break :blk bytes_transferred;
//         };

//         processChanges((&buffer)[0..bytes_transferred]);
//     }
// }

// fn processChanges(buffer_complete: []align(@alignOf(w.DWORD)) w.BYTE) void {
//     var ptr: [*]w.BYTE = buffer_complete.ptr;
//     while (true) {
//         const file_notify_info: *const w.FILE_NOTIFY_INFORMATION = @ptrCast(@alignCast(ptr));

//         const Action = enum(w.DWORD) {
//             added = w.FILE_ACTION_ADDED,
//             removed = w.FILE_ACTION_REMOVED,
//             modified = w.FILE_ACTION_MODIFIED,
//             renamed_old_name = w.FILE_ACTION_RENAMED_OLD_NAME,
//             renamed_new_name = w.FILE_ACTION_RENAMED_NEW_NAME,
//         };
//         const action: Action = @enumFromInt(file_notify_info.Action);

//         const file_name_begin = ptr + @sizeOf(w.FILE_NOTIFY_INFORMATION);
//         const file_name: []const w.WCHAR = @ptrCast(@alignCast(file_name_begin[0..file_notify_info.FileNameLength]));
//         std.debug.print("{s}: {f}\n", .{ @tagName(action), std.unicode.fmtUtf16Le(file_name) });

//         if (file_notify_info.NextEntryOffset == 0) break;
//         ptr += file_notify_info.NextEntryOffset;
//     }
// }

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

    pub const OutgoingError = Io.Writer.Error || Io.Cancelable || SendFileError;

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
                .in_new_file => |*in_new_file| {
                    try in_new_file.sendDecision(host, tx_id, host.tx.peer_tx_id, io, writer);
                },
                .out_file_contents => |*out_file_contents| switch (out_file_contents.state) {
                    .send_metadata => try out_file_contents.sendMetadata(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .send_file_contents => try out_file_contents.sendFileContents(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_decision, .receive_result => unreachable,
                },
                .in_file_contents => |*in_file_contents| switch (in_file_contents.state) {
                    .send_decision => try in_file_contents.sendDecision(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .send_result => try in_file_contents.sendResult(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_file_contents => unreachable,
                },
                .out_delete_file => |*out_delete_file| switch (out_delete_file.state) {
                    .send_file_id => try out_delete_file.sendFileId(host, tx_id, host.tx.peer_tx_id, io, writer),
                    .receive_confirmation => unreachable,
                },
                .in_delete_file => |*in_delete_file| {
                    try in_delete_file.sendConfirmation(host, tx_id, host.tx.peer_tx_id, io, writer);
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
        Io.Cancelable || Allocator.Error || AddOutgoingTxError || ReceiveFileError || Database.CreateFileError;

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
                        .in_new_file => unreachable,
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
                        .in_file_contents => |*in_file_contents| switch (in_file_contents.state) {
                            .receive_file_contents => return error.InvalidHeader,
                            .send_decision, .send_result => unreachable,
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
                        .in_delete_file => unreachable,
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
                        .in_new_file => unreachable,
                        .out_file_contents => |*out_file_contents| switch (out_file_contents.state) {
                            .receive_decision => return error.InvalidHeader,
                            .receive_result => {
                                try out_file_contents.receiveResult(host, reader, io, header.tx_id, action);
                            },
                            .send_metadata, .send_file_contents => unreachable,
                        },
                        .in_file_contents => |*in_file_contents| switch (in_file_contents.state) {
                            .receive_file_contents => {
                                try in_file_contents.receiveFileContents(host, reader, io, header.tx_id, action);
                            },
                            .send_decision, .send_result => unreachable,
                        },
                        .out_delete_file => |*out_delete_file| switch (out_delete_file.state) {
                            .send_file_id => unreachable,
                            .receive_confirmation => return error.InvalidHeader,
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
    in_new_file: InNewFile,

    out_file_contents: OutFileContents,
    in_file_contents: InFileContents,

    out_delete_file: OutDeleteFile,
    in_delete_file: InDeleteFile,

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
            try sendFile(writer, handle, out_file_contents.size);
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
                    try receiveFile(reader, handle, in_file_contents.size);
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

    pub const InDeleteFile = struct {
        fn newTx(
            host: *Host,
            peer_tx_id: network.TransactionId,
            io: Io,
            reader: *Io.Reader,
        ) !void {
            const file_id = try network.receiveFileId(reader);
            switch (try host.db.serverDeleteGlobalFile(file_id, io)) {
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
