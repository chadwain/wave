const std = @import("std");
const assert = std.debug.assert;
const w = std.os.windows;
const Allocator = std.mem.Allocator;
const Io = std.Io;

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

    pub fn formatWtf16AsUtf8(slice: []const w.WCHAR, writer: *Io.Writer) Io.Writer.Error!void {
        switch (cpu_endian) {
            .little => try writer.print("{f}", .{std.unicode.fmtUtf16Le(slice)}),
            .big => @compileError("TODO big endian"),
        }
    }

    pub const Wtf8Path = struct {
        buffer: [max_len]u8,
        len: u16,

        const max_len = w.MAX_PATH * 4;

        pub fn slice(path: *const Wtf8Path) []const u8 {
            return (&path.buffer)[0..path.len];
        }
    };

    pub const ToWtf8PathError = error{PathTooLong};

    pub fn toWtf8Path(self: Wtf16) ToWtf8PathError!Wtf8Path {
        if (cpu_endian != .little) @compileError("TODO big endian");
        const len = std.unicode.calcWtf8Len(self.slice);
        if (len > Wtf8Path.max_len) return error.PathTooLong;
        var path: Wtf8Path = .{ .buffer = undefined, .len = @intCast(len) };
        assert(std.unicode.wtf16LeToWtf8(&path.buffer, self.slice) == len);
        return path;
    }
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

/// Opens a directory capable of async operations and being waited on.
pub fn openDir(parent: ?w.HANDLE, path: Wtf16) !w.HANDLE {
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

pub const OpenFileOptions = union(enum) {
    read,
    create: struct {
        initial_size: w.LARGE_INTEGER,
    },
};

pub fn openFile(parent: ?w.HANDLE, path: Wtf16, options: OpenFileOptions) !w.HANDLE {
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

pub const SendFileError = Io.Writer.Error || Io.UnexpectedError;

pub fn sendFile(
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

pub const ReceiveFileError = Io.Reader.Error || Io.UnexpectedError;

pub fn receiveFile(
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
