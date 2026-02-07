const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The endianness of message contents, except for file paths, which have their own encoding.
pub const endian: std.builtin.Endian = .little;

pub const TransactionId = enum(u32) {
    new = 0xfffffffe,
    disconnect = 0xffffffff,
    _,

    pub fn format(tx_id: TransactionId, writer: *Io.Writer) Io.Writer.Error!void {
        if (std.enums.tagName(TransactionId, tx_id)) |name| {
            try writer.writeAll(name);
        } else {
            try writer.print("{}", .{@intFromEnum(tx_id)});
        }
    }
};

pub const Action = enum(u8) {
    transfer_file_metadata,
    transfer_file_accept,
    transfer_file_decline,
    transfer_file_contents,
    transfer_file_success,
    transfer_file_failure,
};

pub const FileHash = struct {
    blake3: [byte_size]u8,

    pub const byte_size = 32;

    pub fn format(hash: FileHash, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print("{x}", .{std.mem.nativeToBig(@Int(.unsigned, byte_size * 8), @bitCast(hash.blake3))});
    }
};

pub const FileSize = u64;

pub const PathEncoding = enum(u8) {
    wtf16le,
};

pub const PathLenInBytes = u16;

pub const FilePathBuffer = [1 << @bitSizeOf(PathLenInBytes)]u8;

/// Asserts a writer buffer size of at least `@sizeOf(TransactionId)`.
pub fn sendTransactionId(writer: *Io.Writer, id: TransactionId) !void {
    try writer.writeInt(std.meta.Tag(TransactionId), @intFromEnum(id), endian);
}

/// Asserts a writer buffer size of at least 1.
pub fn sendAction(writer: *Io.Writer, action: Action) !void {
    try writer.writeByte(@intFromEnum(action));
}

/// Asserts a writer buffer size of at least `@sizeOf(FileSize)`.
pub fn sendFileMetadata(
    writer: *Io.Writer,
    path_encoding: PathEncoding,
    path: []const u8, // TODO: Make a Path struct
    file_size: FileSize,
    hash: *const FileHash,
) !void {
    try writer.writeByte(@intFromEnum(path_encoding));
    try writer.writeInt(PathLenInBytes, @intCast(path.len), endian);
    try writer.writeInt(FileSize, file_size, endian);
    try writer.writeAll(&hash.blake3);
    try writer.writeAll(path);
}

/// Asserts a reader buffer size of at least `@sizeOf(TransactionId)`.
/// `null` means disconnect.
pub fn receiveTransactionId(reader: *Io.Reader) !?TransactionId {
    const id: TransactionId = @enumFromInt(try reader.takeInt(std.meta.Tag(TransactionId), endian));
    switch (id) {
        .disconnect => return null,
        .new, _ => return id,
    }
}

/// Asserts a reader buffer size of at least 1.
pub fn receiveAction(reader: *Io.Reader) !Action {
    return @enumFromInt(try reader.takeByte());
}

pub const IncomingFileMetadata = struct {
    path_encoding: PathEncoding,
    path_len_bytes: PathLenInBytes,
    file_size: FileSize,
    hash: FileHash,
};

/// Asserts a reader buffer size of at least `FileHash.byte_size`.
pub fn receiveFileMetadata(reader: *Io.Reader, file_path_buffer: *FilePathBuffer) !IncomingFileMetadata {
    const path_encoding: PathEncoding = @enumFromInt(try reader.takeByte());
    const path_len_bytes = try reader.takeInt(PathLenInBytes, endian);
    const file_size = try reader.takeInt(FileSize, endian);

    const hash_bytes = try reader.takeArray(FileHash.byte_size);
    const hash: FileHash = .{ .blake3 = hash_bytes.* };

    var file_path_writer: Io.Writer = .fixed(file_path_buffer);
    try reader.streamExact(&file_path_writer, path_len_bytes);

    return .{
        .path_encoding = path_encoding,
        .path_len_bytes = path_len_bytes,
        .file_size = file_size,
        .hash = hash,
    };
}
