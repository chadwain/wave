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
    /// A client has seen a new file on its local filesystem.
    new_file_init,
    /// The server responds to a new file message.
    new_file_response,

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

pub const FileId = u32;

pub const FileSize = u64;

pub const PathEncoding = enum(u8) {
    wtf16le,
};

pub const PathByteCount = u16;

pub const FilePathBuffer = [1 << @bitSizeOf(PathByteCount)]u8;

/// Asserts a writer buffer size of at least `@sizeOf(TransactionId)`.
pub fn sendTransactionId(writer: *Io.Writer, id: TransactionId) !void {
    try writer.writeInt(std.meta.Tag(TransactionId), @intFromEnum(id), endian);
}

/// Asserts a writer buffer size of at least 1.
pub fn sendAction(writer: *Io.Writer, action: Action) !void {
    try writer.writeByte(@intFromEnum(action));
}

/// Asserts a writer buffer size of at least `@sizeOf(FileId)`.
pub fn sendFileId(writer: *Io.Writer, id: FileId) !void {
    try writer.writeInt(FileId, id, endian);
}

/// Asserts a writer buffer size of at least `@sizeOf(PathByteCount)`.
pub fn sendNewFilePath(
    writer: *Io.Writer,
    path_encoding: PathEncoding,
    path: []const u8, // TODO: Make a Path struct
) !void {
    try writer.writeByte(@intFromEnum(path_encoding));
    try writer.writeInt(PathByteCount, @intCast(path.len), endian);
    try writer.writeAll(path);
}

/// Asserts a writer buffer size of at least `@sizeOf(FileSize)`.
/// Asserts that `path.len` can fit into a `PathByteCount`.
pub fn sendFileMetadata(
    writer: *Io.Writer,
    path_encoding: PathEncoding,
    path: []const u8, // TODO: Make a Path struct
    file_size: FileSize,
    hash: *const FileHash,
) !void {
    try writer.writeByte(@intFromEnum(path_encoding));
    try writer.writeInt(PathByteCount, @intCast(path.len), endian);
    try writer.writeInt(FileSize, file_size, endian);
    try writer.writeAll(&hash.blake3);
    try writer.writeAll(path);
}

/// Asserts a reader buffer size of at least `@sizeOf(TransactionId)`.
/// `null` means disconnect.
pub fn receiveTransactionId(reader: *Io.Reader) Io.Reader.Error!?TransactionId {
    const id: TransactionId = @enumFromInt(try reader.takeInt(std.meta.Tag(TransactionId), endian));
    switch (id) {
        .disconnect => return null,
        .new, _ => return id,
    }
}

pub const ReceiveActionError = error{UnknownAction} || Io.Reader.Error;

/// Asserts a reader buffer size of at least 1.
pub fn receiveAction(reader: *Io.Reader) ReceiveActionError!Action {
    return std.enums.fromInt(Action, try reader.takeByte()) orelse error.UnknownAction;
}

/// Asserts a reader buffer size of at least `@sizeOf(FileId)`.
pub fn receiveFileId(reader: *Io.Reader) Io.Reader.Error!FileId {
    return reader.takeInt(FileId, endian);
}

pub const IncomingNewFilePath = struct {
    path_encoding: PathEncoding,
    path_byte_count: PathByteCount,
};

pub const ReceiveNewFilePathError = error{UnknownPathEncoding} || Io.Reader.StreamError;

/// Asserts a reader buffer size of at least `FileHash.byte_size`.
pub fn receiveNewFilePath(
    reader: *Io.Reader,
    file_path_buffer: *FilePathBuffer,
) ReceiveNewFilePathError!IncomingNewFilePath {
    const path_encoding = std.enums.fromInt(PathEncoding, try reader.takeByte()) orelse
        return error.UnknownPathEncoding;
    const path_byte_count = try reader.takeInt(PathByteCount, endian);

    // TODO: Do path encoding verification here
    var file_path_writer: Io.Writer = .fixed(file_path_buffer);
    try reader.streamExact(&file_path_writer, path_byte_count);

    return .{
        .path_encoding = path_encoding,
        .path_byte_count = path_byte_count,
    };
}

pub const IncomingFileMetadata = struct {
    path_encoding: PathEncoding,
    path_byte_count: PathByteCount,
    file_size: FileSize,
    hash: FileHash,
};

pub const ReceiveFileMetadataError = error{UnknownPathEncoding} || Io.Reader.StreamError;

/// Asserts a reader buffer size of at least `FileHash.byte_size`.
pub fn receiveFileMetadata(
    reader: *Io.Reader,
    file_path_buffer: *FilePathBuffer,
) ReceiveFileMetadataError!IncomingFileMetadata {
    const path_encoding = std.enums.fromInt(PathEncoding, try reader.takeByte()) orelse
        return error.UnknownPathEncoding;
    const path_byte_count = try reader.takeInt(PathByteCount, endian);
    const file_size = try reader.takeInt(FileSize, endian);

    const hash_bytes = try reader.takeArray(FileHash.byte_size);
    const hash: FileHash = .{ .blake3 = hash_bytes.* };

    // TODO: Do path encoding verification here
    var file_path_writer: Io.Writer = .fixed(file_path_buffer);
    try reader.streamExact(&file_path_writer, path_byte_count);

    return .{
        .path_encoding = path_encoding,
        .path_byte_count = path_byte_count,
        .file_size = file_size,
        .hash = hash,
    };
}
