const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The endianness of message contents, except for file paths, which have their own encoding.
pub const endian: std.builtin.Endian = .little;

pub const MessageHeaderTag = enum(u2) {
    disconnect,
    new_tx,
    new_tx_reply,
    existing_tx,
};

pub const TransactionId = enum(u3) {
    invalid = 7,
    _,

    pub fn format(tx_id: TransactionId, writer: *Io.Writer) Io.Writer.Error!void {
        if (std.enums.tagName(TransactionId, tx_id)) |name| {
            try writer.writeAll(name);
        } else {
            try writer.print("{}", .{@intFromEnum(tx_id)});
        }
    }
};

pub const MessageHeader = packed struct(u8) {
    tag: MessageHeaderTag,
    /// The transaction ID of the destination peer.
    /// Not valid when tag is `new_tx`.
    tx_id: TransactionId,
    /// The transaction ID of the source peer.
    /// Only valid when `tag` is `new_tx` or `new_tx_reply`.
    peer_tx_id: TransactionId,
};

pub const Action = enum(u8) {
    /// A client has seen a new file on its local filesystem.
    client_new_file,

    server_registered_new_file,
    server_cant_register_new_files,
    server_new_file_exists,

    transfer_file_metadata,
    transfer_file_accept,
    transfer_file_decline,
    transfer_file_contents,
    transfer_file_success,
    transfer_file_failure,

    /// A client has seen a file get deleted on its local filesystem.
    delete_file,
    /// The server notifies that a file has been globally deleted.
    delete_file_confirm,
};

pub const FileHash = struct {
    blake3: [byte_size]u8,

    pub const byte_size = 32;

    pub fn eql(lhs: *const FileHash, rhs: *const FileHash) bool {
        return std.mem.eql(u8, &lhs.blake3, &rhs.blake3);
    }

    pub fn format(hash: FileHash, writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print("{x}", .{std.mem.nativeToBig(@Int(.unsigned, byte_size * 8), @bitCast(hash.blake3))});
    }
};

pub const FileId = enum(u32) { unknown, _ };

pub const FileSize = u64;

pub const PathEncoding = enum(u8) {
    wtf16le,
};

pub const PathByteCount = u16;

pub const FilePathBuffer = [1 << @bitSizeOf(PathByteCount)]u8;

/// Asserts a writer buffer size of at least 1.
pub fn sendMessageHeaderExistingTx(writer: *Io.Writer, peer_tx_id: TransactionId) !void {
    const header = MessageHeader{
        .tag = .existing_tx,
        .tx_id = peer_tx_id,
        .peer_tx_id = .invalid,
    };
    try writer.writeByte(@bitCast(header));
}

/// Asserts a writer buffer size of at least 1.
pub fn sendMessageHeaderNewTx(writer: *Io.Writer, tx_id: TransactionId) !void {
    const header = MessageHeader{
        .tag = .new_tx,
        .tx_id = .invalid,
        .peer_tx_id = tx_id,
    };
    try writer.writeByte(@bitCast(header));
}

/// Asserts a writer buffer size of at least 1.
pub fn sendMessageHeaderNewTxReply(writer: *Io.Writer, tx_id: TransactionId, peer_tx_id: TransactionId) !void {
    const header = MessageHeader{
        .tag = .new_tx_reply,
        .tx_id = peer_tx_id,
        .peer_tx_id = tx_id,
    };
    try writer.writeByte(@bitCast(header));
}

/// Asserts a writer buffer size of at least 1.
pub fn sendAction(writer: *Io.Writer, action: Action) !void {
    try writer.writeByte(@intFromEnum(action));
}

/// Asserts a writer buffer size of at least `@sizeOf(FileId)`.
pub fn sendFileId(writer: *Io.Writer, id: FileId) !void {
    try writer.writeInt(std.meta.Tag(FileId), @intFromEnum(id), endian);
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
    file_id: FileId,
    file_size: FileSize,
    hash: *const FileHash,
) !void {
    try sendFileId(writer, file_id);
    try writer.writeInt(FileSize, file_size, endian);
    try writer.writeAll(&hash.blake3);
}

/// Asserts a reader buffer size of at least 1.
pub fn receiveMessageHeader(reader: *Io.Reader) Io.Reader.Error!MessageHeader {
    return @bitCast(try reader.takeByte());
}

pub const ReceiveActionError = error{UnknownAction} || Io.Reader.Error;

/// Asserts a reader buffer size of at least 1.
pub fn receiveAction(reader: *Io.Reader) ReceiveActionError!Action {
    return std.enums.fromInt(Action, try reader.takeByte()) orelse error.UnknownAction;
}

/// Asserts a reader buffer size of at least `@sizeOf(FileId)`.
pub fn receiveFileId(reader: *Io.Reader) Io.Reader.Error!FileId {
    // All values of FileId are valid
    return std.enums.fromInt(FileId, try reader.takeInt(std.meta.Tag(FileId), endian)).?;
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
    file_id: FileId,
    file_size: FileSize,
    hash: FileHash,
};

pub const ReceiveFileMetadataError = Io.Reader.Error;

/// Asserts a reader buffer size of at least `FileHash.byte_size`.
pub fn receiveFileMetadata(reader: *Io.Reader) ReceiveFileMetadataError!IncomingFileMetadata {
    const file_id = try receiveFileId(reader);
    const file_size = try reader.takeInt(FileSize, endian);

    const hash_bytes = try reader.takeArray(FileHash.byte_size);
    const hash: FileHash = .{ .blake3 = hash_bytes.* };

    return .{
        .file_id = file_id,
        .file_size = file_size,
        .hash = hash,
    };
}
