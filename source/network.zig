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
    /// Payload: A path
    client_new_file,
    /// Sent in response to a `client_new_file` message.
    /// Payload: A sequence of `FileId`, one for each component of the requested path, in REVERSE order.
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

pub const FileId = enum(u32) { _ };

pub const FileSize = u64;

pub const PathEncoding = enum(u8) {
    wtf16le,
};

pub const PathByteCount = u16;

pub const FilePathBuffer = [1 << @bitSizeOf(PathByteCount)]u8;

pub const min_reader_writer_buffer_size = FileHash.byte_size;

pub const Writer = struct {
    io: *Io.Writer,

    /// Asserts a writer buffer size of at least `min_reader_writer_buffer_size`.
    pub fn init(io_writer: *Io.Writer) Writer {
        assert(io_writer.buffer.len >= min_reader_writer_buffer_size);
        return .{ .io = io_writer };
    }

    pub fn flush(writer: Writer) !void {
        try writer.io.flush();
    }

    fn writeEnum(writer: Writer, comptime Enum: type, value: Enum) !void {
        try writer.io.writeInt(@typeInfo(Enum).@"enum".tag_type, @intFromEnum(value), endian);
    }

    pub fn sendMessageHeaderExistingTx(writer: Writer, peer_tx_id: TransactionId) !void {
        const header = MessageHeader{
            .tag = .existing_tx,
            .tx_id = peer_tx_id,
            .peer_tx_id = .invalid,
        };
        try writer.io.writeStruct(header, endian);
    }

    pub fn sendMessageHeaderNewTx(writer: Writer, tx_id: TransactionId) !void {
        const header = MessageHeader{
            .tag = .new_tx,
            .tx_id = .invalid,
            .peer_tx_id = tx_id,
        };
        try writer.io.writeStruct(header, endian);
    }

    pub fn sendMessageHeaderNewTxReply(writer: Writer, tx_id: TransactionId, peer_tx_id: TransactionId) !void {
        const header = MessageHeader{
            .tag = .new_tx_reply,
            .tx_id = peer_tx_id,
            .peer_tx_id = tx_id,
        };
        try writer.io.writeStruct(header, endian);
    }

    pub fn sendAction(writer: Writer, action: Action) !void {
        try writer.writeEnum(Action, action);
    }

    pub fn sendFileId(writer: Writer, id: FileId) !void {
        try writer.writeEnum(FileId, id);
    }

    pub fn sendNewFilePath(
        writer: Writer,
        path_encoding: PathEncoding,
        path: []const u8, // TODO: Make a Path struct
    ) !void {
        try writer.writeEnum(PathEncoding, path_encoding);
        try writer.io.writeInt(PathByteCount, @intCast(path.len), endian);
        try writer.io.writeAll(path);
    }

    pub fn sendFileMetadata(
        writer: Writer,
        file_id: FileId,
        file_size: FileSize,
        hash: *const FileHash,
    ) !void {
        try writer.sendFileId(file_id);
        try writer.io.writeInt(FileSize, file_size, endian);
        try writer.io.writeAll(&hash.blake3);
    }
};

pub const Reader = struct {
    io: *Io.Reader,

    /// Asserts a reader buffer size of at least `min_reader_writer_buffer_size`.
    pub fn init(io_reader: *Io.Reader) Reader {
        assert(io_reader.buffer.len >= min_reader_writer_buffer_size);
        return .{ .io = io_reader };
    }

    fn readEnum(reader: Reader, comptime Enum: type) Io.Reader.Error!?Enum {
        const int = try reader.io.takeInt(@typeInfo(Enum).@"enum".tag_type, endian);
        return std.enums.fromInt(Enum, int);
    }

    pub fn receiveMessageHeader(reader: Reader) Io.Reader.Error!MessageHeader {
        return reader.io.takeStruct(MessageHeader, endian);
    }

    pub const ReceiveActionError = error{UnknownAction} || Io.Reader.Error;

    pub fn receiveAction(reader: Reader) ReceiveActionError!Action {
        return try reader.readEnum(Action) orelse error.UnknownAction;
    }

    pub fn receiveFileId(reader: Reader) Io.Reader.Error!FileId {
        // All values of FileId are valid
        return reader.io.takeEnumNonexhaustive(FileId, endian);
    }

    pub const IncomingNewFilePath = struct {
        path_encoding: PathEncoding,
        path_byte_count: PathByteCount,
    };

    pub const ReceiveNewFilePathError = error{UnknownPathEncoding} || Io.Reader.StreamError;

    pub fn receiveNewFilePath(
        reader: Reader,
        file_path_buffer: *FilePathBuffer,
    ) ReceiveNewFilePathError!IncomingNewFilePath {
        const path_encoding = try reader.readEnum(PathEncoding) orelse return error.UnknownPathEncoding;
        const path_byte_count = try reader.io.takeInt(PathByteCount, endian);
        // TODO: Ensure path is not empty, and maybe some other sanity checks

        // TODO: Do path encoding verification here
        var file_path_writer: Io.Writer = .fixed(file_path_buffer);
        try reader.io.streamExact(&file_path_writer, path_byte_count);

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

    pub fn receiveFileMetadata(reader: Reader) ReceiveFileMetadataError!IncomingFileMetadata {
        const file_id = try receiveFileId(reader);
        const file_size = try reader.io.takeInt(FileSize, endian);

        const hash_bytes = try reader.io.takeArray(FileHash.byte_size);
        const hash: FileHash = .{ .blake3 = hash_bytes.* };

        return .{
            .file_id = file_id,
            .file_size = file_size,
            .hash = hash,
        };
    }
};
