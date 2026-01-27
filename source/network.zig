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
};

pub const Action = enum(u8) {
    transfer_file_metadata,
    transfer_file_decision_yes,
    transfer_file_decision_no,
    transfer_file_contents,
    transfer_file_confirmation,
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

/// Asserts a writer buffer size of at least `@sizeOf(TransactionId)`.
pub fn sendTransactionId(writer: *Io.Writer, id: TransactionId) !void {
    try writer.writeInt(std.meta.Tag(TransactionId), @intFromEnum(id), endian);
}

/// Asserts a writer buffer size of at least 1.
pub fn sendAction(writer: *Io.Writer, action: Action) !void {
    try writer.writeByte(@intFromEnum(action));
}

/// Asserts a writer buffer size of at least `FileHash.byte_size`.
pub fn sendTransferFileMetadata(
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

/// Asserts a reader buffer size of at least `FileHash.byte_size`.
pub fn receiveTransferFileMetadata(reader: *Io.Reader, allocator: Allocator) !struct {
    path_encoding: PathEncoding,
    path: []const u8,
    file_size: FileSize,
    hash: FileHash,
} {
    const path_encoding: PathEncoding = @enumFromInt(try reader.takeByte());
    const path_len_bytes = try reader.takeInt(PathLenInBytes, endian);
    const file_size = try reader.takeInt(FileSize, endian);

    const hash_bytes = try reader.takeArray(FileHash.byte_size);
    const hash: FileHash = .{ .blake3 = hash_bytes.* };

    var dest: Io.Writer.Allocating = try .initCapacity(allocator, path_len_bytes);
    defer dest.deinit();
    try reader.streamExact(&dest.writer, path_len_bytes);
    const path = try dest.toOwnedSlice();
    errdefer comptime unreachable;

    return .{
        .path_encoding = path_encoding,
        .file_size = file_size,
        .hash = hash,
        .path = path,
    };
}
