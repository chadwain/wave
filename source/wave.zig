pub const client = @import("client.zig");
pub const network = @import("network.zig");
pub const server = @import("server.zig");
pub const windows = @import("windows.zig");

pub const log = @import("std").log.scoped(.wave);

pub const PathComponentCount = u8;
/// The maximum number of components in a file/folder path that will be recognized.
/// If a path has more components than this, the file/folder will not be tracked.
pub const max_path_components: PathComponentCount = @import("std").math.maxInt(PathComponentCount);
