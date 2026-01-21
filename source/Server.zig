const Server = @This();

const wave = @import("wave.zig");
const network = wave.network;

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn start(io: Io, in: *Io.Reader, out: *Io.Writer) !struct {
    send: Io.Future(@typeInfo(@TypeOf(send)).@"fn".return_type.?),
    receive: Io.Future(@typeInfo(@TypeOf(receive)).@"fn".return_type.?),
} {
    var send_task = try io.concurrent(send, .{out});
    errdefer send_task.cancel(io) catch {};
    const receive_task = try io.concurrent(receive, .{in});
    errdefer comptime unreachable;

    return .{
        .send = send_task,
        .receive = receive_task,
    };
}

fn send(writer: *Io.Writer) !void {
    try network.sendTransactionId(writer, .disconnect);
    try writer.flush();
}

// const ReceiveContext = struct {
//     txs: std.AutoHashMapUnmanaged(transaction.Id, Transaction),
// };

fn receive(reader: *Io.Reader) !void {
    // var ctx = ReceiveContext{};
    // defer ctx.deinit();

    while (true) {
        const id = try network.receiveTransactionId(reader) orelse break;
        _ = id;
    }
}
