const std = @import("std");

// Blocking is an example implementation of an IO API
// following the zig-async-io model.
// As it name suggests in this implementation all operations are
// in fact blocking, the async API is just faked.
pub const Blocking = @This();

pub const Completion = void;

pub const ConnectError = std.posix.ConnectError;
pub const SendError = std.posix.WriteError;
pub const RecvError = std.posix.ReadError;

pub fn connect(
    _: *Blocking,
    comptime CtxT: type,
    ctx: *CtxT,
    _: *Completion,
    comptime cbk: fn (ctx: *CtxT, _: *Completion, res: ConnectError!void) void,
    socket: std.posix.socket_t,
    address: std.net.Address,
) void {
    std.posix.connect(socket, &address.any, address.getOsSockLen()) catch |err| {
        cbk(ctx, @constCast(&{}), err);
        return;
    };
    cbk(ctx, @constCast(&{}), {});
}

pub fn onConnect(_: *Blocking, _: ConnectError!void) void {}

pub fn send(
    _: *Blocking,
    comptime CtxT: type,
    ctx: *CtxT,
    _: *Completion,
    comptime cbk: fn (ctx: *CtxT, _: *Completion, res: SendError!usize) void,
    socket: std.posix.socket_t,
    buf: []const u8,
) void {
    const len = std.posix.write(socket, buf) catch |err| {
        cbk(ctx, @constCast(&{}), err);
        return;
    };
    cbk(ctx, @constCast(&{}), len);
}

pub fn onSend(_: *Blocking, _: SendError!usize) void {}

pub fn recv(
    _: *Blocking,
    comptime CtxT: type,
    ctx: *CtxT,
    _: *Completion,
    comptime cbk: fn (ctx: *CtxT, _: *Completion, res: RecvError!usize) void,
    socket: std.posix.socket_t,
    buf: []u8,
) void {
    const len = std.posix.read(socket, buf) catch |err| {
        cbk(ctx, @constCast(&{}), err);
        return;
    };
    cbk(ctx, @constCast(&{}), len);
}

pub fn onRecv(_: *Blocking, _: RecvError!usize) void {}
