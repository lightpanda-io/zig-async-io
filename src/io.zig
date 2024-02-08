const std = @import("std");

const Client = @import("std/http/Client.zig");

pub const Cbk = fn (ctx: *Client, res: anyerror!void) anyerror!void;

pub const Blocking = struct {
    i: usize = 0,

    pub fn connect(
        _: *Blocking,
        comptime ctxT: type,
        ctx: *ctxT,
        comptime cbk: Cbk,
        socket: std.os.socket_t,
        address: std.net.Address,
    ) void {
        std.os.connect(socket, &address.any, address.getOsSockLen()) catch |err| {
            std.os.closeSocket(socket);
            cbk(ctx, err) catch |e| {
                ctx.ctx.setErr(e);
            };
        };
        cbk(ctx, {}) catch |e| ctx.ctx.setErr(e);
    }
};
