const std = @import("std");

const Ctx = @import("std/http/Client.zig").Ctx;

pub const Cbk = fn (ctx: *Ctx, res: anyerror!void) anyerror!void;

pub const Blocking = struct {
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
                ctx.setErr(e);
            };
        };
        cbk(ctx, {}) catch |e| ctx.setErr(e);
    }

    pub fn send(
        _: *Blocking,
        comptime ctxT: type,
        ctx: *ctxT,
        comptime cbk: Cbk,
        socket: std.os.socket_t,
        buf: []const u8,
    ) void {
        const len = std.os.write(socket, buf) catch |err| {
            cbk(ctx, err) catch |e| {
                return ctx.setErr(e);
            };
            return ctx.setErr(err);
        };
        ctx.setLen(len);
        cbk(ctx, {}) catch |e| ctx.setErr(e);
    }

    pub fn recv(
        _: *Blocking,
        comptime ctxT: type,
        ctx: *ctxT,
        comptime cbk: Cbk,
        socket: std.os.socket_t,
        buf: []u8,
    ) void {
        const len = std.os.read(socket, buf) catch |err| {
            cbk(ctx, err) catch |e| {
                return ctx.setErr(e);
            };
            return ctx.setErr(err);
        };
        ctx.setLen(len);
        cbk(ctx, {}) catch |e| ctx.setErr(e);
    }
};
