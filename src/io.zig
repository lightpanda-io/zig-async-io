const std = @import("std");

pub const Ctx = @import("std/http/Client.zig").Ctx;
pub const Cbk = @import("std/http/Client.zig").Cbk;

pub const Blocking = struct {
    pub fn connect(
        _: *Blocking,
        comptime ctxT: type,
        ctx: *ctxT,
        comptime cbk: Cbk,
        socket: std.posix.socket_t,
        address: std.net.Address,
    ) void {
        std.posix.connect(socket, &address.any, address.getOsSockLen()) catch |err| {
            std.posix.close(socket);
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
        socket: std.posix.socket_t,
        buf: []const u8,
    ) void {
        const len = std.posix.write(socket, buf) catch |err| {
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
        socket: std.posix.socket_t,
        buf: []u8,
    ) void {
        const len = std.posix.read(socket, buf) catch |err| {
            cbk(ctx, err) catch |e| {
                return ctx.setErr(e);
            };
            return ctx.setErr(err);
        };
        ctx.setLen(len);
        cbk(ctx, {}) catch |e| ctx.setErr(e);
    }
};
