const std = @import("std");

// IO is a type defined via a root declaration.
// It must implements the following methods:
// - connect, onConnect
// - send, onSend
// - recv, onRecv
// It must also define the following types:
// - Completion
// - ConnectError
// - SendError
// - RecvError
// see Blocking.io for an implementation example.
pub const IO = blk: {
    const root = @import("root");
    if (@hasDecl(root, "IO")) {
        break :blk root.IO;
    }
    @compileError("no IO API defined at root");
};

// Wrapper for a base IO API.
pub fn Wrapper(IO_T: type) type {
    return struct {
        io: *IO_T,
        completion: IO_T.Completion,

        const Self = @This();

        pub fn init(io: *IO_T) Self {
            return .{ .io = io, .completion = undefined };
        }

        // NOTE: Business methods connect, send, recv expect a Ctx
        // who should reference the base IO API in Ctx.io field

        // NOTE: Ctx is already known (ie. @import("std/http/Client.zig").Ctx)
        // but we require to provide its type (comptime) as argument
        // to avoid dependency loop
        // ie. Wrapper requiring Ctx and Ctx requiring Wrapper

        fn Cbk(comptime Ctx: type) type {
            return *const fn (ctx: *Ctx, res: anyerror!void) anyerror!void;
        }

        pub fn connect(
            self: *Self,
            comptime Ctx: type,
            ctx: *Ctx,
            comptime cbk: Cbk(Ctx),
            socket: std.posix.socket_t,
            address: std.net.Address,
        ) void {
            self.io.connect(Ctx, ctx, &self.completion, onConnect(Ctx, cbk), socket, address);
        }

        fn onConnectFn(comptime Ctx: type) type {
            return fn (
                ctx: *Ctx,
                _: *IO_T.Completion,
                result: IO_T.ConnectError!void,
            ) void;
        }
        fn onConnect(comptime Ctx: type, comptime cbk: Cbk(Ctx)) onConnectFn(Ctx) {
            const s = struct {
                fn on(
                    ctx: *Ctx,
                    _: *IO_T.Completion,
                    result: IO_T.ConnectError!void,
                ) void {
                    ctx.io.io.onConnect(result); // base IO callback
                    _ = result catch |err| return ctx.setErr(err);
                    cbk(ctx, {}) catch |err| return ctx.setErr(err);
                }
            };
            return s.on;
        }

        pub fn send(
            self: *Self,
            comptime Ctx: type,
            ctx: *Ctx,
            comptime cbk: Cbk(Ctx),
            socket: std.posix.socket_t,
            buf: []const u8,
        ) void {
            self.io.send(Ctx, ctx, &self.completion, onSend(Ctx, cbk), socket, buf);
        }

        fn onSendFn(comptime Ctx: type) type {
            return fn (
                ctx: *Ctx,
                _: *IO_T.Completion,
                result: IO_T.SendError!usize,
            ) void;
        }
        fn onSend(comptime Ctx: type, comptime cbk: Cbk(Ctx)) onSendFn(Ctx) {
            const s = struct {
                fn on(
                    ctx: *Ctx,
                    _: *IO_T.Completion,
                    result: IO_T.SendError!usize,
                ) void {
                    ctx.io.io.onSend(result); // base IO callback
                    const len = result catch |err| return ctx.setErr(err);
                    ctx.setLen(len);
                    cbk(ctx, {}) catch |e| ctx.setErr(e);
                }
            };
            return s.on;
        }

        pub fn recv(
            self: *Self,
            comptime Ctx: type,
            ctx: *Ctx,
            comptime cbk: Cbk(Ctx),
            socket: std.posix.socket_t,
            buf: []u8,
        ) void {
            self.io.recv(Ctx, ctx, &self.completion, onRecv(Ctx, cbk), socket, buf);
        }

        fn onRecvFn(comptime Ctx: type) type {
            return fn (
                ctx: *Ctx,
                _: *IO_T.Completion,
                result: IO_T.RecvError!usize,
            ) void;
        }
        fn onRecv(comptime Ctx: type, comptime cbk: Cbk(Ctx)) onRecvFn(Ctx) {
            const s = struct {
                fn do(
                    ctx: *Ctx,
                    _: *IO_T.Completion,
                    result: IO_T.RecvError!usize,
                ) void {
                    ctx.io.io.onRecv(result); // base IO callback
                    const len = result catch |err| return ctx.setErr(err);
                    ctx.setLen(len);
                    cbk(ctx, {}) catch |err| return ctx.setErr(err);
                }
            };
            return s.do;
        }
    };
}
