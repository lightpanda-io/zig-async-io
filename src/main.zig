const std = @import("std");

const stack = @import("stack.zig");
pub const Client = @import("std/http/Client.zig");
const Ctx = Client.Ctx;
const Loop = @import("io.zig").Blocking;

const root = @import("root");

fn onRequestWait(ctx: *Ctx, res: anyerror!void) !void {
    res catch |e| {
        std.debug.print("error: {any}\n", .{e});
        return e;
    };
    std.log.debug("REQUEST WAITED", .{});
    std.log.debug("Status code: {any}", .{ctx.req.response.status});
    const body = try ctx.req.reader().readAllAlloc(ctx.alloc(), 1024 * 1024);
    defer ctx.alloc().free(body);
    std.log.debug("Body: \n{s}", .{body});
}

fn onRequestFinish(ctx: *Ctx, res: anyerror!void) !void {
    res catch |err| return err;
    std.log.debug("REQUEST FINISHED", .{});
    return ctx.req.async_wait(ctx, onRequestWait);
}

fn onRequestSend(ctx: *Ctx, res: anyerror!void) !void {
    res catch |err| return err;
    std.log.debug("REQUEST SENT", .{});
    return ctx.req.async_finish(ctx, onRequestFinish);
}

pub fn onRequestConnect(ctx: *Ctx, res: anyerror!void) anyerror!void {
    res catch |err| return err;
    std.log.debug("REQUEST CONNECTED", .{});
    return ctx.req.async_send(ctx, onRequestSend);
}

pub fn main() !void {
    return run();
}

pub fn run() !void {

    // const url = "http://127.0.0.1:8080";
    const url = "https://www.example.com";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer switch (gpa.deinit()) {
        .ok => {},
        .leak => @panic("memory leak"),
    };
    const alloc = gpa.allocator();

    var loop = Loop{};

    var client = Client{ .allocator = alloc };
    defer client.deinit();

    var req = Client.Request{
        .client = &client,
    };
    defer req.deinit();

    var ctx = try Client.Ctx.init(&loop, &req);
    defer ctx.deinit();

    var server_header_buffer: [1024 * 1024]u8 = undefined;

    try client.async_open(
        .GET,
        try std.Uri.parse(url),
        .{ .server_header_buffer = &server_header_buffer },
        &ctx,
        onRequestConnect,
    );

    std.log.debug("Final error: {any}", .{ctx.err});
}

test {
    _ = stack.Stack(fn () void);
    std.testing.refAllDecls(@This());
    try run();
}
