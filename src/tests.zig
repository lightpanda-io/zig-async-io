const std = @import("std");

const Ctx = Client.Ctx;
const stack = @import("stack.zig");
pub const Client = @import("std/http/Client.zig");

const IO = @import("root").IO;
const Blocking = @import("root").Blocking;

fn onRequestWait(ctx: *Ctx, res: anyerror!void) !void {
    res catch |e| {
        std.debug.print("error: {any}\n", .{e});
        return e;
    };
    std.log.debug("request waited", .{});
    std.log.debug("Status code: {any}", .{ctx.req.response.status});
    const body = try ctx.req.reader().readAllAlloc(ctx.alloc(), 1024 * 1024);
    defer ctx.alloc().free(body);
    std.log.debug("body length: {d}", .{body.len});
}

fn onRequestFinish(ctx: *Ctx, res: anyerror!void) !void {
    res catch |err| return err;
    std.log.debug("request finished", .{});
    return ctx.req.async_wait(ctx, onRequestWait);
}

fn onRequestSend(ctx: *Ctx, res: anyerror!void) !void {
    res catch |err| return err;
    std.log.debug("request sent", .{});
    return ctx.req.async_finish(ctx, onRequestFinish);
}

pub fn onRequestConnect(ctx: *Ctx, res: anyerror!void) anyerror!void {
    res catch |err| return err;
    std.log.debug("request connected", .{});
    return ctx.req.async_send(ctx, onRequestSend);
}

test "example.com" {
    var urls = [_][]const u8{
        "https://www.example.com",
    };
    try do(&urls);
}

fn do(urls: [][]const u8) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer switch (gpa.deinit()) {
        .ok => {},
        .leak => @panic("memory leak"),
    };
    const alloc = gpa.allocator();

    var blocking = Blocking{};
    var loop = IO.init(&blocking);

    var client = Client{ .allocator = alloc };
    defer client.deinit();

    var server_header_buffer: [1024 * 1024]u8 = undefined;

    for (urls) |url| {
        var req = Client.Request{
            .client = &client,
        };
        defer req.deinit();

        var ctx = try Client.Ctx.init(&loop, &req);
        defer ctx.deinit();

        std.log.info("request {s}", .{url});
        try client.async_open(
            .GET,
            try std.Uri.parse(url),
            .{ .server_header_buffer = &server_header_buffer },
            &ctx,
            onRequestConnect,
        );

        try std.testing.expect(ctx.err == null);
    }
}
