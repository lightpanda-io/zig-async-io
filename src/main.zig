const std = @import("std");

const stack = @import("stack.zig");
const Client = @import("std/http/Client.zig");
const Loop = Client.Loop;

pub const IO = @import("tigerbeetleio").IO;

const root = @import("root");

pub fn main() !void {
    // const url = "http://127.0.0.1:8080";
    const url = "https://www.example.com";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer switch (gpa.deinit()) {
        .ok => {},
        .leak => @panic("memory leak"),
    };
    const alloc = gpa.allocator();

    var io = try IO.init(32, 0);
    defer io.deinit();

    var loop = Loop.init(&io);

    var client = Client{ .allocator = alloc, .loop = &loop };
    defer client.deinit();

    var req = Client.Request{
        .client = &client,
    };
    defer req.deinit();

    var ctx = try Client.Ctx.init(&loop, &req);
    defer ctx.deinit();

    var server_header_buffer: [2048]u8 = undefined;

    try client.async_open(
        .GET,
        try std.Uri.parse(url),
        .{ .server_header_buffer = &server_header_buffer },
        &ctx,
        Client.onRequestConnect,
    );

    while (!loop.isDone()) {
        try io.run_for_ns(10 * std.time.ns_per_ms);
    }

    std.log.debug("Final error: {any}", .{ctx.err});
}

test {
    _ = stack.Stack(fn () void);
    _ = Client;
    std.testing.refAllDecls(@This());
}
