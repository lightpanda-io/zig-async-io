const std = @import("std");

const stack = @import("stack.zig");
const Client = @import("std/http/Client.zig");
const Loop = @import("io.zig").Blocking;

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

    var loop = Loop{};

    var client = Client{ .allocator = alloc };
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

    std.log.debug("Final error: {any}", .{ctx.err});
}

test {
    _ = stack.Stack(fn () void);
    _ = Client;
    std.testing.refAllDecls(@This());
}
