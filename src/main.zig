const std = @import("std");

const stack = @import("stack.zig");
const Client = @import("std/http/Client.zig");
const Loop = @import("io.zig").Blocking;

const root = @import("root");

const std_options = struct {
    const http_disable_tls = true;
};

pub fn main() !void {
    const options_override = if (@hasDecl(root, "std_options")) root.std_options else struct {};
    const http_disable_tls = if (@hasDecl(options_override, "http_disable_tls"))
        options_override.http_disable_tls
    else
        false;
    std.debug.print("\ndisable tls: {any}\n", .{http_disable_tls});

    // const url = "http://127.0.0.1:8080";
    const url = "http://www.example.com";

    const alloc = std.heap.page_allocator;

    const loop = try alloc.create(Loop);
    defer alloc.destroy(loop);
    loop.* = .{};

    var client = Client{ .allocator = alloc };
    defer client.deinit();

    const req = try alloc.create(Client.Request);
    defer alloc.destroy(req);
    req.* = .{
        .client = &client,
        .arena = std.heap.ArenaAllocator.init(client.allocator),
    };
    defer req.deinit();

    const ctx = try alloc.create(Client.Ctx);
    defer alloc.destroy(ctx);
    ctx.* = try Client.Ctx.init(loop, req);
    defer ctx.deinit();

    var headers = try std.http.Headers.initList(alloc, &[_]std.http.Field{});
    defer headers.deinit();

    try client.async_open(
        .GET,
        try std.Uri.parse(url),
        headers,
        .{},
        ctx,
        Client.onRequestConnect,
    );

    std.debug.print("Final error: {any}\n", .{ctx.err});
}

test {
    _ = stack.Stack(fn () void);
    _ = Client;
    std.testing.refAllDecls(@This());
}
