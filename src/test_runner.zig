const std = @import("std");
const builtin = @import("builtin");

pub const Blocking = @import("Blocking.zig").Blocking;
pub const IO = @import("io.zig").Wrapper(Blocking);

pub const tests = @import("tests.zig");

pub fn main() !void {
    std.testing.refAllDecls(tests);
    for (builtin.test_functions) |test_fn| {
        test_fn.func() catch |err| {
            if (err == error.SkipZigTest) continue;
            return err;
        };
        std.debug.print("{s}\tOK\n", .{test_fn.name});
    }
}
