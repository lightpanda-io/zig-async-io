//! Connecting and opening requests are threadsafe. Individual requests are not.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const http = std.http;
const mem = std.mem;
const net = @import("../net.zig");
const Uri = std.Uri;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const use_vectors = builtin.zig_backend != .stage2_x86_64;

const Client = @This();
const proto = @import("protocol.zig");

const async_net = @import("../net.zig");
const GenericStack = @import("../../stack.zig").Stack;
const async_io = @import("../../io.zig");
const Cbk = async_io.Cbk;
const Loop = async_io.Blocking;

pub const disable_tls = std.options.http_disable_tls;
// pub const disable_tls = true;

/// Allocator used for all allocations made by the client.
///
/// This allocator must be thread-safe.
allocator: Allocator,

ca_bundle: if (disable_tls) void else std.crypto.Certificate.Bundle = if (disable_tls) {} else .{},
ca_bundle_mutex: std.Thread.Mutex = .{},

/// When this is `true`, the next time this client performs an HTTPS request,
/// it will first rescan the system for root certificates.
next_https_rescan_certs: bool = true,

/// The pool of connections that can be reused (and currently in use).
connection_pool: ConnectionPool = .{},

/// This is the proxy that will handle http:// connections. It *must not* be modified when the client has any active connections.
http_proxy: ?Proxy = null,

/// This is the proxy that will handle https:// connections. It *must not* be modified when the client has any active connections.
https_proxy: ?Proxy = null,

/// A set of linked lists of connections that can be reused.
pub const ConnectionPool = struct {
    /// The criteria for a connection to be considered a match.
    pub const Criteria = struct {
        host: []const u8,
        port: u16,
        protocol: Connection.Protocol,
    };

    const Queue = std.DoublyLinkedList(Connection);
    pub const Node = Queue.Node;

    mutex: std.Thread.Mutex = .{},
    /// Open connections that are currently in use.
    used: Queue = .{},
    /// Open connections that are not currently in use.
    free: Queue = .{},
    free_len: usize = 0,
    free_size: usize = 32,

    /// Finds and acquires a connection from the connection pool matching the criteria. This function is threadsafe.
    /// If no connection is found, null is returned.
    pub fn findConnection(pool: *ConnectionPool, criteria: Criteria) ?*Connection {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        var next = pool.free.last;
        while (next) |node| : (next = node.prev) {
            if (node.data.protocol != criteria.protocol) continue;
            if (node.data.port != criteria.port) continue;

            // Domain names are case-insensitive (RFC 5890, Section 2.3.2.4)
            if (!std.ascii.eqlIgnoreCase(node.data.host, criteria.host)) continue;

            pool.acquireUnsafe(node);
            return &node.data;
        }

        return null;
    }

    /// Acquires an existing connection from the connection pool. This function is not threadsafe.
    pub fn acquireUnsafe(pool: *ConnectionPool, node: *Node) void {
        pool.free.remove(node);
        pool.free_len -= 1;

        pool.used.append(node);
    }

    /// Acquires an existing connection from the connection pool. This function is threadsafe.
    pub fn acquire(pool: *ConnectionPool, node: *Node) void {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        return pool.acquireUnsafe(node);
    }

    /// Tries to release a connection back to the connection pool. This function is threadsafe.
    /// If the connection is marked as closing, it will be closed instead.
    ///
    /// The allocator must be the owner of all nodes in this pool.
    /// The allocator must be the owner of all resources associated with the connection.
    pub fn release(pool: *ConnectionPool, allocator: Allocator, connection: *Connection) void {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        const node = @fieldParentPtr(Node, "data", connection);

        pool.used.remove(node);

        if (node.data.closing or pool.free_size == 0) {
            node.data.close(allocator);
            return allocator.destroy(node);
        }

        if (pool.free_len >= pool.free_size) {
            const popped = pool.free.popFirst() orelse unreachable;
            pool.free_len -= 1;

            popped.data.close(allocator);
            allocator.destroy(popped);
        }

        if (node.data.proxied) {
            pool.free.prepend(node); // proxied connections go to the end of the queue, always try direct connections first
        } else {
            pool.free.append(node);
        }

        pool.free_len += 1;
    }

    /// Adds a newly created node to the pool of used connections. This function is threadsafe.
    pub fn addUsed(pool: *ConnectionPool, node: *Node) void {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        pool.used.append(node);
    }

    /// Resizes the connection pool. This function is threadsafe.
    ///
    /// If the new size is smaller than the current size, then idle connections will be closed until the pool is the new size.
    pub fn resize(pool: *ConnectionPool, allocator: Allocator, new_size: usize) void {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        const next = pool.free.first;
        _ = next;
        while (pool.free_len > new_size) {
            const popped = pool.free.popFirst() orelse unreachable;
            pool.free_len -= 1;

            popped.data.close(allocator);
            allocator.destroy(popped);
        }

        pool.free_size = new_size;
    }

    pub fn deinit(pool: *ConnectionPool, allocator: Allocator) void {
        pool.mutex.lock();

        var next = pool.free.first;
        while (next) |node| {
            defer allocator.destroy(node);
            next = node.next;

            node.data.close(allocator);
        }

        next = pool.used.first;
        while (next) |node| {
            defer allocator.destroy(node);
            next = node.next;

            node.data.close(allocator);
        }

        pool.* = undefined;
    }
};

/// An interface to either a plain or TLS connection.
pub const Connection = struct {
    pub const buffer_size = std.crypto.tls.max_ciphertext_record_len;
    const BufferSize = std.math.IntFittingRange(0, buffer_size);

    pub const Protocol = enum { plain, tls };

    stream: async_net.Stream,
    /// undefined unless protocol is tls.
    tls_client: if (!disable_tls) *std.crypto.tls.Client else void,

    protocol: Protocol,
    host: []u8,
    port: u16,

    proxied: bool = false,
    closing: bool = false,

    read_start: BufferSize = 0,
    read_end: BufferSize = 0,
    write_end: BufferSize = 0,
    read_buf: [buffer_size]u8 = undefined,
    write_buf: [buffer_size]u8 = undefined,

    pub fn readvDirectTls(conn: *Connection, buffers: []std.os.iovec) ReadError!usize {
        return conn.tls_client.readv(conn.stream, buffers) catch |err| {
            // https://github.com/ziglang/zig/issues/2473
            if (mem.startsWith(u8, @errorName(err), "TlsAlert")) return error.TlsAlert;

            switch (err) {
                error.TlsConnectionTruncated, error.TlsRecordOverflow, error.TlsDecodeError, error.TlsBadRecordMac, error.TlsBadLength, error.TlsIllegalParameter, error.TlsUnexpectedMessage => return error.TlsFailure,
                error.ConnectionTimedOut => return error.ConnectionTimedOut,
                error.ConnectionResetByPeer, error.BrokenPipe => return error.ConnectionResetByPeer,
                else => return error.UnexpectedReadFailure,
            }
        };
    }

    pub fn async_readvDirect(
        conn: *Connection,
        buffers: []std.os.iovec,
        ctx: *Ctx,
        comptime cbk: Cbk,
    ) !void {
        _ = conn;

        if (ctx.conn().protocol == .tls) {
            if (disable_tls) unreachable;

            std.log.debug("fill", .{});
            return error.TlsNotSupported;
        }

        return ctx.stream().async_readv(buffers, ctx, cbk);
    }

    pub fn readvDirect(conn: *Connection, buffers: []std.os.iovec) ReadError!usize {
        if (conn.protocol == .tls) {
            if (disable_tls) unreachable;

            return conn.readvDirectTls(buffers);
        }

        return conn.stream.readv(buffers) catch |err| switch (err) {
            error.ConnectionTimedOut => return error.ConnectionTimedOut,
            error.ConnectionResetByPeer, error.BrokenPipe => return error.ConnectionResetByPeer,
            else => return error.UnexpectedReadFailure,
        };
    }

    pub fn onRecv(ctx: *Ctx, res: anyerror!void) anyerror!void {
        res catch |err| return ctx.pop(err);

        // EOF
        if (ctx.len() == 0) return ctx.pop(error.EndOfStream);

        // continue
        if (ctx.len() == ctx.buf().len) {
            try ctx.push(onRecv);
            return ctx.loop.recv(
                Ctx,
                ctx,
                onRecv,
                ctx.conn().stream.handle,
                ctx.buf(),
            );
        }

        // finished
        ctx.conn().read_start = 0;
        ctx.conn().read_end = @intCast(ctx.len());
        return ctx.pop({});
    }

    pub fn async_fill_simple(conn: *Connection, ctx: *Ctx, comptime cbk: Cbk) !void {
        try ctx.push(cbk);
        if (ctx.conn().protocol == .tls) {
            if (disable_tls) unreachable;

            std.log.debug("fill", .{});
            return error.TlsNotSupported;
        }

        ctx.setBuf(&ctx.conn().read_buf);
        return ctx.loop.recv(Ctx, ctx, onRecv, conn.stream.handle, ctx.buf());
    }

    fn onFill(ctx: *Ctx, res: anyerror!void) anyerror!void {
        res catch |err| return ctx.pop(err);

        // EOF
        const nread = ctx.len();
        if (nread == 0) return ctx.pop(error.EndOfStream);

        // finished
        ctx.conn().read_start = 0;
        ctx.conn().read_end = @intCast(nread);
        return ctx.pop({});
    }

    pub fn async_fill(conn: *Connection, ctx: *Ctx, comptime cbk: Cbk) !void {
        if (conn.read_end != conn.read_start) return;

        const iovecs = [1]std.os.iovec{
            .{ .iov_base = &conn.read_buf, .iov_len = conn.read_buf.len },
        };
        @memcpy(ctx._iovecs, &iovecs); // TODO: is it necessary?
        try ctx.push(cbk);
        return conn.async_readvDirect(ctx._iovecs, ctx, onFill);
    }

    pub fn fill(conn: *Connection) ReadError!void {
        if (conn.read_end != conn.read_start) return;

        var iovecs = [1]std.os.iovec{
            .{ .iov_base = &conn.read_buf, .iov_len = conn.read_buf.len },
        };
        const nread = try conn.readvDirect(&iovecs);
        if (nread == 0) return error.EndOfStream;
        conn.read_start = 0;
        conn.read_end = @intCast(nread);
    }

    pub fn peek(conn: *Connection) []const u8 {
        return conn.read_buf[conn.read_start..conn.read_end];
    }

    pub fn drop(conn: *Connection, num: BufferSize) void {
        conn.read_start += num;
    }

    pub fn read(conn: *Connection, buffer: []u8) ReadError!usize {
        const available_read = conn.read_end - conn.read_start;
        const available_buffer = buffer.len;

        if (available_read > available_buffer) { // partially read buffered data
            @memcpy(buffer[0..available_buffer], conn.read_buf[conn.read_start..conn.read_end][0..available_buffer]);
            conn.read_start += @intCast(available_buffer);

            return available_buffer;
        } else if (available_read > 0) { // fully read buffered data
            @memcpy(buffer[0..available_read], conn.read_buf[conn.read_start..conn.read_end]);
            conn.read_start += available_read;

            return available_read;
        }

        var iovecs = [2]std.os.iovec{
            .{ .iov_base = buffer.ptr, .iov_len = buffer.len },
            .{ .iov_base = &conn.read_buf, .iov_len = conn.read_buf.len },
        };
        const nread = try conn.readvDirect(&iovecs);

        if (nread > buffer.len) {
            conn.read_start = 0;
            conn.read_end = @intCast(nread - buffer.len);
            return buffer.len;
        }

        return nread;
    }

    pub const ReadError = error{
        TlsFailure,
        TlsAlert,
        ConnectionTimedOut,
        ConnectionResetByPeer,
        UnexpectedReadFailure,
        EndOfStream,
    };

    pub const Reader = std.io.Reader(*Connection, ReadError, read);

    pub fn reader(conn: *Connection) Reader {
        return Reader{ .context = conn };
    }

    pub fn writeAllDirectTls(conn: *Connection, buffer: []const u8) WriteError!void {
        return conn.tls_client.writeAll(conn.stream, buffer) catch |err| switch (err) {
            error.BrokenPipe, error.ConnectionResetByPeer => return error.ConnectionResetByPeer,
            else => return error.UnexpectedWriteFailure,
        };
    }

    fn onWriteAllDirect(ctx: *Ctx, res: anyerror!void) !void {
        res catch |err| switch (err) {
            error.BrokenPipe,
            error.ConnectionResetByPeer,
            => return ctx.pop(error.ConnectionResetByPeer),
            else => return ctx.pop(error.UnexpectedWriteFailure),
        };
        return ctx.pop({});
    }

    pub fn async_writeAllDirect(
        conn: *Connection,
        buffer: []const u8,
        ctx: *Ctx,
        comptime cbk: Cbk,
    ) !void {
        // TODO: tls stuff
        if (conn.protocol == .tls) {
            return error.TlsNotSupported;
        }
        // if (conn.protocol == .tls) {
        //     if (disable_tls) unreachable;

        //     return conn.writeAllDirectTls(buffer);
        // }

        try ctx.push(cbk);
        return conn.stream.async_writeAll(buffer, ctx, onWriteAllDirect);
    }

    pub fn writeAllDirect(conn: *Connection, buffer: []const u8) WriteError!void {
        if (conn.protocol == .tls) {
            if (disable_tls) unreachable;

            return conn.writeAllDirectTls(buffer);
        }

        return conn.stream.writeAll(buffer) catch |err| switch (err) {
            error.BrokenPipe, error.ConnectionResetByPeer => return error.ConnectionResetByPeer,
            else => return error.UnexpectedWriteFailure,
        };
    }

    pub fn write(conn: *Connection, buffer: []const u8) WriteError!usize {
        if (conn.write_end + buffer.len > conn.write_buf.len) {
            try conn.flush();

            if (buffer.len > conn.write_buf.len) {
                try conn.writeAllDirect(buffer);
                return buffer.len;
            }
        }

        @memcpy(conn.write_buf[conn.write_end..][0..buffer.len], buffer);
        conn.write_end += @intCast(buffer.len);

        return buffer.len;
    }

    fn onFlush(ctx: *Ctx, res: anyerror!void) !void {
        res catch |err| return ctx.pop(err);
        ctx.conn().write_end = 0;
        return ctx.pop({});
    }

    pub fn async_flush(conn: *Connection, ctx: *Ctx, comptime cbk: Cbk) !void {
        if (conn.write_end == 0) return error.WriteEmpty;

        try ctx.push(cbk);
        try conn.async_writeAllDirect(conn.write_buf[0..conn.write_end], ctx, onFlush);
    }

    pub fn flush(conn: *Connection) WriteError!void {
        if (conn.write_end == 0) return;

        try conn.writeAllDirect(conn.write_buf[0..conn.write_end]);
        conn.write_end = 0;
    }

    pub const WriteError = error{
        ConnectionResetByPeer,
        UnexpectedWriteFailure,
    };

    pub const Writer = std.io.Writer(*Connection, WriteError, write);

    pub fn writer(conn: *Connection) Writer {
        return Writer{ .context = conn };
    }

    pub fn close(conn: *Connection, allocator: Allocator) void {
        if (conn.protocol == .tls) {
            if (disable_tls) unreachable;

            // try to cleanly close the TLS connection, for any server that cares.
            _ = conn.tls_client.writeEnd(conn.stream, "", true) catch {};
            allocator.destroy(conn.tls_client);
        }

        conn.stream.close();
        allocator.free(conn.host);
    }
};

/// The mode of transport for requests.
pub const RequestTransfer = union(enum) {
    content_length: u64,
    chunked: void,
    none: void,
};

/// The decompressor for response messages.
pub const Compression = union(enum) {
    pub const DeflateDecompressor = std.compress.zlib.DecompressStream(Request.TransferReader);
    pub const GzipDecompressor = std.compress.gzip.Decompress(Request.TransferReader);
    pub const ZstdDecompressor = std.compress.zstd.DecompressStream(Request.TransferReader, .{});

    deflate: DeflateDecompressor,
    gzip: GzipDecompressor,
    zstd: ZstdDecompressor,
    none: void,
};

/// A HTTP response originating from a server.
pub const Response = struct {
    pub const ParseError = Allocator.Error || error{
        HttpHeadersInvalid,
        HttpHeaderContinuationsUnsupported,
        HttpTransferEncodingUnsupported,
        HttpConnectionHeaderUnsupported,
        InvalidContentLength,
        CompressionNotSupported,
    };

    pub fn parse(res: *Response, bytes: []const u8, trailing: bool) ParseError!void {
        var it = mem.tokenizeAny(u8, bytes, "\r\n");

        const first_line = it.next() orelse return error.HttpHeadersInvalid;
        if (first_line.len < 12)
            return error.HttpHeadersInvalid;

        const version: http.Version = switch (int64(first_line[0..8])) {
            int64("HTTP/1.0") => .@"HTTP/1.0",
            int64("HTTP/1.1") => .@"HTTP/1.1",
            else => return error.HttpHeadersInvalid,
        };
        if (first_line[8] != ' ') return error.HttpHeadersInvalid;
        const status: http.Status = @enumFromInt(parseInt3(first_line[9..12]));
        const reason = mem.trimLeft(u8, first_line[12..], " ");

        res.version = version;
        res.status = status;
        res.reason = reason;

        res.headers.clearRetainingCapacity();

        while (it.next()) |line| {
            if (line.len == 0) return error.HttpHeadersInvalid;
            switch (line[0]) {
                ' ', '\t' => return error.HttpHeaderContinuationsUnsupported,
                else => {},
            }

            var line_it = mem.tokenizeAny(u8, line, ": ");
            const header_name = line_it.next() orelse return error.HttpHeadersInvalid;
            const header_value = line_it.rest();

            try res.headers.append(header_name, header_value);

            if (trailing) continue;

            if (std.ascii.eqlIgnoreCase(header_name, "transfer-encoding")) {
                // Transfer-Encoding: second, first
                // Transfer-Encoding: deflate, chunked
                var iter = mem.splitBackwardsScalar(u8, header_value, ',');

                const first = iter.first();
                const trimmed_first = mem.trim(u8, first, " ");

                var next: ?[]const u8 = first;
                if (std.meta.stringToEnum(http.TransferEncoding, trimmed_first)) |transfer| {
                    if (res.transfer_encoding != .none) return error.HttpHeadersInvalid; // we already have a transfer encoding
                    res.transfer_encoding = transfer;

                    next = iter.next();
                }

                if (next) |second| {
                    const trimmed_second = mem.trim(u8, second, " ");

                    if (std.meta.stringToEnum(http.ContentEncoding, trimmed_second)) |transfer| {
                        if (res.transfer_compression != .identity) return error.HttpHeadersInvalid; // double compression is not supported
                        res.transfer_compression = transfer;
                    } else {
                        return error.HttpTransferEncodingUnsupported;
                    }
                }

                if (iter.next()) |_| return error.HttpTransferEncodingUnsupported;
            } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
                const content_length = std.fmt.parseInt(u64, header_value, 10) catch return error.InvalidContentLength;

                if (res.content_length != null and res.content_length != content_length) return error.HttpHeadersInvalid;

                res.content_length = content_length;
            } else if (std.ascii.eqlIgnoreCase(header_name, "content-encoding")) {
                if (res.transfer_compression != .identity) return error.HttpHeadersInvalid;

                const trimmed = mem.trim(u8, header_value, " ");

                if (std.meta.stringToEnum(http.ContentEncoding, trimmed)) |ce| {
                    res.transfer_compression = ce;
                } else {
                    return error.HttpTransferEncodingUnsupported;
                }
            }
        }
    }

    inline fn int64(array: *const [8]u8) u64 {
        return @bitCast(array.*);
    }

    fn parseInt3(text: *const [3]u8) u10 {
        if (use_vectors) {
            const nnn: @Vector(3, u8) = text.*;
            const zero: @Vector(3, u8) = .{ '0', '0', '0' };
            const mmm: @Vector(3, u10) = .{ 100, 10, 1 };
            return @reduce(.Add, @as(@Vector(3, u10), nnn -% zero) *% mmm);
        }
        return std.fmt.parseInt(u10, text, 10) catch unreachable;
    }

    test parseInt3 {
        const expectEqual = testing.expectEqual;
        try expectEqual(@as(u10, 0), parseInt3("000"));
        try expectEqual(@as(u10, 418), parseInt3("418"));
        try expectEqual(@as(u10, 999), parseInt3("999"));
    }

    version: http.Version,
    status: http.Status,
    reason: []const u8,

    /// If present, the number of bytes in the response body.
    content_length: ?u64 = null,

    /// If present, the transfer encoding of the response body, otherwise none.
    transfer_encoding: http.TransferEncoding = .none,

    /// If present, the compression of the response body, otherwise identity (no compression).
    transfer_compression: http.ContentEncoding = .identity,

    /// The headers received from the server.
    headers: http.Headers,
    parser: proto.HeadersParser,
    compression: Compression = .none,

    /// Whether the response body should be skipped. Any data read from the response body will be discarded.
    skip: bool = false,
};

pub const Ctx = struct {
    const Stack = GenericStack(Cbk);

    // temporary Data we need to store on the heap
    // because of the callback execution model
    const Data = struct {
        list: *std.net.AddressList = undefined,
        addr_current: usize = undefined,
        socket: std.os.socket_t = undefined,

        // TODO: we could remove this field as it is already set in ctx.req
        // but we do not know for now what will be the impact to set those directly
        // on the request, especially in case of error/cancellation
        conn: *Connection,
    };

    req: *Request = undefined,

    loop: *Loop,
    data: Data,
    stack: ?*Stack = null,
    err: ?anyerror = null,

    _buffer: ?[]const u8 = null,
    _len: ?usize = null,

    pub fn init(loop: *Loop, req: *Request) !Ctx {
        std.debug.print("tls really off?: {any}\n", .{disable_tls});
        const connection = try req.client.allocator.create(Connection);
        connection.* = .{
            .stream = undefined,
            .tls_client = undefined,
            .protocol = undefined,
            .host = undefined,
            .port = undefined,
        };
        return .{
            .req = req,
            .loop = loop,
            .data = .{ .conn = connection },
        };
    }

    pub fn setErr(self: *Ctx, err: anyerror) void {
        self.err = err;
    }

    pub fn push(self: *Ctx, comptime func: Stack.Fn) !void {
        if (self.stack) |stack| {
            return try stack.push(self.alloc(), func);
        }
        self.stack = try Stack.init(self.alloc(), func);
    }

    pub fn pop(self: *Ctx, res: anyerror!void) !void {
        if (self.stack) |stack| {
            const last = stack.next == null;
            const func = stack.pop(self.alloc(), null);
            const ret = @call(.auto, func, .{ self, res });
            if (last) {
                self.stack = null;
                self.alloc().destroy(stack);
            }
            return ret;
        }
    }

    pub fn deinit(self: Ctx) void {
        if (self.stack) |stack| {
            stack.deinit(self.alloc(), null);
        }
    }

    // not sure about those

    pub fn len(self: Ctx) usize {
        if (self._len == null) unreachable;
        return self._len.?;
    }

    pub fn setLen(self: *Ctx, nb: ?usize) void {
        self._len = nb;
    }

    pub fn buf(self: Ctx) []const u8 {
        if (self._buffer == null) unreachable;
        return self._buffer.?;
    }

    pub fn setBuf(self: *Ctx, bytes: ?[]const u8) void {
        self._buffer = bytes;
    }

    // aliases

    pub fn alloc(self: Ctx) std.mem.Allocator {
        return self.req.client.allocator;
    }

    pub fn conn(self: Ctx) *Connection {
        return self.req.connection.?;
    }

    pub fn stream(self: Ctx) async_net.Stream {
        return self.conn().stream;
    }
};

/// A HTTP request that has been sent.
///
/// Order of operations: open -> send[ -> write -> finish] -> wait -> read
pub const Request = struct {
    uri: Uri = undefined,
    client: *Client,
    /// is null when this connection is released
    connection: ?*Connection = null,

    method: http.Method = undefined,
    version: http.Version = .@"HTTP/1.1",
    headers: http.Headers = undefined,

    /// The transfer encoding of the request body.
    transfer_encoding: RequestTransfer = .none,

    redirects_left: u32 = undefined,
    handle_redirects: bool = undefined,
    handle_continue: bool = undefined,

    response: Response = undefined,

    /// Used as a allocator for resolving redirects locations.
    arena: std.heap.ArenaAllocator,

    pub fn init(arena: std.heap.ArenaAllocator, client: *Client) Request {
        return .{
            .client = client,
            .arena = arena,
        };
    }

    /// Frees all resources associated with the request.
    pub fn deinit(req: *Request) void {
        switch (req.response.compression) {
            .none => {},
            .deflate => |*deflate| deflate.deinit(),
            .gzip => |*gzip| gzip.deinit(),
            .zstd => |*zstd| zstd.deinit(),
        }

        req.headers.deinit();
        req.response.headers.deinit();

        if (req.response.parser.header_bytes_owned) {
            req.response.parser.header_bytes.deinit(req.client.allocator);
        }

        if (req.connection) |connection| {
            if (!req.response.parser.done) {
                // If the response wasn't fully read, then we need to close the connection.
                connection.closing = true;
            }
            req.client.connection_pool.release(req.client.allocator, connection);
        }

        req.arena.deinit();
        req.* = undefined;
    }

    fn onRedirectSend(ctx: *Ctx, res: anyerror!void) !void {
        res catch |err| return ctx.pop(err);
        // go back on check headers
        ctx.conn().async_fill(ctx, onResponseHeaders) catch |err| return ctx.pop(err);
    }

    fn onRedirectConnect(ctx: *Ctx, res: anyerror!void) !void {
        res catch |err| return ctx.pop(err);
        // re-send request
        ctx.req.prepareSend(.{}) catch |err| return ctx.pop(err);
        ctx.req.connection.?.async_flush(ctx, onRedirectSend) catch |err| return ctx.pop(err);
    }

    // async_redirect flow:
    // connect -> setRequestConnection
    // -> onRedirectConnect -> async_flush
    // -> onRedirectSend -> async_fill
    // -> go back on the wait workflow of the response
    fn async_redirect(req: *Request, uri: Uri, ctx: *Ctx) !void {
        req.prepareRedirect(uri);

        const protocol = protocol_map.get(uri.scheme) orelse return error.UnsupportedUrlScheme;

        const port: u16 = uri.port orelse switch (protocol) {
            .plain => 80,
            .tls => 443,
        };

        const host = uri.host orelse return error.UriMissingHost;

        try ctx.push(onRedirectConnect);

        // create a new connection for the redirected URI
        ctx.data.conn = try req.client.allocator.create(Connection);
        ctx.data.conn.* = .{
            .stream = undefined,
            .tls_client = undefined,
            .protocol = undefined,
            .host = undefined,
            .port = undefined,
        };
        return req.client.async_connect(host, port, protocol, ctx, setRequestConnection);
    }

    // This function must deallocate all resources associated with the request, or keep those which will be used
    // This needs to be kept in sync with deinit and request
    fn redirect(req: *Request, uri: Uri) !void {
        req.prepareRedirect(uri);

        const protocol = protocol_map.get(uri.scheme) orelse return error.UnsupportedUrlScheme;

        const port: u16 = uri.port orelse switch (protocol) {
            .plain => 80,
            .tls => 443,
        };

        const host = uri.host orelse return error.UriMissingHost;

        req.connection = try req.client.connect(host, port, protocol);
    }

    fn prepareRedirect(req: *Request, uri: Uri) void {
        assert(req.response.parser.done);

        switch (req.response.compression) {
            .none => {},
            .deflate => |*deflate| deflate.deinit(),
            .gzip => |*gzip| gzip.deinit(),
            .zstd => |*zstd| zstd.deinit(),
        }

        req.client.connection_pool.release(req.client.allocator, req.connection.?);
        req.connection = null;

        req.uri = uri;
        req.redirects_left -= 1;
        req.response.headers.clearRetainingCapacity();
        req.response.parser.reset();

        req.response = .{
            .status = undefined,
            .reason = undefined,
            .version = undefined,
            .headers = req.response.headers,
            .parser = req.response.parser,
        };
    }

    pub const SendError = Connection.WriteError || error{ InvalidContentLength, UnsupportedTransferEncoding };

    pub const SendOptions = struct {
        /// Specifies that the uri should be used as is. You guarantee that the uri is already escaped.
        raw_uri: bool = false,
    };

    pub fn async_send(
        req: *Request,
        options: SendOptions,
        ctx: *Ctx,
        comptime cbk: Cbk,
    ) !void {
        try req.prepareSend(options);
        try req.connection.?.async_flush(ctx, cbk);
    }

    /// Send the HTTP request headers to the server.
    pub fn send(req: *Request, options: SendOptions) SendError!void {
        try req.prepareSend(options);
        try req.connection.?.flush();
    }

    fn prepareSend(req: *Request, options: SendOptions) SendError!void {
        if (!req.method.requestHasBody() and req.transfer_encoding != .none) return error.UnsupportedTransferEncoding;

        const w = req.connection.?.writer();

        try req.method.write(w);
        try w.writeByte(' ');

        if (req.method == .CONNECT) {
            try req.uri.writeToStream(.{ .authority = true }, w);
        } else {
            try req.uri.writeToStream(.{
                .scheme = req.connection.?.proxied,
                .authentication = req.connection.?.proxied,
                .authority = req.connection.?.proxied,
                .path = true,
                .query = true,
                .raw = options.raw_uri,
            }, w);
        }
        try w.writeByte(' ');
        try w.writeAll(@tagName(req.version));
        try w.writeAll("\r\n");

        if (!req.headers.contains("host")) {
            try w.writeAll("Host: ");
            try req.uri.writeToStream(.{ .authority = true }, w);
            try w.writeAll("\r\n");
        }

        if (!req.headers.contains("user-agent")) {
            try w.writeAll("User-Agent: zig/");
            try w.writeAll(builtin.zig_version_string);
            try w.writeAll(" (std.http)\r\n");
        }

        if (!req.headers.contains("connection")) {
            try w.writeAll("Connection: keep-alive\r\n");
        }

        if (!req.headers.contains("accept-encoding")) {
            try w.writeAll("Accept-Encoding: gzip, deflate, zstd\r\n");
        }

        if (!req.headers.contains("te")) {
            try w.writeAll("TE: gzip, deflate, trailers\r\n");
        }

        const has_transfer_encoding = req.headers.contains("transfer-encoding");
        const has_content_length = req.headers.contains("content-length");

        if (!has_transfer_encoding and !has_content_length) {
            switch (req.transfer_encoding) {
                .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
                .content_length => |content_length| try w.print("Content-Length: {d}\r\n", .{content_length}),
                .none => {},
            }
        } else {
            if (has_transfer_encoding) {
                const transfer_encoding = req.headers.getFirstValue("transfer-encoding").?;
                if (std.mem.eql(u8, transfer_encoding, "chunked")) {
                    req.transfer_encoding = .chunked;
                } else {
                    return error.UnsupportedTransferEncoding;
                }
            } else if (has_content_length) {
                const content_length = std.fmt.parseInt(u64, req.headers.getFirstValue("content-length").?, 10) catch return error.InvalidContentLength;

                req.transfer_encoding = .{ .content_length = content_length };
            } else {
                req.transfer_encoding = .none;
            }
        }

        for (req.headers.list.items) |entry| {
            if (entry.value.len == 0) continue;

            try w.writeAll(entry.name);
            try w.writeAll(": ");
            try w.writeAll(entry.value);
            try w.writeAll("\r\n");
        }

        if (req.connection.?.proxied) {
            const proxy_headers: ?http.Headers = switch (req.connection.?.protocol) {
                .plain => if (req.client.http_proxy) |proxy| proxy.headers else null,
                .tls => if (req.client.https_proxy) |proxy| proxy.headers else null,
            };

            if (proxy_headers) |headers| {
                for (headers.list.items) |entry| {
                    if (entry.value.len == 0) continue;

                    try w.writeAll(entry.name);
                    try w.writeAll(": ");
                    try w.writeAll(entry.value);
                    try w.writeAll("\r\n");
                }
            }
        }

        try w.writeAll("\r\n");
    }

    const TransferReadError = Connection.ReadError || proto.HeadersParser.ReadError;

    const TransferReader = std.io.Reader(*Request, TransferReadError, transferRead);

    fn transferReader(req: *Request) TransferReader {
        return .{ .context = req };
    }

    fn transferRead(req: *Request, buf: []u8) TransferReadError!usize {
        if (req.response.parser.done) return 0;

        var index: usize = 0;
        while (index == 0) {
            const amt = try req.response.parser.read(req.connection.?, buf[index..], req.response.skip);
            if (amt == 0 and req.response.parser.done) break;
            index += amt;
        }

        return index;
    }

    pub const WaitError = RequestError || SendError || TransferReadError || proto.HeadersParser.CheckCompleteHeadError || Response.ParseError || Uri.ParseError || error{ TooManyHttpRedirects, RedirectRequiresResend, HttpRedirectMissingLocation, CompressionInitializationFailed, CompressionNotSupported };

    pub fn async_wait(_: *Request, ctx: *Ctx, comptime cbk: Cbk) !void {
        try ctx.push(cbk);
        return ctx.conn().async_fill(ctx, onResponseHeaders);
    }

    /// Waits for a response from the server and parses any headers that are sent.
    /// This function will block until the final response is received.
    ///
    /// If `handle_redirects` is true and the request has no payload, then this function will automatically follow
    /// redirects. If a request payload is present, then this function will error with error.RedirectRequiresResend.
    ///
    /// Must be called after `send` and, if any data was written to the request body, then also after `finish`.
    pub fn wait(req: *Request) WaitError!void {
        while (true) { // handle redirects
            while (true) { // read headers
                try req.connection.?.fill();
                if (try req.parseResponseHeaders()) break;
            }
            const ret = !try req.parseResponse();
            if (ret.redirect_uri) |uri| {
                try req.redirect(uri);
                try req.send(.{});
            }
            if (ret.done) break;
        }
    }

    fn onResponseHeaders(ctx: *Ctx, res: anyerror!void) !void {
        res catch |err| return ctx.pop(err);
        const done = ctx.req.parseResponseHeaders() catch |err| return ctx.pop(err);
        // if read of the headers is not done, continue
        if (!done) return ctx.conn().async_fill(ctx, onResponseHeaders);
        // if read of the headers is done, go read the reponse
        return onResponse(ctx, {});
    }

    fn parseResponseHeaders(req: *Request) !bool {
        const nchecked = try req.response.parser.checkCompleteHead(req.client.allocator, req.connection.?.peek());
        req.connection.?.drop(@intCast(nchecked));

        if (req.response.parser.state.isContent()) return true;
        return false;
    }

    fn onResponse(ctx: *Ctx, res: anyerror!void) !void {
        res catch |err| return ctx.pop(err);
        const ret = ctx.req.parseResponse() catch |err| return ctx.pop(err);
        if (ret.redirect_uri) |uri| {
            ctx.req.async_redirect(uri, ctx) catch |err| return ctx.pop(err);
            return;
        }
        // if read of the response is not done, continue
        if (!ret.done) return ctx.conn().async_fill(ctx, onResponse);
        // if read of the response is done, go execute the provided callback
        return ctx.pop({});
    }

    const WaitRedirectsReturn = struct {
        redirect_uri: ?Uri = null,
        done: bool = true,
    };

    fn parseResponse(req: *Request) WaitError!WaitRedirectsReturn {
        try req.response.parse(req.response.parser.header_bytes.items, false);

        if (req.response.status == .@"continue") {
            req.response.parser.done = true; // we're done parsing the continue response, reset to prepare for the real response
            req.response.parser.reset();

            if (req.handle_continue)
                return .{ .done = false };

            return .{ .done = true };
        }

        // we're switching protocols, so this connection is no longer doing http
        if (req.response.status == .switching_protocols or (req.method == .CONNECT and req.response.status == .ok)) {
            req.connection.?.closing = false;
            req.response.parser.done = true;
        }

        // we default to using keep-alive if not provided in the client if the server asks for it
        const req_connection = req.headers.getFirstValue("connection");
        const req_keepalive = req_connection != null and !std.ascii.eqlIgnoreCase("close", req_connection.?);

        const res_connection = req.response.headers.getFirstValue("connection");
        const res_keepalive = res_connection != null and !std.ascii.eqlIgnoreCase("close", res_connection.?);
        if (res_keepalive and (req_keepalive or req_connection == null)) {
            req.connection.?.closing = false;
        } else {
            req.connection.?.closing = true;
        }

        if (req.response.transfer_encoding != .none) {
            switch (req.response.transfer_encoding) {
                .none => unreachable,
                .chunked => {
                    req.response.parser.next_chunk_length = 0;
                    req.response.parser.state = .chunk_head_size;
                },
            }
        } else if (req.response.content_length) |cl| {
            req.response.parser.next_chunk_length = cl;

            if (cl == 0) req.response.parser.done = true;
        } else {
            req.response.parser.done = true;
        }

        // HEAD requests have no body
        if (req.method == .HEAD) {
            req.response.parser.done = true;
        }

        if (req.response.status.class() == .redirect and req.handle_redirects) {
            req.response.skip = true;

            // skip the body of the redirect response, this will at least leave the connection in a known good state.
            const empty = @as([*]u8, undefined)[0..0];
            assert(try req.transferRead(empty) == 0); // we're skipping, no buffer is necessary

            if (req.redirects_left == 0) return error.TooManyHttpRedirects;

            const location = req.response.headers.getFirstValue("location") orelse
                return error.HttpRedirectMissingLocation;

            const arena = req.arena.allocator();

            const location_duped = try arena.dupe(u8, location);

            const new_url = Uri.parse(location_duped) catch try Uri.parseWithoutScheme(location_duped);
            const resolved_url = try req.uri.resolve(new_url, false, arena);

            // is the redirect location on the same domain, or a subdomain of the original request?
            const is_same_domain_or_subdomain = std.ascii.endsWithIgnoreCase(resolved_url.host.?, req.uri.host.?) and (resolved_url.host.?.len == req.uri.host.?.len or resolved_url.host.?[resolved_url.host.?.len - req.uri.host.?.len - 1] == '.');

            if (resolved_url.host == null or !is_same_domain_or_subdomain or !std.ascii.eqlIgnoreCase(resolved_url.scheme, req.uri.scheme)) {
                // we're redirecting to a different domain, strip privileged headers like cookies
                _ = req.headers.delete("authorization");
                _ = req.headers.delete("www-authenticate");
                _ = req.headers.delete("cookie");
                _ = req.headers.delete("cookie2");
            }

            if (req.response.status == .see_other or ((req.response.status == .moved_permanently or req.response.status == .found) and req.method == .POST)) {
                // we're redirecting to a GET, so we need to change the method and remove the body
                req.method = .GET;
                req.transfer_encoding = .none;
                _ = req.headers.delete("transfer-encoding");
                _ = req.headers.delete("content-length");
                _ = req.headers.delete("content-type");
            }

            if (req.transfer_encoding != .none) {
                return error.RedirectRequiresResend; // The request body has already been sent. The request is still in a valid state, but the redirect must be handled manually.
            }

            return .{ .redirect_uri = resolved_url };
        } else {
            req.response.skip = false;
            if (!req.response.parser.done) {
                switch (req.response.transfer_compression) {
                    .identity => req.response.compression = .none,
                    .compress, .@"x-compress" => return error.CompressionNotSupported,
                    .deflate => req.response.compression = .{
                        .deflate = std.compress.zlib.decompressStream(req.client.allocator, req.transferReader()) catch return error.CompressionInitializationFailed,
                    },
                    .gzip, .@"x-gzip" => req.response.compression = .{
                        .gzip = std.compress.gzip.decompress(req.client.allocator, req.transferReader()) catch return error.CompressionInitializationFailed,
                    },
                    .zstd => req.response.compression = .{
                        .zstd = std.compress.zstd.decompressStream(req.client.allocator, req.transferReader()),
                    },
                }
            }

            return .{ .done = true };
        }
        return .{ .done = false };
    }

    pub const ReadError = TransferReadError || proto.HeadersParser.CheckCompleteHeadError || error{ DecompressionFailure, InvalidTrailers };

    pub const Reader = std.io.Reader(*Request, ReadError, read);

    pub fn reader(req: *Request) Reader {
        return .{ .context = req };
    }

    /// Reads data from the response body. Must be called after `wait`.
    pub fn read(req: *Request, buffer: []u8) ReadError!usize {
        const out_index = switch (req.response.compression) {
            .deflate => |*deflate| deflate.read(buffer) catch return error.DecompressionFailure,
            .gzip => |*gzip| gzip.read(buffer) catch return error.DecompressionFailure,
            .zstd => |*zstd| zstd.read(buffer) catch return error.DecompressionFailure,
            else => try req.transferRead(buffer),
        };

        if (out_index == 0) {
            const has_trail = !req.response.parser.state.isContent();

            while (!req.response.parser.state.isContent()) { // read trailing headers
                try req.connection.?.fill();

                const nchecked = try req.response.parser.checkCompleteHead(req.client.allocator, req.connection.?.peek());
                req.connection.?.drop(@intCast(nchecked));
            }

            if (has_trail) {
                // The response headers before the trailers are already guaranteed to be valid, so they will always be parsed again and cannot return an error.
                // This will *only* fail for a malformed trailer.
                req.response.parse(req.response.parser.header_bytes.items, true) catch return error.InvalidTrailers;
            }
        }

        return out_index;
    }

    /// Reads data from the response body. Must be called after `wait`.
    pub fn readAll(req: *Request, buffer: []u8) !usize {
        var index: usize = 0;
        while (index < buffer.len) {
            const amt = try read(req, buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    pub const WriteError = Connection.WriteError || error{ NotWriteable, MessageTooLong };

    pub const Writer = std.io.Writer(*Request, WriteError, write);

    pub fn writer(req: *Request) Writer {
        return .{ .context = req };
    }

    /// Write `bytes` to the server. The `transfer_encoding` field determines how data will be sent.
    /// Must be called after `send` and before `finish`.
    pub fn write(req: *Request, bytes: []const u8) WriteError!usize {
        switch (req.transfer_encoding) {
            .chunked => {
                try req.connection.?.writer().print("{x}\r\n", .{bytes.len});
                try req.connection.?.writer().writeAll(bytes);
                try req.connection.?.writer().writeAll("\r\n");

                return bytes.len;
            },
            .content_length => |*len| {
                if (len.* < bytes.len) return error.MessageTooLong;

                const amt = try req.connection.?.write(bytes);
                len.* -= amt;
                return amt;
            },
            .none => return error.NotWriteable,
        }
    }

    /// Write `bytes` to the server. The `transfer_encoding` field determines how data will be sent.
    /// Must be called after `send` and before `finish`.
    pub fn writeAll(req: *Request, bytes: []const u8) WriteError!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try write(req, bytes[index..]);
        }
    }

    pub const FinishError = WriteError || error{MessageNotCompleted};

    /// Finish the body of a request. This notifies the server that you have no more data to send.
    /// Must be called after `send`.
    pub fn finish(req: *Request) FinishError!void {
        try req.common_finish();
        try req.connection.?.flush();
    }

    pub fn async_finish(req: *Request, ctx: *Ctx, comptime cbk: Cbk) !void {
        try req.common_finish();
        req.connection.?.async_flush(ctx, cbk) catch |err| switch (err) {
            error.WriteEmpty => return cbk(ctx, {}),
            else => return cbk(ctx, err),
        };
    }

    fn common_finish(req: *Request) FinishError!void {
        switch (req.transfer_encoding) {
            .chunked => try req.connection.?.writer().writeAll("0\r\n\r\n"),
            .content_length => |len| if (len != 0) return error.MessageNotCompleted,
            .none => {},
        }
    }
};

pub const Proxy = struct {
    allocator: Allocator,
    headers: http.Headers,

    protocol: Connection.Protocol,
    host: []const u8,
    port: u16,

    supports_connect: bool = true,
};

/// Release all associated resources with the client.
///
/// All pending requests must be de-initialized and all active connections released
/// before calling this function.
pub fn deinit(client: *Client) void {
    assert(client.connection_pool.used.first == null); // There are still active requests.

    client.connection_pool.deinit(client.allocator);

    if (client.http_proxy) |*proxy| {
        proxy.allocator.free(proxy.host);
        proxy.headers.deinit();
    }

    if (client.https_proxy) |*proxy| {
        proxy.allocator.free(proxy.host);
        proxy.headers.deinit();
    }

    if (!disable_tls)
        client.ca_bundle.deinit(client.allocator);

    client.* = undefined;
}

/// Uses the *_proxy environment variable to set any unset proxies for the client.
/// This function *must not* be called when the client has any active connections.
pub fn loadDefaultProxies(client: *Client) !void {
    // Prevent any new connections from being created.
    client.connection_pool.mutex.lock();
    defer client.connection_pool.mutex.unlock();

    assert(client.connection_pool.used.first == null); // There are still active requests.

    if (client.http_proxy == null) http: {
        const content: []const u8 = if (std.process.hasEnvVarConstant("http_proxy"))
            try std.process.getEnvVarOwned(client.allocator, "http_proxy")
        else if (std.process.hasEnvVarConstant("HTTP_PROXY"))
            try std.process.getEnvVarOwned(client.allocator, "HTTP_PROXY")
        else if (std.process.hasEnvVarConstant("all_proxy"))
            try std.process.getEnvVarOwned(client.allocator, "all_proxy")
        else if (std.process.hasEnvVarConstant("ALL_PROXY"))
            try std.process.getEnvVarOwned(client.allocator, "ALL_PROXY")
        else
            break :http;
        defer client.allocator.free(content);

        const uri = Uri.parse(content) catch
            Uri.parseWithoutScheme(content) catch
            break :http;

        const protocol = if (uri.scheme.len == 0)
            .plain // No scheme, assume http://
        else
            protocol_map.get(uri.scheme) orelse break :http; // Unknown scheme, ignore

        const host = if (uri.host) |host| try client.allocator.dupe(u8, host) else break :http; // Missing host, ignore
        client.http_proxy = .{
            .allocator = client.allocator,
            .headers = .{ .allocator = client.allocator },

            .protocol = protocol,
            .host = host,
            .port = uri.port orelse switch (protocol) {
                .plain => 80,
                .tls => 443,
            },
        };

        if (uri.user != null and uri.password != null) {
            const prefix = "Basic ";

            const unencoded = try std.fmt.allocPrint(client.allocator, "{s}:{s}", .{ uri.user.?, uri.password.? });
            defer client.allocator.free(unencoded);

            const buffer = try client.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(unencoded.len) + prefix.len);
            defer client.allocator.free(buffer);

            const result = std.base64.standard.Encoder.encode(buffer[prefix.len..], unencoded);
            @memcpy(buffer[0..prefix.len], prefix);

            try client.http_proxy.?.headers.append("proxy-authorization", result);
        }
    }

    if (client.https_proxy == null) https: {
        const content: []const u8 = if (std.process.hasEnvVarConstant("https_proxy"))
            try std.process.getEnvVarOwned(client.allocator, "https_proxy")
        else if (std.process.hasEnvVarConstant("HTTPS_PROXY"))
            try std.process.getEnvVarOwned(client.allocator, "HTTPS_PROXY")
        else if (std.process.hasEnvVarConstant("all_proxy"))
            try std.process.getEnvVarOwned(client.allocator, "all_proxy")
        else if (std.process.hasEnvVarConstant("ALL_PROXY"))
            try std.process.getEnvVarOwned(client.allocator, "ALL_PROXY")
        else
            break :https;
        defer client.allocator.free(content);

        const uri = Uri.parse(content) catch
            Uri.parseWithoutScheme(content) catch
            break :https;

        const protocol = if (uri.scheme.len == 0)
            .plain // No scheme, assume http://
        else
            protocol_map.get(uri.scheme) orelse break :https; // Unknown scheme, ignore

        const host = if (uri.host) |host| try client.allocator.dupe(u8, host) else break :https; // Missing host, ignore
        client.https_proxy = .{
            .allocator = client.allocator,
            .headers = .{ .allocator = client.allocator },

            .protocol = protocol,
            .host = host,
            .port = uri.port orelse switch (protocol) {
                .plain => 80,
                .tls => 443,
            },
        };

        if (uri.user != null and uri.password != null) {
            const prefix = "Basic ";

            const unencoded = try std.fmt.allocPrint(client.allocator, "{s}:{s}", .{ uri.user.?, uri.password.? });
            defer client.allocator.free(unencoded);

            const buffer = try client.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(unencoded.len) + prefix.len);
            defer client.allocator.free(buffer);

            const result = std.base64.standard.Encoder.encode(buffer[prefix.len..], unencoded);
            @memcpy(buffer[0..prefix.len], prefix);

            try client.https_proxy.?.headers.append("proxy-authorization", result);
        }
    }
}

pub const ConnectTcpError = Allocator.Error || error{ ConnectionRefused, NetworkUnreachable, ConnectionTimedOut, ConnectionResetByPeer, TemporaryNameServerFailure, NameServerFailure, UnknownHostName, HostLacksNetworkAddresses, UnexpectedConnectFailure, TlsInitializationFailed };

// requires ctx.data.stream to be set
fn setConnection(ctx: *Ctx, res: anyerror!void) !void {

    // check stream
    errdefer ctx.data.conn.stream.close();
    res catch |e| {
        // ctx.data.conn.stream.close(); is it needed with errdefer?
        switch (e) {
            error.ConnectionRefused,
            error.NetworkUnreachable,
            error.ConnectionTimedOut,
            error.ConnectionResetByPeer,
            error.TemporaryNameServerFailure,
            error.NameServerFailure,
            error.UnknownHostName,
            error.HostLacksNetworkAddresses,
            => return ctx.pop(e),
            else => return ctx.pop(error.UnexpectedConnectFailure),
        }
    };

    // TODO: tls stuff
    if (ctx.data.conn.protocol == .tls) {
        return ctx.pop(error.TlsNotSupported);
    }
    // if (protocol == .tls) {
    //     if (disable_tls) unreachable;

    //     conn.data.tls_client = try client.allocator.create(std.crypto.tls.Client);
    //     errdefer client.allocator.destroy(conn.data.tls_client);

    //     conn.data.tls_client.* = std.crypto.tls.Client.init(stream, client.ca_bundle, host) catch return error.TlsInitializationFailed;
    //     // This is appropriate for HTTPS because the HTTP headers contain
    //     // the content length which is used to detect truncation attacks.
    //     conn.data.tls_client.allow_truncation_attacks = true;
    // }

    // add connection node in pool
    const node = ctx.req.client.allocator.create(ConnectionPool.Node) catch |e| return ctx.pop(e);
    errdefer ctx.req.client.allocator.destroy(node);
    // NOTE we can not use the ctx.data.conn pointer as a node connection data,
    // we need to copy it's value and use this reference for the connection
    node.* = .{
        .data = .{
            .stream = ctx.data.conn.stream,
            .tls_client = undefined,
            .protocol = ctx.data.conn.protocol,
            .host = ctx.data.conn.host,
            .port = ctx.data.conn.port,
        },
    };
    // remove old pointer, now useless
    const old_conn = ctx.data.conn;
    defer ctx.req.client.allocator.destroy(old_conn);

    ctx.req.client.connection_pool.addUsed(node);
    ctx.data.conn = &node.data;

    return ctx.pop({});
}

/// Connect to `host:port` using the specified protocol. This will reuse a connection if one is already open.
/// This function is threadsafe.
pub fn async_connectTcp(
    client: *Client,
    host: []const u8,
    port: u16,
    protocol: Connection.Protocol,
    ctx: *Ctx,
    comptime cbk: Cbk,
) !void {
    try ctx.push(cbk);
    if (ctx.req.client.connection_pool.findConnection(.{
        .host = host,
        .port = port,
        .protocol = protocol,
    })) |conn| {
        ctx.req.connection = conn;
        return ctx.pop({});
    }

    if (disable_tls and protocol == .tls)
        return error.TlsInitializationFailed;

    return async_net.async_tcpConnectToHost(
        client.allocator,
        host,
        port,
        ctx,
        setConnection,
    );
}

pub const ConnectUnixError = Allocator.Error || std.os.SocketError || error{ NameTooLong, Unsupported } || std.os.ConnectError;

/// Connect to `path` as a unix domain socket. This will reuse a connection if one is already open.
/// This function is threadsafe.
// pub fn connectUnix(client: *Client, path: []const u8) ConnectUnixError!*Connection {
//     if (!net.has_unix_sockets) return error.Unsupported;

//     if (client.connection_pool.findConnection(.{
//         .host = path,
//         .port = 0,
//         .protocol = .plain,
//     })) |node|
//         return node;

//     const conn = try client.allocator.create(ConnectionPool.Node);
//     errdefer client.allocator.destroy(conn);
//     conn.* = .{ .data = undefined };

//     const stream = try std.net.connectUnixSocket(path);
//     errdefer stream.close();

//     conn.data = .{
//         .stream = stream,
//         .tls_client = undefined,
//         .protocol = .plain,

//         .host = try client.allocator.dupe(u8, path),
//         .port = 0,
//     };
//     errdefer client.allocator.free(conn.data.host);

//     client.connection_pool.addUsed(conn);

//     return &conn.data;
// }

/// Connect to `tunnel_host:tunnel_port` using the specified proxy with HTTP CONNECT. This will reuse a connection if one is already open.
/// This function is threadsafe.
// pub fn connectTunnel(
//     client: *Client,
//     proxy: *Proxy,
//     tunnel_host: []const u8,
//     tunnel_port: u16,
// ) !*Connection {
//     if (!proxy.supports_connect) return error.TunnelNotSupported;

//     if (client.connection_pool.findConnection(.{
//         .host = tunnel_host,
//         .port = tunnel_port,
//         .protocol = proxy.protocol,
//     })) |node|
//         return node;

//     var maybe_valid = false;
//     (tunnel: {
//         const conn = try client.connectTcp(proxy.host, proxy.port, proxy.protocol);
//         errdefer {
//             conn.closing = true;
//             client.connection_pool.release(client.allocator, conn);
//         }

//         const uri = Uri{
//             .scheme = "http",
//             .user = null,
//             .password = null,
//             .host = tunnel_host,
//             .port = tunnel_port,
//             .path = "",
//             .query = null,
//             .fragment = null,
//         };

//         // we can use a small buffer here because a CONNECT response should be very small
//         var buffer: [8096]u8 = undefined;

//         var req = client.open(.CONNECT, uri, proxy.headers, .{
//             .handle_redirects = false,
//             .connection = conn,
//             .header_strategy = .{ .static = &buffer },
//         }) catch |err| {
//             std.log.debug("err {}", .{err});
//             break :tunnel err;
//         };
//         defer req.deinit();

//         req.send(.{ .raw_uri = true }) catch |err| break :tunnel err;
//         req.wait() catch |err| break :tunnel err;

//         if (req.response.status.class() == .server_error) {
//             maybe_valid = true;
//             break :tunnel error.ServerError;
//         }

//         if (req.response.status != .ok) break :tunnel error.ConnectionRefused;

//         // this connection is now a tunnel, so we can't use it for anything else, it will only be released when the client is de-initialized.
//         req.connection = null;

//         client.allocator.free(conn.host);
//         conn.host = try client.allocator.dupe(u8, tunnel_host);
//         errdefer client.allocator.free(conn.host);

//         conn.port = tunnel_port;
//         conn.closing = false;

//         return conn;
//     }) catch {
//         // something went wrong with the tunnel
//         proxy.supports_connect = maybe_valid;
//         return error.TunnelNotSupported;
//     };
// }

// Prevents a dependency loop in open()
const ConnectErrorPartial = ConnectTcpError || error{ UnsupportedUrlScheme, ConnectionRefused };
pub const ConnectError = ConnectErrorPartial || RequestError;

fn onConnectProxy(ctx: *Ctx, res: anyerror!void) anyerror!void {
    res catch |e| {
        ctx.data.conn.closing = true;
        ctx.req.client.connection_pool.release(ctx.req.client.allocator, ctx.data.conn);
        return ctx.pop(e);
    };
    ctx.data.conn.proxied = true;
    return ctx.pop({});
}

/// Connect to `host:port` using the specified protocol. This will reuse a connection if one is already open.
///
/// If a proxy is configured for the client, then the proxy will be used to connect to the host.
///
/// This function is threadsafe.
pub fn async_connect(
    client: *Client,
    host: []const u8,
    port: u16,
    protocol: Connection.Protocol,
    ctx: *Ctx,
    comptime cbk: Cbk,
) !void {
    // pointer required so that `supports_connect` can be updated if a CONNECT fails
    const potential_proxy: ?*Proxy = switch (protocol) {
        .plain => if (client.http_proxy) |*proxy_info| proxy_info else null,
        .tls => if (client.https_proxy) |*proxy_info| proxy_info else null,
    };

    if (potential_proxy) |proxy| {
        // don't attempt to proxy the proxy thru itself.
        if (std.mem.eql(u8, proxy.host, host) and proxy.port == port and proxy.protocol == protocol) {
            return client.async_connectTcp(host, port, protocol, ctx, cbk);
        }

        // TODO: enable tunnel
        // if (proxy.supports_connect) tunnel: {
        //     return connectTunnel(client, ctx, proxy, host, port) catch |err| switch (err) {
        //         error.TunnelNotSupported => break :tunnel,
        //         else => |e| return e,
        //     };
        // }

        // fall back to using the proxy as a normal http proxy
        try ctx.push(cbk);
        return client.async_connectTcp(proxy.host, proxy.port, proxy.protocol, ctx, onConnectProxy);
    }

    return client.async_connectTcp(host, port, protocol, ctx, cbk);
}

pub const RequestError = ConnectTcpError || ConnectErrorPartial || Request.SendError || std.fmt.ParseIntError || Connection.WriteError || error{
    UnsupportedUrlScheme,
    UriMissingHost,

    CertificateBundleLoadFailure,
    UnsupportedTransferEncoding,
};

pub const RequestOptions = struct {
    version: http.Version = .@"HTTP/1.1",

    /// Automatically ignore 100 Continue responses. This assumes you don't care, and will have sent the body before you
    /// wait for the response.
    ///
    /// If this is not the case AND you know the server will send a 100 Continue, set this to false and wait for a
    /// response before sending the body. If you wait AND the server does not send a 100 Continue before you finish the
    /// request, then the request *will* deadlock.
    handle_continue: bool = true,

    handle_redirects: bool = true,
    max_redirects: u32 = 3,
    header_strategy: StorageStrategy = .{ .dynamic = 16 * 1024 },

    /// Must be an already acquired connection.
    connection: ?*Connection = null,

    pub const StorageStrategy = union(enum) {
        /// In this case, the client's Allocator will be used to store the
        /// entire HTTP header. This value is the maximum total size of
        /// HTTP headers allowed, otherwise
        /// error.HttpHeadersExceededSizeLimit is returned from read().
        dynamic: usize,
        /// This is used to store the entire HTTP header. If the HTTP
        /// header is too big to fit, `error.HttpHeadersExceededSizeLimit`
        /// is returned from read(). When this is used, `error.OutOfMemory`
        /// cannot be returned from `read()`.
        static: []u8,
    };
};

pub const protocol_map = std.ComptimeStringMap(Connection.Protocol, .{
    .{ "http", .plain },
    .{ "ws", .plain },
    .{ "https", .tls },
    .{ "wss", .tls },
});

// requires ctx.data.conn to be set
fn setRequestConnection(ctx: *Ctx, res: anyerror!void) anyerror!void {
    res catch |e| return ctx.pop(e);

    ctx.req.connection = ctx.data.conn;
    return ctx.pop({});
}

/// Open a connection to the host specified by `uri` and prepare to send a HTTP request.
///
/// `uri` must remain alive during the entire request.
/// `headers` is cloned and may be freed after this function returns.
///
/// The caller is responsible for calling `deinit()` on the `Request`.
/// This function is threadsafe.
pub fn async_open(
    client: *Client,
    method: http.Method,
    uri: Uri,
    headers: http.Headers,
    options: RequestOptions,
    ctx: *Ctx,
    comptime cbk: Cbk,
) !void {
    const protocol = protocol_map.get(uri.scheme) orelse return error.UnsupportedUrlScheme;
    const port: u16 = uri.port orelse switch (protocol) {
        .plain => 80,
        .tls => 443,
    };
    const host = uri.host orelse return error.UriMissingHost;

    // add fields to request
    ctx.req.uri = uri;
    ctx.req.method = method;
    ctx.req.version = options.version;
    ctx.req.redirects_left = options.max_redirects;
    ctx.req.handle_redirects = options.handle_redirects;
    ctx.req.handle_continue = options.handle_continue;
    // TODO: we need to copy headers,
    // cf. comment "Headers must be cloned to properly handle header transformations in redirects."
    ctx.req.headers = try headers.clone(client.allocator);
    ctx.req.response = .{
        .status = undefined,
        .reason = undefined,
        .version = undefined,
        .headers = http.Headers{ .allocator = ctx.req.arena.allocator(), .owned = false },
        .parser = switch (options.header_strategy) {
            .dynamic => |max| proto.HeadersParser.initDynamic(max),
            .static => |buf| proto.HeadersParser.initStatic(buf),
        },
    };

    // TODO: tls stuff
    if (protocol == .tls) return error.TlsNotSupported;
    // if (protocol == .tls and @atomicLoad(bool, &client.next_https_rescan_certs, .Acquire)) {
    //     if (disable_tls) unreachable;

    //     client.ca_bundle_mutex.lock();
    //     defer client.ca_bundle_mutex.unlock();

    //     if (client.next_https_rescan_certs) {
    //         client.ca_bundle.rescan(client.allocator) catch return error.CertificateBundleLoadFailure;
    //         @atomicStore(bool, &client.next_https_rescan_certs, false, .Release);
    //     }
    // }

    // we already have the connection,
    // set it and call directly the callback
    if (options.connection) |conn| {
        ctx.req.connection = conn;
        return cbk(ctx, {});
    }

    // push callback function
    try ctx.push(cbk);

    // add fields to connection
    ctx.data.conn.protocol = protocol;
    ctx.data.conn.host = try client.allocator.dupe(u8, host);
    ctx.data.conn.port = port;

    return client.async_connect(host, port, protocol, ctx, setRequestConnection);
}

pub const FetchOptions = struct {
    pub const Location = union(enum) {
        url: []const u8,
        uri: Uri,
    };

    pub const Payload = union(enum) {
        string: []const u8,
        file: std.fs.File,
        none,
    };

    pub const ResponseStrategy = union(enum) {
        storage: RequestOptions.StorageStrategy,
        file: std.fs.File,
        none,
    };

    header_strategy: RequestOptions.StorageStrategy = .{ .dynamic = 16 * 1024 },
    response_strategy: ResponseStrategy = .{ .storage = .{ .dynamic = 16 * 1024 * 1024 } },

    location: Location,
    method: http.Method = .GET,
    headers: http.Headers = http.Headers{ .allocator = std.heap.page_allocator, .owned = false },
    payload: Payload = .none,
    raw_uri: bool = false,
};

pub const FetchResult = struct {
    status: http.Status,
    body: ?[]const u8 = null,
    headers: http.Headers,

    allocator: Allocator,
    options: FetchOptions,

    pub fn deinit(res: *FetchResult) void {
        if (res.options.response_strategy == .storage and res.options.response_strategy.storage == .dynamic) {
            if (res.body) |body| res.allocator.free(body);
        }

        res.headers.deinit();
    }
};

// TODO: enable fetch
// /// Perform a one-shot HTTP request with the provided options.
// ///
// /// This function is threadsafe.
// pub fn fetch(client: *Client, allocator: Allocator, options: FetchOptions) !FetchResult {
//     const has_transfer_encoding = options.headers.contains("transfer-encoding");
//     const has_content_length = options.headers.contains("content-length");

//     if (has_content_length or has_transfer_encoding) return error.UnsupportedHeader;

//     const uri = switch (options.location) {
//         .url => |u| try Uri.parse(u),
//         .uri => |u| u,
//     };

//     var req = try open(client, options.method, uri, options.headers, .{
//         .header_strategy = options.header_strategy,
//         .handle_redirects = options.payload == .none,
//     });
//     defer req.deinit();

//     { // Block to maintain lock of file to attempt to prevent a race condition where another process modifies the file while we are reading it.
//         // This relies on other processes actually obeying the advisory lock, which is not guaranteed.
//         if (options.payload == .file) try options.payload.file.lock(.shared);
//         defer if (options.payload == .file) options.payload.file.unlock();

//         switch (options.payload) {
//             .string => |str| req.transfer_encoding = .{ .content_length = str.len },
//             .file => |file| req.transfer_encoding = .{ .content_length = (try file.stat()).size },
//             .none => {},
//         }

//         try req.send(.{ .raw_uri = options.raw_uri });

//         switch (options.payload) {
//             .string => |str| try req.writeAll(str),
//             .file => |file| {
//                 try file.seekTo(0);
//                 var fifo = std.fifo.LinearFifo(u8, .{ .Static = 8192 }).init();
//                 try fifo.pump(file.reader(), req.writer());
//             },
//             .none => {},
//         }

//         try req.finish();
//     }

//     try req.wait();

//     var res = FetchResult{
//         .status = req.response.status,
//         .headers = try req.response.headers.clone(allocator),

//         .allocator = allocator,
//         .options = options,
//     };

//     switch (options.response_strategy) {
//         .storage => |storage| switch (storage) {
//             .dynamic => |max| res.body = try req.reader().readAllAlloc(allocator, max),
//             .static => |buf| res.body = buf[0..try req.reader().readAll(buf)],
//         },
//         .file => |file| {
//             var fifo = std.fifo.LinearFifo(u8, .{ .Static = 8192 }).init();
//             try fifo.pump(req.reader(), file.writer());
//         },
//         .none => { // Take advantage of request internals to discard the response body and make the connection available for another request.
//             req.response.skip = true;

//             const empty = @as([*]u8, undefined)[0..0];
//             assert(try req.transferRead(empty) == 0); // we're skipping, no buffer is necessary
//         },
//     }

//     return res;
// }

// test {
//     const native_endian = comptime builtin.cpu.arch.endian();
//     if (builtin.zig_backend == .stage2_llvm and native_endian == .big) {
//         // https://github.com/ziglang/zig/issues/13782
//         return error.SkipZigTest;
//     }

//     if (builtin.os.tag == .wasi) return error.SkipZigTest;

//     if (builtin.zig_backend == .stage2_x86_64 and
//         !comptime std.Target.x86.featureSetHas(builtin.cpu.features, .avx)) return error.SkipZigTest;

//     std.testing.refAllDecls(@This());
// }

fn onRequestWait(ctx: *Ctx, res: anyerror!void) !void {
    res catch |e| {
        std.debug.print("error: {any}\n", .{e});
        return e;
    };
    std.log.debug("REQUEST WAIT", .{});
    std.debug.print("Status code: {any}\n", .{ctx.req.response.status});
    const body = try ctx.req.reader().readAllAlloc(ctx.alloc(), 2000);
    std.log.debug("BODY {s}", .{body});
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
    return ctx.req.async_send(.{}, ctx, onRequestSend);
}

test {
    const alloc = std.testing.allocator;

    const loop = try alloc.create(Loop);
    defer alloc.destroy(loop);
    loop.* = .{};

    var client = Client{ .allocator = alloc };
    defer client.deinit();

    const req = try alloc.create(Request);
    defer alloc.destroy(req);
    req.* = .{
        .client = &client,
        .arena = std.heap.ArenaAllocator.init(client.allocator),
    };
    defer req.deinit();

    const ctx = try alloc.create(Ctx);
    defer alloc.destroy(ctx);
    ctx.* = try Ctx.init(loop, req);
    defer ctx.deinit();

    var headers = try std.http.Headers.initList(alloc, &[_]std.http.Field{});
    defer headers.deinit();

    // const url = "http://www.example.com";
    const url = "http://127.0.0.1:8000/zig";
    try client.open(
    try client.async_open(
        .GET,
        try std.Uri.parse(url),
        headers,
        .{},
        ctx,
        onRequestConnect,
    );
}
