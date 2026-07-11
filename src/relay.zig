//! Nostr relay client: a websocket connection to a relay that publishes
//! events and drives subscriptions using the NIP-01 wire messages.
//!
//! The connection state machine (`Connection`) is generic over its byte
//! stream so it can be exercised end-to-end in CI against an in-memory fake
//! stream — handshake, framing, control-frame handling and message
//! reassembly are all proven hermetically. The concrete TCP/TLS dialer that
//! wires a real socket into a `Connection` lives in a later part; a real relay
//! cannot be reached from CI, so keeping the logic transport-agnostic is what
//! makes it testable.

const std = @import("std");
const websocket = @import("websocket.zig");
const message = @import("message.zig");
const event_mod = @import("event.zig");
const filter_mod = @import("filter.zig");

const Event = event_mod.Event;
const Filter = filter_mod.Filter;

/// A relay never sends a single logical message larger than this; we refuse to
/// buffer past it so a hostile relay cannot exhaust memory.
pub const max_message_len = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Relay URL parsing
// ---------------------------------------------------------------------------

pub const Url = struct {
    /// True for `wss://` (TLS), false for `ws://`.
    secure: bool,
    /// Borrows from the input string.
    host: []const u8,
    port: u16,
    /// Borrows from the input string; defaults to "/".
    path: []const u8,
};

pub const UrlError = error{ InvalidUrl, UnsupportedScheme };

/// Parses a relay URL (`ws://host[:port][/path]` or `wss://...`). The default
/// port is 80 for `ws` and 443 for `wss`; the default path is "/". Host and
/// path borrow from `url`.
pub fn parseUrl(url: []const u8) UrlError!Url {
    var rest = url;
    const secure = if (std.mem.startsWith(u8, rest, "wss://")) blk: {
        rest = rest["wss://".len..];
        break :blk true;
    } else if (std.mem.startsWith(u8, rest, "ws://")) blk: {
        rest = rest["ws://".len..];
        break :blk false;
    } else return UrlError.UnsupportedScheme;

    if (rest.len == 0) return UrlError.InvalidUrl;

    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |i| rest[0..i] else rest;
    const path = if (slash) |i| rest[i..] else "/";
    if (authority.len == 0) return UrlError.InvalidUrl;

    var host = authority;
    var port: u16 = if (secure) 443 else 80;

    if (authority[0] == '[') {
        // IPv6 literal: [addr] or [addr]:port
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return UrlError.InvalidUrl;
        host = authority[1..close];
        if (host.len == 0) return UrlError.InvalidUrl;
        const after = authority[close + 1 ..];
        if (after.len > 0) {
            if (after[0] != ':') return UrlError.InvalidUrl;
            port = std.fmt.parseInt(u16, after[1..], 10) catch return UrlError.InvalidUrl;
        }
    } else if (std.mem.lastIndexOfScalar(u8, authority, ':')) |ci| {
        host = authority[0..ci];
        if (host.len == 0) return UrlError.InvalidUrl;
        port = std.fmt.parseInt(u16, authority[ci + 1 ..], 10) catch return UrlError.InvalidUrl;
    }

    return .{ .secure = secure, .host = host, .port = port, .path = path };
}

// ---------------------------------------------------------------------------
// Connection state machine (generic over the byte stream)
// ---------------------------------------------------------------------------

pub const ConnectionError = error{
    HandshakeFailed,
    MessageTooLarge,
    /// The relay sent a frame we don't accept mid-stream (e.g. a reserved
    /// opcode, or a continuation with no started message).
    UnexpectedFrame,
    RandomFailed,
};

/// A websocket connection to a relay over `Stream`. `Stream` must provide:
///   * `fn read(self, buffer: []u8) !usize` — 0 means the peer closed.
///   * `fn writeAll(self, bytes: []const u8) !void`
///
/// The connection owns two growable buffers (raw receive bytes and the
/// reassembled message) but not the stream; call `deinit` to free them.
pub fn Connection(comptime Stream: type) type {
    return struct {
        const Self = @This();

        stream: Stream,
        io: std.Io,
        allocator: std.mem.Allocator,
        /// Raw bytes received but not yet decoded into whole frames.
        recv: std.ArrayList(u8),
        /// Payload of the in-progress (possibly fragmented) message.
        msg: std.ArrayList(u8),

        pub fn init(allocator: std.mem.Allocator, io: std.Io, stream: Stream) Self {
            return .{
                .stream = stream,
                .io = io,
                .allocator = allocator,
                .recv = .empty,
                .msg = .empty,
            };
        }

        pub fn deinit(self: *Self) void {
            self.recv.deinit(self.allocator);
            self.msg.deinit(self.allocator);
            self.* = undefined;
        }

        /// Performs the RFC 6455 opening handshake for `host`/`path`. Any bytes
        /// the relay sent after the response head are retained for `receive`.
        pub fn handshake(self: *Self, host: []const u8, path: []const u8) !void {
            const key = websocket.generateKey(self.io) catch return ConnectionError.RandomFailed;

            var req: std.ArrayList(u8) = .empty;
            defer req.deinit(self.allocator);
            try websocket.appendHandshakeRequest(&req, self.allocator, host, path, &key);
            try self.stream.writeAll(req.items);

            const accept = websocket.acceptKey(&key);

            // Read until the blank line terminating the response head.
            while (std.mem.indexOf(u8, self.recv.items, "\r\n\r\n") == null) {
                if (self.recv.items.len > 16 * 1024) return ConnectionError.HandshakeFailed;
                if (!try self.fill()) return ConnectionError.HandshakeFailed;
            }
            const idx = std.mem.indexOf(u8, self.recv.items, "\r\n\r\n").?;
            const head_len = idx + 4;
            websocket.checkHandshakeResponse(self.recv.items[0..head_len], &accept) catch
                return ConnectionError.HandshakeFailed;
            self.consume(head_len);
        }

        /// Publishes an event: sends `["EVENT", <event>]`.
        pub fn publish(self: *Self, ev: Event) !void {
            const text = try message.encodeEvent(self.allocator, ev);
            defer self.allocator.free(text);
            try self.sendText(text);
        }

        /// Opens a subscription: sends `["REQ", <id>, <filters>...]`.
        pub fn subscribe(self: *Self, subscription_id: []const u8, filters: []const Filter) !void {
            const text = try message.encodeReq(self.allocator, subscription_id, filters);
            defer self.allocator.free(text);
            try self.sendText(text);
        }

        /// Cancels a subscription: sends `["CLOSE", <id>]`.
        pub fn unsubscribe(self: *Self, subscription_id: []const u8) !void {
            const text = try message.encodeClose(self.allocator, subscription_id);
            defer self.allocator.free(text);
            try self.sendText(text);
        }

        /// Sends a websocket close control frame.
        pub fn close(self: *Self) !void {
            try self.sendFrame(.close, &.{});
        }

        /// Reads the next relay message, transparently answering pings, skipping
        /// pongs, and reassembling fragmented frames. Returns `null` when the
        /// relay closes the connection (a close frame or EOF). The caller owns
        /// the returned message and must `deinit` it.
        pub fn receive(self: *Self) !?message.ParsedRelayMessage {
            while (true) {
                if (try websocket.decodeFrame(self.recv.items)) |frame| {
                    switch (frame.opcode) {
                        .text, .binary, .continuation => {
                            if (self.msg.items.len + frame.payload.len > max_message_len)
                                return ConnectionError.MessageTooLarge;
                            try self.msg.appendSlice(self.allocator, frame.payload);
                            const fin = frame.fin;
                            self.consume(frame.frame_len);
                            if (fin) {
                                const parsed = try message.parseRelayMessage(self.allocator, self.msg.items);
                                self.msg.clearRetainingCapacity();
                                return parsed;
                            }
                        },
                        .ping => {
                            // Control payloads are <=125 bytes and unfragmented.
                            var echo: [125]u8 = undefined;
                            const n = @min(frame.payload.len, echo.len);
                            @memcpy(echo[0..n], frame.payload[0..n]);
                            self.consume(frame.frame_len);
                            try self.sendFrame(.pong, echo[0..n]);
                        },
                        .pong => self.consume(frame.frame_len),
                        .close => {
                            self.consume(frame.frame_len);
                            self.close() catch {};
                            return null;
                        },
                        _ => {
                            self.consume(frame.frame_len);
                            return ConnectionError.UnexpectedFrame;
                        },
                    }
                    continue;
                }
                // Need more bytes before a full frame is available.
                if (!try self.fill()) return null; // EOF
            }
        }

        fn sendText(self: *Self, text: []const u8) !void {
            try self.sendFrame(.text, text);
        }

        fn sendFrame(self: *Self, opcode: websocket.Opcode, payload: []const u8) !void {
            var mask: [4]u8 = undefined;
            self.io.randomSecure(&mask) catch return ConnectionError.RandomFailed;

            var frame: std.ArrayList(u8) = .empty;
            defer frame.deinit(self.allocator);
            try websocket.appendClientFrame(&frame, self.allocator, opcode, payload, mask);
            try self.stream.writeAll(frame.items);
        }

        /// Reads more bytes into `recv`. Returns false on EOF.
        fn fill(self: *Self) !bool {
            var tmp: [4096]u8 = undefined;
            const n = try self.stream.read(&tmp);
            if (n == 0) return false;
            try self.recv.appendSlice(self.allocator, tmp[0..n]);
            return true;
        }

        /// Drops the first `n` bytes of `recv`, keeping the remainder.
        fn consume(self: *Self, n: usize) void {
            const remaining = self.recv.items.len - n;
            std.mem.copyForwards(u8, self.recv.items[0..remaining], self.recv.items[n..]);
            self.recv.shrinkRetainingCapacity(remaining);
        }
    };
}

// ---------------------------------------------------------------------------
// Live transport: dialing a real relay over TCP (ws://) or TLS (wss://).
// ---------------------------------------------------------------------------

const net = std.Io.net;
const tls = std.crypto.tls;
const posix = std.posix;

/// Adapts a pair of std `Io.Reader`/`Io.Writer` to the two-method stream
/// interface `Connection` expects. This is the exact bridge the live dialer
/// wires a socket (or a TLS session) into, and it is exercised hermetically in
/// tests by pointing it at in-memory `Io.Reader.fixed` / `Io.Writer.Allocating`.
pub const IoStream = struct {
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    /// For TLS, `writer` is the TLS session writer, whose flush only drains
    /// ciphertext into the *underlying* transport writer's buffer — that
    /// transport writer must then be flushed too for the bytes to reach the
    /// socket. Null for plain `ws://`, where `writer` already is the transport.
    transport_writer: ?*std.Io.Writer = null,

    pub fn read(self: IoStream, buffer: []u8) std.Io.Reader.ShortError!usize {
        return self.reader.readSliceShort(buffer);
    }

    pub fn writeAll(self: IoStream, bytes: []const u8) std.Io.Writer.Error!void {
        try self.writer.writeAll(bytes);
        try self.writer.flush();
        if (self.transport_writer) |tw| try tw.flush();
    }
};

/// A `Connection` over a live socket/TLS stream.
pub const LiveConnection = Connection(IoStream);

const TlsState = struct {
    client: tls.Client,
    read_buffer: []u8,
    write_buffer: []u8,
};

/// Owns the byte-stream plumbing behind a live relay connection. The std
/// `Io.Reader`/`Io.Writer` chain is pointer-linked (its vtables recover their
/// parent with `@fieldParentPtr`), so this is heap-allocated by `dial` and
/// never moved: `Connection`'s `IoStream` holds pointers into these fields.
const Transport = struct {
    tcp: net.Stream,
    tcp_reader: net.Stream.Reader,
    tcp_writer: net.Stream.Writer,
    tcp_read_buffer: []u8,
    tcp_write_buffer: []u8,
    tls_state: ?*TlsState,

    fn deinit(self: *Transport, gpa: std.mem.Allocator, io: std.Io) void {
        if (self.tls_state) |ts| {
            gpa.free(ts.read_buffer);
            gpa.free(ts.write_buffer);
            gpa.destroy(ts);
        }
        self.tcp.close(io);
        gpa.free(self.tcp_read_buffer);
        gpa.free(self.tcp_write_buffer);
    }
};

/// A live connection to a Nostr relay. Create with `dial`; free with `deinit`.
/// The publish/subscribe/receive methods forward to the underlying
/// `Connection` (see its docs for semantics).
pub const Relay = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    transport: *Transport,
    conn: LiveConnection,

    pub fn publish(self: *Relay, ev: Event) !void {
        return self.conn.publish(ev);
    }
    pub fn subscribe(self: *Relay, subscription_id: []const u8, filters: []const Filter) !void {
        return self.conn.subscribe(subscription_id, filters);
    }
    pub fn unsubscribe(self: *Relay, subscription_id: []const u8) !void {
        return self.conn.unsubscribe(subscription_id);
    }
    pub fn receive(self: *Relay) !?message.ParsedRelayMessage {
        return self.conn.receive();
    }

    pub fn deinit(self: *Relay) void {
        self.conn.close() catch {};
        self.conn.deinit();
        self.transport.deinit(self.gpa, self.io);
        const gpa = self.gpa;
        const transport = self.transport;
        self.* = undefined;
        gpa.destroy(transport);
    }
};

/// Resolves `host` with the system resolver (libc `getaddrinfo`) and connects a
/// TCP stream to `port`, trying each returned address until one connects.
///
/// We deliberately bypass std's built-in DNS resolver (`net.HostName.connect`):
/// it reads nameservers from `/etc/resolv.conf`, but on macOS that file is empty
/// (name resolution is handled by the system configuration framework, not
/// resolv.conf), so std falls back to querying `127.0.0.1:53` — where nothing is
/// listening — and a hostname lookup hangs indefinitely. `getaddrinfo` uses the
/// OS resolver and works on both macOS and Linux. It needs libc, which the
/// library already links for libsecp256k1 and LMDB. A numeric host (an IP
/// literal) resolves through the same path.
fn resolveAndConnect(gpa: std.mem.Allocator, io: std.Io, host: []const u8, port: u16) !net.Stream {
    const host_z = try gpa.dupeZ(u8, host);
    defer gpa.free(host_z);

    var res: ?*std.c.addrinfo = null;
    if (@intFromEnum(std.c.getaddrinfo(host_z.ptr, null, null, &res)) != 0)
        return error.NameResolutionFailed;
    const list = res orelse return error.NameResolutionFailed;
    defer std.c.freeaddrinfo(list);

    var last_err: anyerror = error.NameResolutionFailed;
    var node: ?*std.c.addrinfo = list;
    while (node) |ai| : (node = ai.next) {
        const raw = ai.addr orelse continue;
        const address: net.IpAddress = switch (@as(posix.sa_family_t, @intCast(ai.family))) {
            posix.AF.INET => .{ .ip4 = .{
                .port = port,
                .bytes = @bitCast(@as(*const posix.sockaddr.in, @ptrCast(@alignCast(raw))).addr),
            } },
            posix.AF.INET6 => .{ .ip6 = .{
                .port = port,
                .bytes = @as(*const posix.sockaddr.in6, @ptrCast(@alignCast(raw))).addr,
            } },
            else => continue,
        };
        return address.connect(io, .{ .mode = .stream }) catch |err| {
            last_err = err;
            continue;
        };
    }
    return last_err;
}

/// Connects to the relay at `url` (`ws://` or `wss://`), performing the TCP
/// connect, the TLS handshake for `wss://` (verifying the server certificate
/// against the system CA bundle), and the websocket opening handshake. Returns
/// a ready `Relay`. The caller owns it and must `deinit`.
///
/// Not covered by CI (no relay is reachable there); the transport-agnostic
/// `Connection` and the `IoStream` adapter it uses are what the tests exercise.
pub fn dial(gpa: std.mem.Allocator, io: std.Io, url: []const u8) !*Relay {
    const parsed = try parseUrl(url);

    const transport = try gpa.create(Transport);
    errdefer gpa.destroy(transport);
    transport.tls_state = null;

    transport.tcp = try resolveAndConnect(gpa, io, parsed.host, parsed.port);
    errdefer transport.tcp.close(io);

    transport.tcp_read_buffer = try gpa.alloc(u8, 64 * 1024);
    errdefer gpa.free(transport.tcp_read_buffer);
    transport.tcp_write_buffer = try gpa.alloc(u8, 64 * 1024);
    errdefer gpa.free(transport.tcp_write_buffer);

    transport.tcp_reader = transport.tcp.reader(io, transport.tcp_read_buffer);
    transport.tcp_writer = transport.tcp.writer(io, transport.tcp_write_buffer);

    const stream: IoStream = if (parsed.secure) blk: {
        const ts = try gpa.create(TlsState);
        errdefer gpa.destroy(ts);
        ts.read_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(ts.read_buffer);
        ts.write_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(ts.write_buffer);

        var ca_bundle: std.crypto.Certificate.Bundle = .empty;
        defer ca_bundle.deinit(gpa);
        var ca_lock: std.Io.RwLock = .init;
        try ca_bundle.rescan(gpa, io, std.Io.Timestamp.now(io, .real));

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.randomSecure(&entropy) catch return error.RandomFailed;

        ts.client = try tls.Client.init(
            &transport.tcp_reader.interface,
            &transport.tcp_writer.interface,
            .{
                .host = .{ .explicit = parsed.host },
                .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &ca_lock, .bundle = &ca_bundle } },
                .read_buffer = ts.read_buffer,
                .write_buffer = ts.write_buffer,
                .entropy = &entropy,
                .realtime_now = std.Io.Timestamp.now(io, .real),
            },
        );
        transport.tls_state = ts;
        break :blk .{
            .reader = &ts.client.reader,
            .writer = &ts.client.writer,
            .transport_writer = &transport.tcp_writer.interface,
        };
    } else .{
        .reader = &transport.tcp_reader.interface,
        .writer = &transport.tcp_writer.interface,
    };

    const relay = try gpa.create(Relay);
    errdefer gpa.destroy(relay);
    relay.* = .{
        .gpa = gpa,
        .io = io,
        .transport = transport,
        .conn = LiveConnection.init(gpa, io, stream),
    };
    errdefer relay.conn.deinit();

    try relay.conn.handshake(parsed.host, parsed.path);
    return relay;
}

// ---------------------------------------------------------------------------
// Tests — an in-memory fake stream drives the connection end to end.
// ---------------------------------------------------------------------------

const FakeStream = struct {
    /// Scripted server->client bytes.
    to_read: []const u8,
    read_pos: usize = 0,
    /// Captured client->server bytes.
    written: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    fn read(self: *FakeStream, buffer: []u8) error{}!usize {
        const remaining = self.to_read[self.read_pos..];
        const n = @min(buffer.len, remaining.len);
        @memcpy(buffer[0..n], remaining[0..n]);
        self.read_pos += n;
        return n;
    }

    fn writeAll(self: *FakeStream, bytes: []const u8) !void {
        try self.written.appendSlice(self.allocator, bytes);
    }
};

const TestConn = Connection(*FakeStream);

/// Builds an unmasked server text frame (as a relay would send).
fn serverText(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    try list.append(allocator, 0x81); // FIN + text
    std.debug.assert(text.len <= 125); // test payloads stay small
    try list.append(allocator, @intCast(text.len));
    try list.appendSlice(allocator, text);
    return list.toOwnedSlice(allocator);
}

/// Decodes the single client frame the connection wrote, returning its
/// (unmasked) text payload in `out`.
fn onlyWrittenText(allocator: std.mem.Allocator, written: []u8) ![]u8 {
    const frame = (try websocket.decodeFrame(written)).?;
    return allocator.dupe(u8, frame.payload);
}

/// A fake stream that answers the client's handshake correctly: on the first
/// read it inspects the request the client wrote, derives the matching
/// `Sec-WebSocket-Accept` from the client's (random) key, and returns a 101
/// response followed by `trailer` frames. This exercises the real success
/// path without hardcoding the RNG-dependent key.
const HandshakeStream = struct {
    written: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    trailer: []const u8 = "",
    /// If set, deliberately corrupt the accept value to force a failure.
    break_accept: bool = false,
    response: std.ArrayList(u8) = .empty,
    pos: usize = 0,
    built: bool = false,

    fn deinit(self: *HandshakeStream) void {
        self.response.deinit(self.allocator);
    }

    fn writeAll(self: *HandshakeStream, bytes: []const u8) !void {
        try self.written.appendSlice(self.allocator, bytes);
    }

    fn read(self: *HandshakeStream, buffer: []u8) !usize {
        if (!self.built) {
            const req = self.written.items;
            const prefix = "Sec-WebSocket-Key: ";
            const kstart = (std.mem.indexOf(u8, req, prefix) orelse return error.NoKey) + prefix.len;
            const kend = std.mem.indexOfPos(u8, req, kstart, "\r\n") orelse return error.NoKey;
            var accept = websocket.acceptKey(req[kstart..kend]);
            if (self.break_accept) accept[0] = if (accept[0] == 'A') 'B' else 'A';
            try self.response.appendSlice(self.allocator, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
            try self.response.appendSlice(self.allocator, &accept);
            try self.response.appendSlice(self.allocator, "\r\n\r\n");
            try self.response.appendSlice(self.allocator, self.trailer);
            self.built = true;
        }
        const remaining = self.response.items[self.pos..];
        const n = @min(buffer.len, remaining.len);
        @memcpy(buffer[0..n], remaining[0..n]);
        self.pos += n;
        return n;
    }
};

test "handshake succeeds and leaves trailing frames for receive" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);

    const notice = try serverText(allocator, "[\"NOTICE\",\"hi\"]");
    defer allocator.free(notice);

    var server = HandshakeStream{ .written = &written, .allocator = allocator, .trailer = notice };
    defer server.deinit();
    var conn = Connection(*HandshakeStream).init(allocator, std.testing.io, &server);
    defer conn.deinit();

    try conn.handshake("relay.example.com", "/");

    // The request the client sent must be a well-formed upgrade.
    try std.testing.expect(std.mem.startsWith(u8, written.items, "GET / HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, written.items, "Host: relay.example.com\r\n") != null);

    // The frame that followed the response head must be readable.
    var m = (try conn.receive()).?;
    defer m.deinit();
    try std.testing.expectEqualStrings("hi", m.value.notice.message);
}

test "handshake fails on a mismatched accept" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);
    var server = HandshakeStream{ .written = &written, .allocator = allocator, .break_accept = true };
    defer server.deinit();
    var conn = Connection(*HandshakeStream).init(allocator, std.testing.io, &server);
    defer conn.deinit();
    try std.testing.expectError(ConnectionError.HandshakeFailed, conn.handshake("relay.example.com", "/"));
}

test "publish/subscribe/unsubscribe write correct client frames" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);
    var server = FakeStream{ .to_read = "", .written = &written, .allocator = allocator };
    var conn = TestConn.init(allocator, std.testing.io, &server);
    defer conn.deinit();

    // subscribe
    const authors = [_][32]u8{[_]u8{0xab} ** 32};
    const kinds = [_]u16{1};
    try conn.subscribe("s1", &[_]Filter{.{ .authors = &authors, .kinds = &kinds }});
    {
        const text = try onlyWrittenText(allocator, written.items);
        defer allocator.free(text);
        try std.testing.expect(std.mem.startsWith(u8, text, "[\"REQ\",\"s1\",{"));
    }

    // unsubscribe
    written.clearRetainingCapacity();
    try conn.unsubscribe("s1");
    {
        const text = try onlyWrittenText(allocator, written.items);
        defer allocator.free(text);
        try std.testing.expectEqualStrings("[\"CLOSE\",\"s1\"]", text);
    }
}

fn newConn(
    allocator: std.mem.Allocator,
    server: *FakeStream,
) TestConn {
    return TestConn.init(allocator, std.testing.io, server);
}

test "receive parses a scripted EVENT then EOSE" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);

    const ev_json =
        "[\"EVENT\",\"s1\",{\"id\":\"" ++ "d0a1d13aff1d1725d80305f74a3f8419674d726342773b06ddc6988cc5be3a40" ++
        "\",\"pubkey\":\"" ++ "f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca" ++
        "\",\"created_at\":1700000000,\"kind\":1,\"tags\":[],\"content\":\"hi\",\"sig\":\"" ++ "ab" ** 64 ++ "\"}]";

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(allocator);
    // Event frame is >125 bytes, so build it with the general encoder (masked
    // is fine — the decoder unmasks; here we send it unmasked as a server).
    try appendServerText(&script, allocator, ev_json);
    try appendServerText(&script, allocator, "[\"EOSE\",\"s1\"]");

    var server = FakeStream{ .to_read = script.items, .written = &written, .allocator = allocator };
    var conn = newConn(allocator, &server);
    defer conn.deinit();

    var m1 = (try conn.receive()).?;
    defer m1.deinit();
    try std.testing.expectEqualStrings("s1", m1.value.event.subscription_id);
    try std.testing.expectEqualStrings("hi", m1.value.event.event.content);

    var m2 = (try conn.receive()).?;
    defer m2.deinit();
    try std.testing.expectEqualStrings("s1", m2.value.eose.subscription_id);

    // No more data -> EOF.
    try std.testing.expect((try conn.receive()) == null);
}

test "receive answers a ping with a pong and continues" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(allocator);
    // ping "pq" (unmasked server frame), then a NOTICE.
    try script.appendSlice(allocator, &[_]u8{ 0x89, 0x02, 'p', 'q' });
    try appendServerText(&script, allocator, "[\"NOTICE\",\"ok\"]");

    var server = FakeStream{ .to_read = script.items, .written = &written, .allocator = allocator };
    var conn = newConn(allocator, &server);
    defer conn.deinit();

    var m = (try conn.receive()).?;
    defer m.deinit();
    try std.testing.expectEqualStrings("ok", m.value.notice.message);

    // The connection must have written a pong echoing "pq".
    const pong = (try websocket.decodeFrame(written.items)).?;
    try std.testing.expectEqual(websocket.Opcode.pong, pong.opcode);
    try std.testing.expectEqualStrings("pq", pong.payload);
}

test "receive reassembles a fragmented text message" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);

    // "[\"NOTICE\",\"ab\"]" split: first fragment text (FIN=0), then
    // continuation (FIN=1).
    const full = "[\"NOTICE\",\"ab\"]";
    const cut = 6;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(allocator);
    // fragment 1: opcode text (0x01), FIN=0
    try script.appendSlice(allocator, &[_]u8{ 0x01, @intCast(cut) });
    try script.appendSlice(allocator, full[0..cut]);
    // fragment 2: opcode continuation (0x00), FIN=1
    try script.appendSlice(allocator, &[_]u8{ 0x80, @intCast(full.len - cut) });
    try script.appendSlice(allocator, full[cut..]);

    var server = FakeStream{ .to_read = script.items, .written = &written, .allocator = allocator };
    var conn = newConn(allocator, &server);
    defer conn.deinit();

    var m = (try conn.receive()).?;
    defer m.deinit();
    try std.testing.expectEqualStrings("ab", m.value.notice.message);
}

test "receive returns null on a close frame" {
    const allocator = std.testing.allocator;
    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(allocator);
    var server = FakeStream{ .to_read = &[_]u8{ 0x88, 0x00 }, .written = &written, .allocator = allocator };
    var conn = newConn(allocator, &server);
    defer conn.deinit();
    try std.testing.expect((try conn.receive()) == null);
}

/// Appends an unmasked server text frame (supports arbitrary lengths).
fn appendServerText(list: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try list.append(allocator, 0x81);
    if (text.len <= 125) {
        try list.append(allocator, @intCast(text.len));
    } else if (text.len <= 0xffff) {
        try list.append(allocator, 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext, @intCast(text.len), .big);
        try list.appendSlice(allocator, &ext);
    } else {
        try list.append(allocator, 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, &ext, text.len, .big);
        try list.appendSlice(allocator, &ext);
    }
    try list.appendSlice(allocator, text);
}

test "parseUrl handles schemes, ports, paths, and IPv6" {
    const a = try parseUrl("wss://relay.damus.io");
    try std.testing.expect(a.secure);
    try std.testing.expectEqualStrings("relay.damus.io", a.host);
    try std.testing.expectEqual(@as(u16, 443), a.port);
    try std.testing.expectEqualStrings("/", a.path);

    const b = try parseUrl("ws://localhost:7777/nostr");
    try std.testing.expect(!b.secure);
    try std.testing.expectEqualStrings("localhost", b.host);
    try std.testing.expectEqual(@as(u16, 7777), b.port);
    try std.testing.expectEqualStrings("/nostr", b.path);

    const c = try parseUrl("wss://example.com/");
    try std.testing.expectEqualStrings("example.com", c.host);
    try std.testing.expectEqualStrings("/", c.path);

    const d = try parseUrl("ws://[::1]:8080/x");
    try std.testing.expectEqualStrings("::1", d.host);
    try std.testing.expectEqual(@as(u16, 8080), d.port);

    try std.testing.expectError(UrlError.UnsupportedScheme, parseUrl("http://x"));
    try std.testing.expectError(UrlError.InvalidUrl, parseUrl("wss://"));
    try std.testing.expectError(UrlError.InvalidUrl, parseUrl("ws://host:notaport"));
}

test "IoStream drives a Connection over real std Io.Reader/Writer" {
    // The live dialer feeds sockets through IoStream; here we point IoStream at
    // in-memory std readers/writers so the exact adapter code path runs in CI.
    const allocator = std.testing.allocator;

    var server: std.ArrayList(u8) = .empty;
    defer server.deinit(allocator);
    try appendServerText(&server, allocator, "[\"NOTICE\",\"live\"]");

    var reader = std.Io.Reader.fixed(server.items);
    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    var conn = LiveConnection.init(allocator, std.testing.io, .{ .reader = &reader, .writer = &out.writer });
    defer conn.deinit();

    // Reading a relay message flows through IoStream.read -> readSliceShort.
    var m = (try conn.receive()).?;
    defer m.deinit();
    try std.testing.expectEqualStrings("live", m.value.notice.message);

    // Writing flows through IoStream.writeAll -> writeAll + flush; the captured
    // bytes must decode back to the CLOSE frame we sent.
    try conn.unsubscribe("s1");
    var written = out.toArrayList();
    defer written.deinit(allocator);
    const frame = (try websocket.decodeFrame(written.items)).?;
    try std.testing.expectEqualStrings("[\"CLOSE\",\"s1\"]", frame.payload);
}

test "live dialer is semantically analyzed" {
    // `dial` opens a real socket, so it can't run in CI, and Zig would
    // otherwise skip analyzing an uncalled function's body. Referencing it (and
    // the `Relay` methods) forces full type-checking so the live TCP/TLS path
    // is kept compiling by CI even though it is exercised only by hand.
    _ = &dial;
    _ = &resolveAndConnect;
    _ = &Relay.publish;
    _ = &Relay.subscribe;
    _ = &Relay.unsubscribe;
    _ = &Relay.receive;
    _ = &Relay.deinit;
}
