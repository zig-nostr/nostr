//! When a relay connection has gone quiet, and what to do about it.
//!
//! A relay that goes away without closing leaves the thread reading it blocked
//! forever: no error, no timeout, no reconnect. Nothing inside that thread can
//! notice, which is the whole difficulty, because a thread waiting on a dead
//! peer is the last thing able to tell that it is waiting. Somebody else has to
//! watch the clock and act.
//!
//! This module is that somebody's policy and nothing else. It is a pure
//! function over two measurements, so it can be asserted without a socket, a
//! thread or a clock, and every product that keeps relay connections can hold
//! the same numbers instead of picking its own.
//!
//! The numbers are Amethyst's, from their survey of 122 relays: idle timeouts
//! cluster around 60, 120, 240, 300 and 600 seconds, and a ping only reliably
//! holds a connection open when its interval is at most about half the shortest
//! tier. Ninety seconds is three missed answers.
//!
//! **Answering the relay's pings is not a substitute for sending our own.** A
//! relay's idle timer counts what it RECEIVES from us, so the pong the library
//! sends in reply to its ping does not reset it. Amethyst measured exactly that
//! against a live relay, and `Connection.idleMs` is written to match: a pong we
//! send counts for nothing, an inbound byte counts.
//!
//! **Giving up is `Relay.shutdown`, never a socket receive timeout.**
//! `SO_RCVTIMEO` makes the read return EAGAIN, and this io model treats EAGAIN
//! as a programmer bug and panics in Debug. `shutdown` is a syscall on the
//! descriptor and is safe to call while another thread is blocked reading it.
//! Where the reader wants to come up for air rather than be torn down, the
//! answer is `Relay.receiveTimeout`, which consumes nothing.
//!
//! The table of live connections, the thread that ticks, and what a product
//! does when a relay is given up on are all product concerns and stay where
//! they are. Only the policy is shared.

const std = @import("std");

/// Silence after which the watcher asks the relay whether it is still there.
pub const ping_after_ms: i64 = 30_000;
/// Silence after which it stops asking and cuts the connection.
pub const dead_after_ms: i64 = 90_000;
/// How often to look. Short enough that ninety seconds means ninety, long
/// enough to cost nothing.
pub const tick_ms: u64 = 5_000;

/// What to do about one connection.
pub const Action = enum { leave_it, ping, give_up };

/// The policy, given how long a connection has been silent and how long since
/// it was last pinged. Both null mean "no measurement"; `Connection.idleMs`
/// returns exactly that shape.
pub fn action(idle_ms: ?i64, since_ping_ms: ?i64) Action {
    // Nothing has ever arrived on this connection. That is the window between
    // the handshake and the relay's first word, not a stall, and reading a
    // missing measurement as an infinite one would cut off every relay that
    // took a moment to answer.
    const idle = idle_ms orelse return .leave_it;
    if (idle >= dead_after_ms) return .give_up;
    if (idle < ping_after_ms) return .leave_it;
    // Silent past the interval. Ping, but only once per interval: at a five
    // second tick a socket that has stopped answering would otherwise collect a
    // dozen more pings on its way to being declared dead.
    const since = since_ping_ms orelse return .ping;
    return if (since >= ping_after_ms) .ping else .leave_it;
}

test "a connection that has never spoken is not a stalled one" {
    // The window between the handshake and the relay's first word. Reading a
    // missing measurement as an infinite one would cut off every relay that
    // took a moment to answer, which on a slow network is all of them.
    try std.testing.expectEqual(Action.leave_it, action(null, null));
    try std.testing.expectEqual(Action.leave_it, action(null, 999_999));
}

test "a talking relay is left alone" {
    try std.testing.expectEqual(Action.leave_it, action(0, null));
    try std.testing.expectEqual(Action.leave_it, action(ping_after_ms - 1, null));
}

test "a relay that has gone quiet is asked whether it is still there" {
    try std.testing.expectEqual(Action.ping, action(ping_after_ms, null));
}

test "a quiet relay is asked once per interval, not once per look" {
    const idle = ping_after_ms + 5_000;
    try std.testing.expectEqual(Action.leave_it, action(idle, 5_000));
    try std.testing.expectEqual(Action.ping, action(idle, ping_after_ms));
}

test "a relay that answers none of three pings is given up on" {
    try std.testing.expectEqual(Action.give_up, action(dead_after_ms, 0));
    // The deadline wins over the ping interval: a socket this far gone is not
    // asked again, it is closed.
    try std.testing.expectEqual(Action.give_up, action(dead_after_ms + 60_000, dead_after_ms));
}

test "the deadline is a multiple of the interval, so silence is answered before it is fatal" {
    // Not decoration. If the deadline were under the interval a relay would be
    // declared dead without ever having been asked anything, and every quiet
    // connection would be recycled on a timer.
    try std.testing.expect(dead_after_ms >= ping_after_ms * 2);
}

test "a look happens several times inside the interval it enforces" {
    // The tick is the resolution of every number above. If it were coarser than
    // the ping interval, "ping after thirty seconds" would mean whenever the
    // next look happened to land, and the deadline would overshoot by a whole
    // tick.
    try std.testing.expect(@as(i64, @intCast(tick_ms)) * 2 <= ping_after_ms);
}
