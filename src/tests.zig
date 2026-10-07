//! Test root.
//!
//! `refAllDecls` forces every declaration to be analysed. Zig only checks
//! what is reachable, and none of this code had ever been compiled while it
//! lived in reverb -- it was not referenced from any build root there.

const std = @import("std");

test {
    std.testing.refAllDecls(@import("root.zig"));
    std.testing.refAllDecls(@import("KeyStone.zig"));
    std.testing.refAllDecls(@import("Google.zig"));
    std.testing.refAllDecls(@import("Github.zig"));
    std.testing.refAllDecls(@import("QueryBuilder.zig"));
    std.testing.refAllDecls(@import("JWT.zig"));
    std.testing.refAllDecls(@import("jwt_types.zig"));
}

test {
    // The JWT tests written while this lived in reverb.
    _ = @import("JWT.zig");
}
