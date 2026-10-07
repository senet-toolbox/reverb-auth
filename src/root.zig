//! OAuth and session handling for Reverb.
//!
//! Split out of reverb itself: an HTTP server does not need to carry an
//! identity provider. The dependency runs one way -- this package imports
//! reverb for `Context`, `Cookie` and the request helpers, and reverb knows
//! nothing about it.

pub const KeyStone = @import("KeyStone.zig");
pub const Google = @import("Google.zig");
pub const Github = @import("Github.zig");
pub const QueryBuilder = @import("QueryBuilder.zig");

/// JSON Web Tokens. Moved here with the rest of the auth stack, since
/// nothing else in reverb used it.
pub const JWT = @import("JWT.zig");
pub const Algorithm = @import("jwt_types.zig").Algorithm;
pub const Validation = @import("jwt_types.zig").Validation;
pub const Header = @import("jwt_types.zig").Header;
