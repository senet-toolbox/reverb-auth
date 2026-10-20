const std = @import("std");
const QueryBuilder = @import("QueryBuilder.zig");
const http = std.http;
const json = std.json;
const Client = http.Client;

pub const Options = struct {
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8 = "http://localhost:5173",
    grant_type: []const u8 = "authorization_code",
    /// Where codes and refresh tokens are exchanged. Tests point it at a
    /// fake.
    token_url: []const u8 = "https://oauth2.googleapis.com/token",
    userinfo_url: []const u8 = "https://openidconnect.googleapis.com/v1/userinfo",
};

pub const GoogleUserInfo = struct {
    sub: []const u8,
    name: []const u8,
    given_name: []const u8,
    family_name: []const u8,
    picture: []const u8,
    email: []const u8,
    email_verified: bool,
};

/// Calls Google's OAuth endpoints. Holds only its options, so one provider
/// may be used from several threads at once.
pub const Provider = struct {
    const Self = @This();
    options: Options,

    pub fn init(target: *Provider, options: Options) void {
        target.* = .{ .options = options };
    }

    /// Exchanges an authorization code for tokens. Returns Google's JSON
    /// body, owned by the caller (`parseResp(TokenResp, ...)` reads it).
    pub fn tokenExchange(google_prov: *const Self, gpa: std.mem.Allocator, auth_code: []const u8) ![]u8 {
        const o = google_prov.options;
        return postForm(gpa, o.token_url, &.{
            .{ "code", auth_code },
            .{ "client_id", o.client_id },
            .{ "client_secret", o.client_secret },
            .{ "redirect_uri", o.redirect_uri },
            .{ "grant_type", o.grant_type },
        });
    }

    /// Exchanges a refresh token for a new access token (and id token).
    /// Returns Google's JSON body, owned by the caller.
    pub fn refreshToken(google_prov: *const Self, gpa: std.mem.Allocator, refresh_token: []const u8) ![]u8 {
        const o = google_prov.options;
        return postForm(gpa, o.token_url, &.{
            .{ "client_id", o.client_id },
            .{ "client_secret", o.client_secret },
            .{ "refresh_token", refresh_token },
            .{ "grant_type", "refresh_token" },
        });
    }

    /// The signed-in user's profile. Returns Google's JSON body, owned by
    /// the caller.
    pub fn getUserInfo(google_prov: *const Self, gpa: std.mem.Allocator, access_token: []const u8) ![]u8 {
        const authorization = try std.fmt.allocPrint(gpa, "Bearer {s}", .{access_token});
        defer gpa.free(authorization);

        var threaded: std.Io.Threaded = .init_single_threaded;
        var client = Client{ .allocator = gpa, .io = threaded.io(), .write_buffer_size = 8192 };
        defer client.deinit();

        var body: std.Io.Writer.Allocating = .init(gpa);
        errdefer body.deinit();
        const resp = try client.fetch(.{
            .method = .GET,
            .headers = .{ .authorization = .{ .override = authorization } },
            .location = .{ .url = google_prov.options.userinfo_url },
            .response_writer = &body.writer,
        });
        if (resp.status != .ok) {
            std.log.warn("google userinfo: {d} {s}", .{ @intFromEnum(resp.status), body.written() });
            return error.WrongStatusResponse;
        }
        return body.toOwnedSlice();
    }
};

/// POSTs `fields` form-encoded to `url` and returns the response body,
/// owned by the caller.
///
/// A refusal is logged with Google's answer (`invalid_grant` and the like),
/// never with the request: that carries the client secret and the code.
fn postForm(gpa: std.mem.Allocator, url: []const u8, fields: []const [2][]const u8) ![]u8 {
    var form: QueryBuilder = undefined;
    try form.init(gpa);
    defer form.deinit();
    for (fields) |field| try form.add(field[0], field[1]);
    try form.queryStrEncode();

    var threaded: std.Io.Threaded = .init_single_threaded;
    var client = Client{ .allocator = gpa, .io = threaded.io(), .write_buffer_size = 8192 };
    defer client.deinit();

    var body: std.Io.Writer.Allocating = .init(gpa);
    errdefer body.deinit();
    const resp = try client.fetch(.{
        .method = .POST,
        .headers = .{ .content_type = .{ .override = "application/x-www-form-urlencoded" } },
        .location = .{ .url = url },
        .payload = form.str,
        .response_writer = &body.writer,
    });
    if (resp.status != .ok) {
        std.log.warn("google token endpoint: {d} {s}", .{ @intFromEnum(resp.status), body.written() });
        return error.WrongStatusResponse;
    }
    return body.toOwnedSlice();
}

pub const TokenResp = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: i64,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    id_token: ?[]const u8 = null,
};

pub const RefreshTokenResp = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: i64,
    scope: ?[]const u8 = null,
    id_token: ?[]const u8 = null,
};

/// Parses one of Google's JSON answers. The strings point into memory from
/// `arena`, which should be a request arena: nothing here frees them.
/// Fields Google adds over time are ignored.
pub fn parseResp(comptime T: type, body: []const u8, arena: std.mem.Allocator) !T {
    return json.parseFromSliceLeaky(T, arena, body, .{ .ignore_unknown_fields = true }) catch
        error.MalformedJson;
}

test "parseResp keeps strings alive and ignores fields it does not know" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const resp = try parseResp(TokenResp,
        \\{"access_token":"ya29.a","expires_in":3599,"token_type":"Bearer",
        \\ "refresh_token_expires_in":604799,"id_token":"x.y.z"}
    , arena.allocator());
    try std.testing.expectEqualStrings("ya29.a", resp.access_token);
    try std.testing.expectEqualStrings("x.y.z", resp.id_token.?);
    try std.testing.expectEqual(@as(?[]const u8, null), resp.refresh_token);
}
