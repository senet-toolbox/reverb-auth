const std = @import("std");
pub const Google = @import("Google.zig");
pub const Github = @import("Github.zig");
const Context = @import("reverb").Context;
const Cookie = @import("reverb").Cookie;
const Reply = @import("reverb").Reply;
const Workers = @import("reverb").Workers;
const QueryBuilder = @import("QueryBuilder.zig");
const JWT = @import("JWT.zig");
const JWTRoot = @import("jwt_types.zig");
// Reverb re-exports loom's Time, so auth needs only the one dependency.
const Time = @import("reverb").Time;

pub const Secrets = struct {
    github: ?[]const u8 = null,
    google: ?[]const u8 = null,
    apple: ?[]const u8 = null,
    azure: ?[]const u8 = null,
};

pub const ClientIds = struct {
    github: ?[]const u8 = null,
    google: ?[]const u8 = null,
    apple: ?[]const u8 = null,
    azure: ?[]const u8 = null,
};

pub const Config = struct {
    pub const Providers = struct {
        google: ?Google.Options = null,
        github: ?Github.Options = null,
    };

    // New preferred API
    providers: Providers = .{},
    // Legacy API (still supported)
    client_ids: ClientIds = .{},
    secrets: Secrets = .{},
    google_config: ?Google.Options = null,
    github_config: ?Github.Options = null,
    session_secret: ?[]const u8 = null,
    session_ttl_seconds: i64 = 60 * 60 * 24 * 7,
    session_cookie_name: []const u8 = "keystone_session_token",
    refresh_cookie_name: []const u8 = "keystone_refresh_token",
    oauth_state_cookie_name: []const u8 = "keystone_oauth_state",
    oauth_nonce_cookie_name: []const u8 = "keystone_oauth_nonce",
    secure_cookies: bool = false,
    http_only_cookies: bool = true,
    same_site: ?Cookie.SameSite = .lax,
    on_sign_in: ?SignInHook = null,
};

/// Called on a sign-in worker thread after a provider vouched for a user,
/// at sign-in and at each refresh, so it must be threadsafe. Returns the id the session is issued for,
/// usually the app's own user id, allocated from `allocator` (the request's
/// memory). An error refuses the sign-in.
pub const SignInHook = *const fn (allocator: std.mem.Allocator, user: SignedIn) anyerror![]const u8;

/// A user as the provider describes them.
pub const SignedIn = struct {
    provider: OauthProvider,
    /// The provider's id for the user (Google's `sub`). Stable; an email
    /// address can change hands.
    subject: []const u8,
    email: []const u8,
    email_verified: bool,
    name: ?[]const u8 = null,
    picture: ?[]const u8 = null,
};

pub const ClientConfig = struct {
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: ?[]const u8 = null,
    grant_type: ?[]const u8 = null,
    state: ?[]const u8 = null,
    /// Overrides the provider's token endpoint; for tests.
    token_url: ?[]const u8 = null,
};

pub const Clients = struct {
    google: ?ClientConfig = null,
    github: ?ClientConfig = null,
};

pub const InitConfig = struct {
    clients: Clients,
    hook_path: []const u8 = "/auth/callback",
    backend_url: []const u8 = "http://localhost:8080",
    origin: []const u8 = "http://localhost:5173",
    session_secret: ?[]const u8 = null,
    session_ttl_seconds: i64 = 60 * 60 * 24 * 7,
    session_cookie_name: []const u8 = "keystone_session_token",
    refresh_cookie_name: []const u8 = "keystone_refresh_token",
    oauth_state_cookie_name: []const u8 = "keystone_oauth_state",
    oauth_nonce_cookie_name: []const u8 = "keystone_oauth_nonce",
    secure_cookies: bool = false,
    http_only_cookies: bool = true,
    /// For the session and refresh cookies. `lax` suits a frontend on the
    /// same site as this server (app.example.com and api.example.com);
    /// one on another site needs `none`, which browsers honour only with
    /// `secure_cookies`.
    same_site: ?Cookie.SameSite = .lax,
    on_sign_in: ?SignInHook = null,
    /// Sign-ins and refreshes wait on Google, so they run on these.
    sign_in_threads: usize = 2,
    /// Sign-ins that may wait for a thread; past this they answer 503.
    sign_in_queue: usize = 16,
};

const KeyStone = @This();
pub var keystone_config: Config = undefined;
pub var api_config: InitConfig = .{ .clients = .{} };
var google_options: Google.Options = undefined;
var google_provider: Google.Provider = undefined;
var github_options: Github.Options = undefined;
var github_provider: Github.Provider = undefined;
var google_initialized = false;
var github_initialized = false;

pub fn init(config: Config, allocator: std.mem.Allocator) !void {
    keystone_config = config;
    google_initialized = false;
    github_initialized = false;

    if (keystone_config.providers.google) |provider_google| {
        google_options = provider_google;
        google_provider.init(google_options);
        google_initialized = true;
    } else if (keystone_config.google_config) |legacy_google_options| {
        google_options = legacy_google_options;
        google_provider.init(google_options);
        google_initialized = true;
    } else if (keystone_config.client_ids.google != null and keystone_config.secrets.google != null) {
        const client_id = keystone_config.client_ids.google orelse return error.ClientIdNull;
        const secret = keystone_config.secrets.google orelse return error.ClientSecretNull;
        google_options = Google.Options{
            .client_id = client_id,
            .client_secret = secret,
            .redirect_uri = "http://localhost:5173/auth/callback",
            .grant_type = "authorization_code",
        };
        google_provider.init(google_options);
        google_initialized = true;
    }

    if (keystone_config.providers.github) |provider_github| {
        github_options = provider_github;
        try github_provider.init(github_options, allocator);
        github_initialized = true;
    } else if (keystone_config.github_config) |legacy_github_options| {
        github_options = legacy_github_options;
        try github_provider.init(github_options, allocator);
        github_initialized = true;
    } else if (keystone_config.client_ids.github != null and keystone_config.secrets.github != null) {
        const client_id = keystone_config.client_ids.github orelse return error.ClientIdNull;
        const secret = keystone_config.secrets.github orelse return error.ClientSecretNull;
        github_options = Github.Options{
            .client_id = client_id,
            .client_secret = secret,
            .redirect_uri = "http://localhost:5173/nightwatch/auth",
        };
        try github_provider.init(github_options, allocator);
        github_initialized = true;
    }
}

/// Configures the providers, starts the sign-in workers and registers the
/// routes. `gpa` must be threadsafe: sign-ins allocate from it on the
/// workers. Call `deinit` once the server's `listen` has returned and
/// before its `deinit`.
pub fn install(server: anytype, cfg: InitConfig, gpa: std.mem.Allocator, io: std.Io) !void {
    api_config = cfg;
    try init(try buildConfig(cfg, gpa), gpa);
    if (google_initialized) {
        job_allocator = gpa;
        try pool.init(gpa, io, .{ .threads = cfg.sign_in_threads, .queue = cfg.sign_in_queue });
        pool_running = true;
    }
    errdefer deinit();
    try registerRoutes(server);
}

/// Stops the sign-in workers. Sign-ins already queued finish and send
/// their replies first.
pub fn deinit() void {
    if (!pool_running) return;
    pool.deinit();
    pool_running = false;
}

pub fn registerRoutes(server: anytype) !void {
    if (google_initialized) {
        try server.post("/exchange/google/token", routeGoogleExchange, &.{});
        try server.post("/auth/validate/google/session", routeValidateSession, &.{});
    }

    if (github_initialized) {
        try server.post("/exchange/github/token", routeGithubExchange, &.{});
    }

    if (google_initialized or github_initialized) {
        try server.post("/auth/session/bootstrap", routeBootstrapSession, &.{});
        try server.post("/auth/session/refresh", routeRefreshSession, &.{});
        try server.post("/auth/session/signout", routeSignoutSession, &.{});
    }
}

pub const OauthProvider = enum {
    google,
    apple,
    github,
    azure,
};

pub fn refreshToken(provider: OauthProvider, allocator: std.mem.Allocator, refresh_token: []const u8) ![]const u8 {
    switch (provider) {
        .google => {
            if (!google_initialized) return error.ProviderNotConfigured;
            return try google_provider.refreshToken(allocator, refresh_token);
        },
        .github => {
            if (!github_initialized) return error.ProviderNotConfigured;
            return try github_provider.refreshToken(refresh_token);
        },
        else => {},
    }
    return error.InValidProvider;
}

pub fn getUserInfo(provider: OauthProvider, allocator: std.mem.Allocator, access_token: []const u8) ![]const u8 {
    switch (provider) {
        .google => {
            if (!google_initialized) return error.ProviderNotConfigured;
            return try google_provider.getUserInfo(allocator, access_token);
        },
        .github => {
            if (!github_initialized) return error.ProviderNotConfigured;
            return try github_provider.getUserInfo(access_token);
        },
        else => {},
    }
    return error.InValidProvider;
}

pub const AuthState = enum {
    loading,
    signed_out,
    signed_in,
};

pub const AuthUser = struct {
    id: []const u8,
    email: []const u8,
    name: []const u8,
    picture: ?[]const u8 = null,
};

pub const SessionInfo = struct {
    token: []const u8,
    user: AuthUser,
    provider: OauthProvider,
    issued_at: i64,
    expires_at: i64,
};

pub const AuthSessionResponse = struct {
    success: bool,
    state: AuthState,
    session: ?SessionInfo = null,
    err: ?[]const u8 = null,
};

pub const ExchangeSessionResponse = struct {
    success: bool,
    state: AuthState,
    token: []const u8,
    issued_at: i64,
    expires_at: i64,
    user: struct {
        id: []const u8,
        email: []const u8,
        name: []const u8,
        picture: ?[]const u8 = null,
    },
};

// Login with github
// send auth-code
// receive code and exchange for access and refresh token
// store refresh token in db hashed
// set cookie with refresh token
// compare with cookie token on request
pub fn exchangeGithubToken(ctx: *Context) ![]const u8 {
    try ctx.parseForm();
    try validateCallbackPayload(ctx);
    const auth_code = ctx.form_params.get("auth-code").?;

    if (!github_initialized) return error.ProviderNotConfigured;
    const body: []const u8 = github_provider.tokenExchange(auth_code) catch return error.TokenExchangeGithub;

    const map = try QueryBuilder.parseParams(body, &ctx.arena) orelse return error.ParsingParams;
    const access_token = map.get("access_token") orelse return error.GetAccessToken;
    return access_token;

    // const resp: *GithubTokenResp = try parseResp(GithubTokenResp, body, ctx.arena);
}

// Google's id_token claims
pub const GoogleClaims = struct {
    iss: []const u8, // "https://accounts.google.com"
    azp: []const u8,
    aud: []const u8, // your client_id
    sub: []const u8, // unique google user id
    email: []const u8,
    email_verified: bool,
    name: ?[]const u8 = null,
    picture: ?[]const u8 = null,
    given_name: ?[]const u8 = null,
    family_name: ?[]const u8 = null,
    iat: i64,
    exp: i64,
};

/// Reads the id token Google's token endpoint returned.
///
/// Its signature is not checked: the token came straight from Google over
/// TLS, which OpenID Connect accepts instead (Core 1.0, 3.1.3.7, step 6).
/// Who issued it, who it is for and when it expires still are, so a token
/// minted for another app is refused. `error.InvalidIdToken` otherwise.
pub fn handleGoogleCallback(allocator: std.mem.Allocator, google_id_token: []const u8) !JWT.JWT(GoogleClaims) {
    return JWT.decode(
        allocator,
        GoogleClaims,
        google_id_token,
        .{ .secret = "" },
        .{
            .skip_secret = true,
            .required_claims = &.{ .exp, .iss, .aud },
            .iss = &.{ "https://accounts.google.com", "accounts.google.com" },
            .aud = &.{google_options.client_id},
        },
    ) catch |err| {
        std.log.warn("google id token refused: {any}", .{err});
        return error.InvalidIdToken;
    };
}

pub const SessionClaims = struct {
    sub: []const u8,
    email: []const u8,
    name: []const u8,
    exp: i64,
    iat: i64,
};

// ---------------------------------------------------------------------------
// Sign-in and refresh, on worker threads
//
// Both wait on Google for a few hundred milliseconds. Their routes check
// what they can on the loop thread and defer the reply; a worker calls
// Google, runs the app's `on_sign_in`, signs the session and sends the
// reply with its cookies.
// ---------------------------------------------------------------------------

const Job = struct {
    reply: *Reply,
    kind: enum { exchange, refresh },
    /// The authorization code, or the refresh token. Owned by the job.
    grant: []u8,
};

const Pool = Workers(Job, runJob);
var pool: Pool = undefined;
var pool_running = false;
var job_allocator: std.mem.Allocator = undefined;

const json_type = "application/json";

/// What a worker answers.
const Outcome = struct {
    status: u16,
    content_type: []const u8 = json_type,
    body: []const u8,
    cookies: []const Cookie = &.{},
};

fn runJob(job: Job) void {
    defer job_allocator.free(job.grant);
    var arena: std.heap.ArenaAllocator = .init(job_allocator);
    defer arena.deinit();
    const outcome = switch (job.kind) {
        .exchange => signIn(arena.allocator(), job.grant),
        .refresh => refresh(arena.allocator(), job.grant),
    };
    job.reply.sendWithCookies(outcome.status, outcome.content_type, outcome.body, outcome.cookies);
}

fn signIn(arena: std.mem.Allocator, code: []const u8) Outcome {
    const issued = exchangeCode(arena, code) catch |err| return refusal(err);
    const session = issued.session;
    const body = std.json.Stringify.valueAlloc(arena, ExchangeSessionResponse{
        .success = true,
        .state = .signed_in,
        .token = session.token,
        .issued_at = session.issued_at,
        .expires_at = session.expires_at,
        .user = .{
            .id = session.user.id,
            .email = session.user.email,
            .name = session.user.name,
            .picture = session.user.picture,
        },
    }, .{}) catch |err| return refusal(err);
    return .{ .status = 200, .body = body, .cookies = issued.cookies };
}

/// The session for the user behind `code`, and the cookies that carry it.
fn exchangeCode(arena: std.mem.Allocator, code: []const u8) !Issued {
    const body = try google_provider.tokenExchange(arena, code);
    const tokens = try Google.parseResp(Google.TokenResp, body, arena);
    const id_token = tokens.id_token orelse return error.MissingIdToken;
    const google = try handleGoogleCallback(arena, id_token);
    return issueSession(arena, google.claims, tokens.refresh_token, true);
}

fn refresh(arena: std.mem.Allocator, refresh_token: []const u8) Outcome {
    const body = refreshToken(.google, arena, refresh_token) catch |err| switch (err) {
        // Revoked or expired: the user has to sign in again.
        error.WrongStatusResponse => return signedOut(arena, "refresh_rejected"),
        else => return refusal(err),
    };
    const refreshed = Google.parseResp(Google.RefreshTokenResp, body, arena) catch |err| return refusal(err);
    const id_token = refreshed.id_token orelse return signedOut(arena, "refresh_id_token_missing");
    const google = handleGoogleCallback(arena, id_token) catch |err| return refusal(err);
    const issued = issueSession(arena, google.claims, null, false) catch |err| return refusal(err);
    const response: AuthSessionResponse = .{ .success = true, .state = .signed_in, .session = issued.session };
    const json = std.json.Stringify.valueAlloc(arena, response, .{}) catch |err| return refusal(err);
    return .{ .status = 200, .body = json, .cookies = issued.cookies };
}

fn signedOut(arena: std.mem.Allocator, reason: []const u8) Outcome {
    const response: AuthSessionResponse = .{ .success = false, .state = .signed_out, .err = reason };
    const json = std.json.Stringify.valueAlloc(arena, response, .{}) catch |err| return refusal(err);
    return .{ .status = 200, .body = json };
}

/// Refused by Google, or by the checks on what came back: the user can try
/// again. Anything else is the server's problem.
fn refusal(err: anyerror) Outcome {
    const status: u16 = switch (err) {
        error.WrongStatusResponse,
        error.MissingIdToken,
        error.InvalidIdToken,
        => 401,
        else => 500,
    };
    if (status == 401) {
        std.log.warn("google sign-in refused: {any}", .{err});
    } else {
        std.log.err("google sign-in: {any}", .{err});
    }
    return .{ .status = status, .content_type = "text/plain", .body = "Google sign-in failed" };
}

const Issued = struct {
    session: SessionInfo,
    cookies: []const Cookie,
};

/// Issues a session for the user Google vouched for: runs the app's
/// `on_sign_in`, signs the session token, and lists the cookies to set --
/// the session, Google's refresh token when it sent one, and at sign-in
/// the spent OAuth guards, cleared.
fn issueSession(arena: std.mem.Allocator, google: GoogleClaims, refresh_token: ?[]const u8, clear_guards: bool) !Issued {
    const user: SignedIn = .{
        .provider = .google,
        .subject = google.sub,
        .email = google.email,
        .email_verified = google.email_verified,
        .name = google.name,
        .picture = google.picture,
    };
    const user_id = if (keystone_config.on_sign_in) |hook| try hook(arena, user) else user.subject;

    const issued_at = Time.timestamp();
    const expires_at = issued_at + keystone_config.session_ttl_seconds;
    const name = google.name orelse "User";
    const token = try encodeSessionToken(arena, .{
        .sub = user_id,
        .email = google.email,
        .name = name,
        .iat = issued_at,
        .exp = expires_at,
    });

    var cookies: std.ArrayList(Cookie) = .empty;
    try cookies.append(arena, sessionCookie(keystone_config.session_cookie_name, token, keystone_config.session_ttl_seconds));
    if (refresh_token) |value| {
        try cookies.append(arena, sessionCookie(keystone_config.refresh_cookie_name, value, 60 * 60 * 24 * 30));
    }
    if (clear_guards) {
        try cookies.append(arena, sessionCookie(keystone_config.oauth_state_cookie_name, "", 0));
        try cookies.append(arena, sessionCookie(keystone_config.oauth_nonce_cookie_name, "", 0));
    }
    return .{
        .session = .{
            .token = token,
            .provider = .google,
            .issued_at = issued_at,
            .expires_at = expires_at,
            .user = .{ .id = user_id, .email = google.email, .name = name, .picture = google.picture },
        },
        .cookies = cookies.items,
    };
}

/// A cookie with this package's attributes. An empty value with a zero
/// lifetime clears it.
fn sessionCookie(name: []const u8, value: []const u8, max_age: i64) Cookie {
    return .{
        .name = name,
        .value = value,
        .expires = max_age,
        .http_only = keystone_config.http_only_cookies,
        .secure = keystone_config.secure_cookies,
        .same_site = keystone_config.same_site,
    };
}

/// Hands a sign-in or refresh to a worker. The reply is the worker's from
/// here; a full queue answers 503 at once.
fn deferToWorker(ctx: *Context, kind: @FieldType(Job, "kind"), grant: []const u8) !void {
    const owned = try job_allocator.dupe(u8, grant);
    errdefer job_allocator.free(owned);
    const reply = try ctx.deferReply();
    pool.submit(.{ .reply = reply, .kind = kind, .grant = owned }) catch {
        job_allocator.free(owned);
        reply.send(503, "text/plain", "too many sign-ins at once; try again shortly");
    };
}

pub fn bootstrapSession(ctx: *Context) !AuthSessionResponse {
    const claims = try validateSession(ctx) orelse {
        return .{
            .success = true,
            .state = .signed_out,
        };
    };

    return .{
        .success = true,
        .state = .signed_in,
        .session = .{
            .token = sessionTokenFromRequest(ctx) orelse "",
            .provider = .google,
            .issued_at = claims.iat,
            .expires_at = claims.exp,
            .user = .{
                .id = claims.sub,
                .email = claims.email,
                .name = claims.name,
            },
        },
    };
}

pub fn signOutSession(ctx: *Context, _: bool) !AuthSessionResponse {
    try clearSessionCookies(ctx);
    return .{
        .success = true,
        .state = .signed_out,
    };
}

fn validateSession(ctx: *Context) !?SessionClaims {
    const token = sessionTokenFromRequest(ctx) orelse return null;
    return decodeSessionToken(ctx.requestAllocator(), token);
}

fn decodeSessionToken(allocator: std.mem.Allocator, token: []const u8) !?SessionClaims {
    if (token.len == 0) return null;
    // A missing secret means no session can be verified, which is the
    // same outcome as an invalid token.
    const secret = sessionSecret() catch return null;
    var jwt = JWT.decode(
        allocator,
        SessionClaims,
        token,
        .{ .secret = secret },
        .{},
    ) catch return null;
    defer jwt.deinit();

    const now = Time.timestamp();
    if (jwt.claims.exp < now) return null;

    return SessionClaims{
        .sub = try allocator.dupe(u8, jwt.claims.sub),
        .email = try allocator.dupe(u8, jwt.claims.email),
        .name = try allocator.dupe(u8, jwt.claims.name),
        .exp = jwt.claims.exp,
        .iat = jwt.claims.iat,
    };
}

fn sessionTokenFromRequest(ctx: *Context) ?[]const u8 {
    const auth_header = std.mem.trim(u8, ctx.http_header.authorization, " \t\r\n");
    if (auth_header.len > 7 and std.ascii.startsWithIgnoreCase(auth_header, "Bearer ")) {
        const token = std.mem.trim(u8, auth_header[7..], " \t\r\n");
        if (token.len > 0) return token;
    }

    const cookie_name = keystone_config.session_cookie_name;
    if (ctx.getCookie(cookie_name)) |cookie| {
        if (cookie.value.len > 0) return cookie.value;
    }
    return null;
}

/// The key session tokens are signed with.
///
/// There used to be a hardcoded fallback here, committed to the
/// repository. Anyone holding a copy of this source could mint a valid
/// session for any user of any deployment that had not set
/// `session_secret`, and nothing warned that it was in use. There is no
/// default now: a missing secret is a configuration error, not something
/// to paper over.
fn sessionSecret() ![]const u8 {
    const secret = keystone_config.session_secret orelse return error.MissingSessionSecret;
    if (secret.len == 0) return error.MissingSessionSecret;
    return secret;
}

fn encodeSessionToken(allocator: std.mem.Allocator, claims: SessionClaims) ![]const u8 {
    return JWT.encode(
        allocator,
        JWTRoot.Header{
            .alg = .HS256,
            .typ = "JWT",
        },
        claims,
        .{ .secret = try sessionSecret() },
    );
}

fn getRefreshToken(ctx: *Context) !?[]const u8 {
    if (ctx.http_header.content_type == .Form) {
        ctx.parseForm() catch {};
        if (ctx.form_params.get("refresh-token")) |token| {
            if (token.len > 0) return token;
        }
    }
    if (ctx.getCookie(keystone_config.refresh_cookie_name)) |cookie| {
        if (cookie.value.len > 0) return cookie.value;
    }
    return null;
}

fn validateCallbackPayload(ctx: *Context) !void {
    if (ctx.form_params.get("error") != null) return error.OauthCallbackError;

    const expected_state_cookie = ctx.getCookie(keystone_config.oauth_state_cookie_name);
    const incoming_state = ctx.form_params.get("state");
    if (expected_state_cookie) |state_cookie| {
        if (state_cookie.value.len > 0) {
            const state = incoming_state orelse return error.InvalidOauthState;
            if (!std.mem.eql(u8, state, state_cookie.value)) return error.InvalidOauthState;
        }
    }

    const expected_nonce_cookie = ctx.getCookie(keystone_config.oauth_nonce_cookie_name);
    const incoming_nonce = ctx.form_params.get("nonce");
    if (expected_nonce_cookie) |nonce_cookie| {
        if (nonce_cookie.value.len > 0) {
            const nonce = incoming_nonce orelse return error.InvalidOauthNonce;
            if (!std.mem.eql(u8, nonce, nonce_cookie.value)) return error.InvalidOauthNonce;
        }
    }
}

fn clearSessionCookies(ctx: *Context) !void {
    for ([_][]const u8{
        keystone_config.session_cookie_name,
        keystone_config.refresh_cookie_name,
        keystone_config.oauth_state_cookie_name,
        keystone_config.oauth_nonce_cookie_name,
    }) |name| try ctx.addCookie(sessionCookie(name, "", 0));
}

fn buildConfig(init_cfg: InitConfig, allocator: std.mem.Allocator) !Config {
    var cfg: Config = .{
        .session_secret = init_cfg.session_secret,
        .session_ttl_seconds = init_cfg.session_ttl_seconds,
        .session_cookie_name = init_cfg.session_cookie_name,
        .refresh_cookie_name = init_cfg.refresh_cookie_name,
        .oauth_state_cookie_name = init_cfg.oauth_state_cookie_name,
        .oauth_nonce_cookie_name = init_cfg.oauth_nonce_cookie_name,
        .secure_cookies = init_cfg.secure_cookies,
        .http_only_cookies = init_cfg.http_only_cookies,
        .same_site = init_cfg.same_site,
        .on_sign_in = init_cfg.on_sign_in,
    };

    if (init_cfg.clients.google) |google_client| {
        const redirect_uri = google_client.redirect_uri orelse try defaultRedirectUri(allocator, init_cfg);
        cfg.providers.google = .{
            .client_id = google_client.client_id,
            .client_secret = google_client.client_secret,
            .redirect_uri = redirect_uri,
            .grant_type = google_client.grant_type orelse "authorization_code",
        };
        if (google_client.token_url) |url| cfg.providers.google.?.token_url = url;
    }

    if (init_cfg.clients.github) |github_client| {
        const redirect_uri = github_client.redirect_uri orelse try defaultRedirectUri(allocator, init_cfg);
        cfg.providers.github = .{
            .client_id = github_client.client_id,
            .client_secret = github_client.client_secret,
            .redirect_uri = redirect_uri,
            .state = github_client.state orelse "keystone_csrf",
        };
    }

    return cfg;
}

fn defaultRedirectUri(allocator: std.mem.Allocator, init_cfg: InitConfig) ![]const u8 {
    if (std.mem.startsWith(u8, init_cfg.hook_path, "http://") or std.mem.startsWith(u8, init_cfg.hook_path, "https://")) {
        return allocator.dupe(u8, init_cfg.hook_path);
    }
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ init_cfg.origin, init_cfg.hook_path });
}

fn routeGoogleExchange(ctx: *Context) !void {
    // The quick checks, here on the loop: what the browser sent back.
    ctx.parseForm() catch return ctx.ERROR(400, "expected a form");
    validateCallbackPayload(ctx) catch |err| {
        std.log.warn("google sign-in refused: {any}", .{err});
        return ctx.ERROR(401, "Google sign-in failed");
    };
    const code = ctx.form_params.get("auth-code") orelse return ctx.ERROR(401, "Google sign-in failed");
    try deferToWorker(ctx, .exchange, code);
}

fn routeGithubExchange(ctx: *Context) !void {
    const token = try exchangeGithubToken(ctx);
    const Resp = struct {
        success: bool,
        token: []const u8,
    };
    try ctx.JSON(Resp, .{
        .success = true,
        .token = token,
    });
}

fn routeBootstrapSession(ctx: *Context) !void {
    const resp = try bootstrapSession(ctx);
    try ctx.JSON(AuthSessionResponse, resp);
}

fn routeRefreshSession(ctx: *Context) !void {
    const refresh_token = try getRefreshToken(ctx) orelse return ctx.JSON(AuthSessionResponse, .{
        .success = false,
        .state = .signed_out,
        .err = "refresh_token_missing",
    });
    try deferToWorker(ctx, .refresh, refresh_token);
}

fn routeSignoutSession(ctx: *Context) !void {
    var revoke_remote = false;
    if (ctx.http_header.content_type == .Form) {
        ctx.parseForm() catch {};
        if (ctx.form_params.get("revoke_remote")) |flag| {
            revoke_remote = std.mem.eql(u8, flag, "1") or std.ascii.eqlIgnoreCase(flag, "true");
        }
    }

    const resp = try signOutSession(ctx, revoke_remote);
    try ctx.JSON(AuthSessionResponse, resp);
}

fn routeValidateSession(ctx: *Context) !void {
    const user = try requireAuth(ctx);
    const UserResp = struct {
        email: []const u8,
        name: []const u8,
    };
    try ctx.JSON(UserResp, .{
        .email = user.email,
        .name = user.name,
    });
}

// Simple middleware-style function
pub fn requireAuth(ctx: *Context) !SessionClaims {
    return validateSession(ctx) catch {
        try ctx.ERROR(401, "Auth Header Invalid");
        return error.AuthHeaderInvalid;
    } orelse {
        try ctx.ERROR(401, "Invalid or expired session");
        return error.Unauthorized;
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// An id token as Google's token endpoint returns it. The signature is
/// arbitrary: `handleGoogleCallback` does not check it.
fn fakeIdToken(allocator: std.mem.Allocator, iss: []const u8, aud: []const u8, exp: i64) ![]const u8 {
    return JWT.encode(allocator, .{ .alg = .HS256, .typ = "JWT" }, .{
        .iss = iss,
        .azp = aud,
        .aud = aud,
        .sub = "1234567890",
        .email = "ada@example.com",
        .email_verified = true,
        .name = "Ada",
        .iat = Time.timestamp(),
        .exp = exp,
    }, .{ .secret = "not-googles-key" });
}

test "a Google id token is accepted only for this client, from Google, unexpired" {
    try init(.{ .providers = .{ .google = .{ .client_id = "our-client", .client_secret = "s" } } }, testing.allocator);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const later = Time.timestamp() + 3600;

    const ok = try handleGoogleCallback(a, try fakeIdToken(a, "https://accounts.google.com", "our-client", later));
    try testing.expectEqualStrings("1234567890", ok.claims.sub);
    try testing.expectEqualStrings("ada@example.com", ok.claims.email);

    try testing.expectError(error.InvalidIdToken, handleGoogleCallback(a, try fakeIdToken(a, "https://accounts.google.com", "someone-elses-client", later)));
    try testing.expectError(error.InvalidIdToken, handleGoogleCallback(a, try fakeIdToken(a, "https://evil.example", "our-client", later)));
    try testing.expectError(error.InvalidIdToken, handleGoogleCallback(a, try fakeIdToken(a, "accounts.google.com", "our-client", Time.timestamp() - 3600)));
}
