# reverb-auth

OAuth and session handling for [Reverb](https://github.com/senet-toolbox/reverb).

Google and GitHub sign-in, session cookies, and JSON Web Tokens. Split out
of reverb itself: an HTTP server does not need to carry an identity
provider. The dependency runs one way — this package imports reverb for
`Context`, `Cookie` and the request helpers, and reverb knows nothing about
it.

## Requirements

Zig 0.16.0, and reverb, pinned by commit in `build.zig.zon`. An app that
uses both must pin the same reverb, so they share one `Context`.

## Usage

```zig
const auth = @import("reverb_auth");

// JWT travels with this package -- it was `reverb.JWT` before the split.
const token = try auth.JWT.encode(allocator, header, claims, .{ .secret = secret });
```

```sh
zig build test
```

## Status

Extracted on 2026-10-07. Apart from the JWT tests, this code had **never
been compiled** — it was unreachable from every build root in reverb.
Turning it on surfaced three things:

- `QueryBuilder.remove` referenced `query_param_list`, a field that does
  not exist. The list is `params`, which the surrounding loop already
  iterates.
- A **hardcoded JWT signing secret** was committed in `KeyStone.zig` and
  used as a silent fallback whenever `session_secret` was unset. Anyone
  with a copy of the source could mint a valid session for any user of any
  such deployment. There is no fallback now — a missing secret is
  `error.MissingSessionSecret`.
- A direct `loom` import, replaced with reverb's re-export so this package
  has one dependency rather than two.

**If any deployment ran with the old default, rotate its secret and
invalidate existing sessions.** Tokens signed with the committed key should
be treated as forgeable.

### Google sign-in (2026-10-20)

Reworked for assembler-backend, the first app to run it:

- `KeyStone.install(server, .{ .clients = .{ .google = ... }, .session_secret
  = ..., .on_sign_in = hook })` registers `/exchange/google/token`,
  `/auth/session/{bootstrap,refresh,signout}` and
  `/auth/validate/google/session`, the routes vapor's KeyStone calls.
- `on_sign_in` gets the user Google vouched for and returns the id the
  session is issued for, so the app can store the user.
- Google's id token is refused unless it names this client as its
  audience, Google as its issuer, and has not expired. Its signature is not
  checked; it comes straight from Google over TLS (OpenID Connect Core
  3.1.3.7).
- Request memory instead of the process-lifetime `ctx.arena`; `parseResp`
  no longer returns strings into freed memory, and ignores fields Google
  adds; a refused exchange is logged with Google's answer, never with the
  request (it carries the client secret).
- `token_url` in the client config points the exchange at a fake for tests.

GitHub sign-in is untouched and still unverified: it returns the access
token to the browser and allocates from `ctx.arena`.
