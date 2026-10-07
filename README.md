# reverb-auth

OAuth and session handling for [Reverb](https://github.com/senet-toolbox/reverb).

Google and GitHub sign-in, session cookies, and JSON Web Tokens. Split out
of reverb itself: an HTTP server does not need to carry an identity
provider. The dependency runs one way — this package imports reverb for
`Context`, `Cookie` and the request helpers, and reverb knows nothing about
it.

## Requirements

Zig 0.16.0, and reverb.

**The reverb dependency is a path, not a pinned URL**, because
`senet-toolbox/reverb` is private and `zig fetch` cannot reach it without
credentials. So this package currently needs a sibling checkout:

```
Zig/
├── reverb/
└── reverb-auth/
```

Switch `build.zig.zon` to a pinned `git+https://…#<commit>` once reverb is
public, or when CI has a token to fetch with.

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

Beyond the 8 JWT tests, nothing here is verified. The OAuth flows have no
tests and have never run.
