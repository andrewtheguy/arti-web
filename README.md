# arti-web-poc

A proof-of-concept **Tor onion (hidden) service in pure Rust**, built on
[Arti](https://gitlab.torproject.org/tpo/core/arti). It serves an
**auth-gated web app** over an embedded onion service, and can also act as a
**local forwarder** so ordinary tools can reach an onion without Tor Browser.

Two roles, one binary:

| Command | Role | Local socket? |
|---|---|---|
| `arti-web-poc serve` | Host the auth-gated onion service | **No** — ingress is only via the Tor rendezvous |
| `arti-web-poc tunnel <onion>` | Forward a remote onion to `127.0.0.1:<port>` | Yes — a loopback listener (client side) |

## Why it looks the way it does

- **Arti embeds the onion service in-process.** The `serve` role opens **no**
  local TCP/SOCKS socket — no other app (or local malware, or port scan) on the
  host can reach it. The `.onion` address itself is a capability, and the login
  is application-layer defense-in-depth on top of that.
- **Auth works with JavaScript disabled.** Tor Browser's *Safer/Safest* levels
  turn JS off, so login/logout/restricted content are plain server-rendered HTML
  forms + a session cookie. The AJAX demo is *progressive enhancement* shown only
  after login.
- **Persistent identity.** The onion-service key lives in a keystore under the
  data dir, so the `.onion` address is stable across restarts.

## Requirements

- A recent Rust toolchain (the crate uses `edition = "2024"`).
- Outbound network access (the Tor client bootstraps against the live network).
- **Tor Browser** to visit the `.onion` directly — *or* use `tunnel` + any
  normal HTTP client.

## Build

```bash
cargo build            # first build is slow: it compiles Arti + a static sqlite
```

## Usage

### Serve (host)

```bash
RUST_LOG=info cargo run -- serve
# options:
#   --data-dir <PATH>   persistent state + onion key   [env: ARTI_WEB_POC_DATA_DIR]
#                                                       [default: arti-web-poc-data]
#   --nickname <NAME>   keystore namespace; changing it mints a NEW address
#                                                       [default: arti-web-poc]
```

On startup it bootstraps Tor and prints the address + demo credentials:

```
  Auth-gated onion service is live (persistent — same address on restart).
  Open in Tor Browser:
    http://<56-char>.onion

  Demo login:  username = agent   password = tor-rocks
```

Open that URL in **Tor Browser** → you're redirected to `/login` → sign in →
the restricted page loads (and its on-load `fetch('/api/ping')` proves the
session cookie rides AJAX requests too). First load can take 10–30s while the
service descriptor publishes.

### Tunnel (client, any device)

Reach the service from a normal browser or `curl` — no Tor Browser. The client
device needs only the **public `.onion` address** (no keys are copied):

```bash
RUST_LOG=info cargo run -- tunnel <addr>.onion          # -> 127.0.0.1:8080
RUST_LOG=info cargo run -- tunnel <addr>.onion -l 9000  # -> 127.0.0.1:9000
# -p / --virtual-port  port on the onion to dial   [default: 80]

curl http://127.0.0.1:8080/login        # or point a normal browser at it
```

## HTTP endpoints (`serve`)

| Method | Path | Behavior |
|---|---|---|
| GET | `/` | Redirect to `/restricted` (if signed in) or `/login` |
| GET | `/login` | Server-rendered login form (no JS) |
| POST | `/login` | Verify credentials → create session → `Set-Cookie` → 303 |
| GET | `/restricted` | Gated content; requires a valid session |
| GET | `/api/ping` | Auth-gated JSON; **401** without a session |
| POST | `/logout` | Destroy session + clear cookie (plain form) |

## Security notes

- **Password storage:** Argon2id, with a dummy-hash verification path on unknown
  usernames to blunt user-enumeration timing.
- **Sessions:** 256-bit `OsRng` tokens; cookie is
  `HttpOnly; SameSite=Strict; Secure; Path=/`. `.onion` and `http://localhost`
  are both secure contexts, so `Secure` is honored there.
  - *Gotcha:* `curl` (and many non-browser clients) won't replay a `Secure`
    cookie over plain `http`. For scripted access through the tunnel, either pass
    the cookie manually or drop `Secure` from `COOKIE_ATTRS` in `src/server.rs`
    (the loopback hop is local-only; the Tor hop is encrypted regardless).
- **The onion key is the identity.** It lives at
  `arti-web-poc-data/state/keystore/hss/<nickname>/ks_hs_id.ed25519_expanded_private`.
  The data dirs are created `0700`, Arti's `fs-mistrust` checks are left **on**,
  and `arti-web-poc-data/` is git-ignored. Anyone who copies that key can impersonate
  your service. To rotate to a fresh address, delete `arti-web-poc-data/`.
- **`tunnel` reverses the "no local socket" property** — that's its job. It binds
  loopback only; never bind it to `0.0.0.0`. At that point the login is your
  access control.

## Not for production

This is a POC. Sessions are in-memory (lost on restart), there's no login
rate-limiting/lockout or CSRF token beyond `SameSite=Strict`, and the demo
credentials are hardcoded in `src/server.rs`. Replace those before relying on it.
