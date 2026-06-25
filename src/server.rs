//! `serve` subcommand: an auth-gated Tor onion service.
//!
//! Why this shape, specifically for Tor Browser:
//!   * Tor Browser's "Safer"/"Safest" security levels DISABLE JavaScript, so the
//!     auth flow is plain server-rendered HTML forms — it works with JS fully off.
//!     The AJAX demo is progressive enhancement shown only after login.
//!   * Arti embeds the onion service in-process: there is NO local SOCKS/TCP
//!     socket. The only ingress is the Tor rendezvous, so no other local app can
//!     reach this endpoint. The .onion address is itself a capability; the login
//!     below is application-layer defense-in-depth on top of that.
//!   * `.onion` is a secure context in Tor Browser, so `Secure` cookies are honored.
//!
//! State is persistent: the onion-service identity key lives in the keystore
//! under the data dir, so the .onion address stays the same across restarts.
//! Guard that directory — its key *is* the service identity.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use arti_client::{TorClient, config::TorClientConfigBuilder};
use clap::Args;
use futures::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use rand::rngs::OsRng;
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

/// Run the auth-gated onion service (host side; opens no local socket).
#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Directory for persistent Tor state + the onion identity key.
    #[arg(long, env = "ARTI_WEB_DATA_DIR", default_value = "arti-web-data")]
    data_dir: PathBuf,

    /// Onion-service nickname = keystore namespace. Changing it mints a NEW
    /// .onion address; keep it constant to keep the same address.
    #[arg(long, default_value = "arti-web-poc")]
    nickname: String,
}

/// Restricted page template; `__USERNAME__` is replaced at render time.
const RESTRICTED_HTML: &str = include_str!("index.html");

/// Cookie attributes. `Secure` is honored because Tor Browser (and a normal
/// browser over http://localhost via the tunnel) treats the origin as a secure
/// context. `SameSite=Strict` blocks cross-site requests (CSRF). Note: non-browser
/// clients like curl won't replay a `Secure` cookie over plain http.
const COOKIE_ATTRS: &str = "HttpOnly; SameSite=Strict; Secure; Path=/";
const MAX_LOGIN_BODY_BYTES: u64 = 8 * 1024;

static PING_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Shared application state behind an `Arc`.
struct AppState {
    /// username -> Argon2 PHC hash string.
    users: HashMap<String, String>,
    /// A throwaway hash verified against when a username is unknown, so the
    /// response time of a bad-username attempt resembles a bad-password one.
    dummy_hash: String,
    /// Active sessions: opaque token -> username.
    sessions: Mutex<HashMap<String, String>>,
}

impl AppState {
    /// Verify credentials in roughly constant time w.r.t. username existence.
    fn verify(&self, username: &str, password: &str) -> bool {
        let hash = self.users.get(username).unwrap_or(&self.dummy_hash);
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        let ok = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // Only a real, existing user can succeed.
        ok && self.users.contains_key(username)
    }

    fn create_session(&self, username: &str) -> String {
        let token = new_token();
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), username.to_string());
        token
    }

    fn user_for(&self, token: &str) -> Option<String> {
        self.sessions.lock().unwrap().get(token).cloned()
    }

    fn destroy_session(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

pub async fn run(args: ServeArgs) -> Result<()> {
    // --- Demo credentials (replace with a real user store for anything real) ---
    let demo_user = "agent";
    let demo_pass = "tor-rocks";
    let mut users = HashMap::new();
    users.insert(demo_user.to_string(), hash_password(demo_pass));
    let state = Arc::new(AppState {
        users,
        dummy_hash: hash_password("this password matches nothing"),
        sessions: Mutex::new(HashMap::new()),
    });

    // --- Persistent Tor state: the onion-service identity key is stored in the
    // keystore under `state_dir`, so reusing this directory yields the SAME
    // .onion address across restarts. The key is sensitive (it *is* the service
    // identity), so directories are created 0700 and fs-mistrust checks stay on. ---
    let state_dir = args.data_dir.join("state");
    let cache_dir = args.data_dir.join("cache");
    create_private_dir(&args.data_dir)?;
    create_private_dir(&state_dir)?;
    create_private_dir(&cache_dir)?;
    tracing::info!("using persistent state dir: {}", state_dir.display());

    tracing::info!("bootstrapping Tor client...");
    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .context("building Tor client config")?;
    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .context("bootstrapping Tor client")?;
    tracing::info!("Tor client bootstrapped");

    let hs_config = OnionServiceConfigBuilder::default()
        .nickname(args.nickname.parse().context("invalid nickname")?)
        .build()?;
    let (service, rend_requests) = tor_client
        .launch_onion_service(hs_config)?
        .ok_or_else(|| anyhow::anyhow!("onion service support is disabled"))?;
    let onion_addr = service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("no onion address available yet"))?;

    println!("\n========================================================================");
    println!("  Auth-gated onion service is live (persistent — same address on restart).");
    println!("  Open in Tor Browser:");
    println!("    http://{}", onion_addr.display_unredacted());
    println!();
    println!("  Demo login:  username = {demo_user}   password = {demo_pass}");
    println!("  (first load may take 10-30s while the descriptor publishes)");
    println!("========================================================================\n");

    let mut stream_requests = handle_rend_requests(rend_requests);
    while let Some(stream_req) = stream_requests.next().await {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream_req, state).await {
                tracing::warn!("connection error: {e}");
            }
        });
    }

    Ok(())
}

/// Accept one Tor stream and serve HTTP/1.1 over it via hyper.
async fn serve_connection(
    stream_req: tor_hsservice::StreamRequest,
    state: Arc<AppState>,
) -> Result<()> {
    let stream = stream_req
        .accept(Connected::new_empty())
        .await
        .context("accepting Tor stream")?;
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let state = state.clone();
                async move { handle(state, req).await }
            }),
        )
        .await
        .context("serving HTTP connection")?;
    Ok(())
}

async fn handle(
    state: Arc<AppState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let token = session_token(req.headers());
    let current_user = token.as_deref().and_then(|t| state.user_for(t));

    tracing::info!("{method} {path} (auth={})", current_user.is_some());

    let resp = match (&method, path.as_str()) {
        // Landing: route by auth state.
        (&Method::GET, "/") => match current_user {
            Some(_) => redirect("/restricted", None),
            None => redirect("/login", None),
        },

        // Login form (server-rendered; no JS required).
        (&Method::GET, "/login") => {
            if current_user.is_some() {
                redirect("/restricted", None)
            } else {
                html(StatusCode::OK, login_page(false))
            }
        }

        // Process login.
        (&Method::POST, "/login") => {
            if !login_body_within_limit(&req) {
                return Ok(html(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "<h1>413 payload too large</h1>".to_string(),
                ));
            }

            let form = parse_form(&collect_body(req).await);
            let user = form.get("username").map(String::as_str).unwrap_or("");
            let pass = form.get("password").map(String::as_str).unwrap_or("");
            if state.verify(user, pass) {
                let new = state.create_session(user);
                tracing::info!("login OK for user={user}");
                redirect("/restricted", Some(&set_cookie(&new)))
            } else {
                tracing::info!("login FAILED for user={user}");
                html(StatusCode::UNAUTHORIZED, login_page(true))
            }
        }

        // Restricted content (requires a valid session).
        (&Method::GET, "/restricted") => match &current_user {
            Some(user) => html(
                StatusCode::OK,
                RESTRICTED_HTML.replace("__USERNAME__", &html_escape(user)),
            ),
            None => redirect("/login", None),
        },

        // Auth-gated API for the AJAX demo. The API enforces auth itself —
        // hiding the UI is never the access control.
        (&Method::GET, "/api/ping") => match &current_user {
            Some(user) => {
                let count = PING_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                let body = format!(
                    r#"{{"status":"ok","user":"{}","message":"authenticated request over Tor","count":{count}}}"#,
                    json_escape(user)
                );
                json(StatusCode::OK, body)
            }
            None => json(
                StatusCode::UNAUTHORIZED,
                r#"{"status":"error","message":"not authenticated"}"#.to_string(),
            ),
        },

        // Logout: destroy session + clear cookie. Plain form POST, no JS.
        (&Method::POST, "/logout") => {
            if let Some(t) = &token {
                state.destroy_session(t);
            }
            redirect("/login", Some(&clear_cookie()))
        }

        _ => html(StatusCode::NOT_FOUND, "<h1>404 not found</h1>".to_string()),
    };

    Ok(resp)
}

// ---------- response builders ----------

fn html(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store")
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// 303 See Other so a POST redirects to a GET, optionally setting a cookie.
fn redirect(location: &str, cookie: Option<&str>) -> Response<Full<Bytes>> {
    let mut b = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(CACHE_CONTROL, "no-store")
        .header(LOCATION, location);
    if let Some(c) = cookie {
        b = b.header(SET_COOKIE, c);
    }
    b.body(Full::new(Bytes::new())).unwrap()
}

fn set_cookie(token: &str) -> String {
    format!("session={token}; {COOKIE_ATTRS}")
}

fn clear_cookie() -> String {
    format!("session=; {COOKIE_ATTRS}; Max-Age=0")
}

// ---------- helpers ----------

/// Create `dir` (and parents) if needed, with `0700` permissions on Unix so the
/// onion-service key material is never group/world readable. Idempotent.
fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating data dir {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting 0700 on {}", dir.display()))?;
    }
    Ok(())
}

/// 256-bit cryptographically-random session token, hex-encoded.
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("hashing password")
        .to_string()
}

/// Extract the `session` cookie value from the request headers.
fn session_token(headers: &hyper::HeaderMap) -> Option<String> {
    let cookies = headers.get(COOKIE)?.to_str().ok()?;
    cookies
        .split(';')
        .find_map(|c| c.trim().strip_prefix("session=").map(str::to_string))
}

fn login_body_within_limit(req: &Request<Incoming>) -> bool {
    matches!(
        req.body().size_hint().upper(),
        Some(size) if size <= MAX_LOGIN_BODY_BYTES
    )
}

async fn collect_body(req: Request<Incoming>) -> String {
    match req.into_body().collect().await {
        Ok(c) => String::from_utf8_lossy(&c.to_bytes()).into_owned(),
        Err(_) => String::new(),
    }
}

/// Parse an `application/x-www-form-urlencoded` body.
fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?;
            let v = it.next().unwrap_or("");
            Some((url_decode(k), url_decode(v)))
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn login_page(error: bool) -> String {
    let err = if error {
        r#"<p class="err">Invalid username or password.</p>"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login — Arti Onion POC</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; min-height:100vh; display:grid; place-items:center;
    font:16px/1.5 system-ui,sans-serif; background:#14131a; color:#e7e5ee; }}
  .card {{ width:min(92vw,400px); background:#1e1c27; border:1px solid #322f40;
    border-radius:14px; padding:28px 30px; box-shadow:0 12px 40px rgba(0,0,0,.4); }}
  h1 {{ margin:0 0 18px; font-size:20px; }}
  label {{ display:block; font-size:13px; color:#9a96ad; margin:12px 0 4px; }}
  input {{ width:100%; box-sizing:border-box; padding:10px 12px; border-radius:9px;
    border:1px solid #322f40; background:#14131a; color:#e7e5ee; font-size:15px; }}
  button {{ margin-top:18px; width:100%; border:0; border-radius:9px; cursor:pointer;
    background:#7c5cff; color:#fff; font-size:15px; font-weight:600; padding:11px; }}
  .err {{ color:#ff6b6b; font-size:14px; margin:0 0 4px; }}
  .note {{ color:#6f6b80; font-size:12px; margin-top:16px; }}
</style></head><body>
  <div class="card">
    <h1>🔒 Restricted area</h1>
    {err}
    <form method="POST" action="/login" autocomplete="off">
      <label for="u">Username</label>
      <input id="u" name="username" autofocus>
      <label for="p">Password</label>
      <input id="p" name="password" type="password">
      <button type="submit">Sign in</button>
    </form>
    <p class="note">Served over a Tor onion service. Works with JavaScript disabled.</p>
  </div>
</body></html>"#
    )
}
