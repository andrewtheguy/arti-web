//! POC: a Tor onion (hidden) service, built on Arti, that serves a static HTML
//! page whose embedded JavaScript makes an AJAX call back to a backend endpoint.
//!
//! Run with `RUST_LOG=info cargo run`, wait for bootstrap, then open the printed
//! `http://<...>.onion` URL in Tor Browser. The page auto-fires a `fetch()` to
//! `/api/ping` on load, proving the hidden service + HTTP-over-Tor + JS + AJAX
//! loop works end to end.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use arti_client::{TorClient, config::TorClientConfigBuilder};
use futures::StreamExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use safelog::DisplayRedacted;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests};

/// The static page served at `/`. Self-contained: inline CSS + JS, no external
/// assets (nothing external is reachable over an onion service anyway).
const INDEX_HTML: &str = include_str!("index.html");

/// Counts handled `/api/ping` requests so successive AJAX calls visibly change.
static PING_COUNT: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Ephemeral Tor state: a fresh keypair (and thus a fresh .onion) each run.
    // IMPORTANT: `_temp_dir` must stay alive for the whole program — if it is
    // dropped, the state/cache dirs are deleted and the Tor client breaks.
    let _temp_dir = tempfile::tempdir().context("creating temp dir for Tor state")?;
    let state_dir = _temp_dir.path().join("state");
    let cache_dir = _temp_dir.path().join("cache");

    tracing::info!("bootstrapping Tor client (ephemeral mode)...");
    let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .context("building Tor client config")?;
    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .context("bootstrapping Tor client")?;
    tracing::info!("Tor client bootstrapped");

    // Launch the onion service.
    let hs_config = OnionServiceConfigBuilder::default()
        .nickname("arti-web-poc".parse()?)
        .build()?;
    let (service, rend_requests) = tor_client
        .launch_onion_service(hs_config)?
        .ok_or_else(|| anyhow::anyhow!("onion service support is disabled"))?;

    let onion_addr = service
        .onion_address()
        .ok_or_else(|| anyhow::anyhow!("no onion address available yet"))?;

    println!("\n========================================================================");
    println!("  Onion service is live. Open this in Tor Browser:");
    println!("    http://{}", onion_addr.display_unredacted());
    println!("  (first load may take 10-30s while the descriptor publishes)");
    println!("========================================================================\n");

    // Convert rendezvous requests into a stream of per-connection StreamRequests,
    // and serve HTTP on each one.
    let mut stream_requests = handle_rend_requests(rend_requests);
    while let Some(stream_req) = stream_requests.next().await {
        tokio::spawn(async move {
            if let Err(e) = serve_connection(stream_req).await {
                tracing::warn!("connection error: {e}");
            }
        });
    }

    Ok(())
}

/// Accept one Tor stream and serve HTTP/1.1 over it via hyper.
async fn serve_connection(stream_req: tor_hsservice::StreamRequest) -> Result<()> {
    let stream = stream_req
        .accept(Connected::new_empty())
        .await
        .context("accepting Tor stream")?;

    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(io, service_fn(handle))
        .await
        .context("serving HTTP connection")?;
    Ok(())
}

/// Route requests: `/` serves the page, `/api/ping` is the AJAX backend.
async fn handle(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    tracing::info!("{} {}", req.method(), req.uri().path());

    let resp = match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from_static(INDEX_HTML.as_bytes())))
            .unwrap(),

        (&Method::GET, "/api/ping") => {
            let count = PING_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            let body = format!(
                r#"{{"status":"ok","message":"hello from the onion backend","count":{count}}}"#
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }

        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap(),
    };

    Ok(resp)
}
