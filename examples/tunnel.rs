//! Onion → localhost forwarder.
//!
//! Exposes a remote onion service as a plain local TCP port so ordinary tools
//! (curl, a normal browser, any HTTP client) can reach it WITHOUT Tor Browser.
//! Run this on any device that has this binary; it speaks to the onion over Tor.
//!
//!   cargo run --example tunnel -- <addr.onion> [local_port] [virtual_port]
//!   # defaults: local_port=8080, virtual_port=80
//!   # then:  curl http://127.0.0.1:8080/login
//!
//! SECURITY NOTE: unlike the server (which exposes no local socket), this DOES
//! open a listening socket. It binds 127.0.0.1 only, so it is reachable by other
//! processes/users on THIS machine. Whatever auth the onion service enforces
//! (the login flow) is now the access control. Do not bind this to 0.0.0.0.

use std::env;

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut args = env::args().skip(1);
    let onion = args
        .next()
        .context("usage: tunnel <addr.onion> [local_port] [virtual_port]")?;
    let local_port: u16 = match args.next() {
        Some(s) => s.parse().context("local_port must be a number")?,
        None => 8080,
    };
    let virtual_port: u16 = match args.next() {
        Some(s) => s.parse().context("virtual_port must be a number")?,
        None => 80,
    };

    // A client only needs to *connect*; default config persists circuit/dir
    // cache in the standard Arti dirs so later starts bootstrap faster.
    eprintln!("bootstrapping Tor client...");
    let client = TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .context("bootstrapping Tor client")?;

    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .await
        .with_context(|| format!("binding 127.0.0.1:{local_port}"))?;

    println!("\n========================================================================");
    println!("  Tunnel up. Forwarding:");
    println!("    http://127.0.0.1:{local_port}  ->  {onion}:{virtual_port}  (via Tor)");
    println!("  Try:  curl http://127.0.0.1:{local_port}/login");
    println!("========================================================================\n");

    loop {
        let (mut tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept error: {e}");
                continue;
            }
        };
        let client = client.clone();
        let onion = onion.clone();
        tokio::spawn(async move {
            tracing::info!("connection from {peer}; dialing onion...");
            let mut tor = match client.connect((onion.as_str(), virtual_port)).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("onion connect failed: {e}");
                    return;
                }
            };
            // Pump bytes both directions until either side closes.
            match tokio::io::copy_bidirectional(&mut tcp, &mut tor).await {
                Ok((up, down)) => tracing::info!("closed ({up} up / {down} down bytes)"),
                Err(e) => tracing::warn!("forward error: {e}"),
            }
        });
    }
}
