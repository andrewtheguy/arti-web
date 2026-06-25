//! `tunnel` subcommand: onion → localhost forwarder.
//!
//! Exposes a remote onion service as a plain local TCP port so ordinary tools
//! (curl, a normal browser, any HTTP client) can reach it WITHOUT Tor Browser.
//! Run this on any device; it speaks to the onion over Tor.
//!
//! SECURITY NOTE: unlike `serve` (which exposes no local socket), this DOES open
//! a listening socket. It binds 127.0.0.1 only, so it is reachable by other
//! processes/users on THIS machine. Whatever auth the onion service enforces
//! (the login flow) is now the access control. Do not bind this to 0.0.0.0.

use anyhow::{Context, Result};
use arti_client::{TorClient, TorClientConfig};
use clap::Args;
use tokio::net::TcpListener;

/// Forward a remote onion service to a local TCP port (client side).
#[derive(Args, Debug)]
pub struct TunnelArgs {
    /// Onion address to forward to, e.g. abc...xyz.onion
    onion: String,

    /// Local TCP port to listen on (bound to 127.0.0.1).
    #[arg(long, short = 'l', default_value_t = 8080)]
    local_port: u16,

    /// Virtual port on the onion service to connect to.
    #[arg(long, short = 'p', default_value_t = 80)]
    virtual_port: u16,
}

pub async fn run(args: TunnelArgs) -> Result<()> {
    let TunnelArgs {
        onion,
        local_port,
        virtual_port,
    } = args;

    // A client only needs to *connect*; default config persists circuit/dir
    // cache in the standard Arti dirs so later starts bootstrap faster.
    tracing::info!("bootstrapping Tor client...");
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
