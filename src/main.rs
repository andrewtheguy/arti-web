//! arti-web-poc — a Tor onion service POC with two roles in one binary:
//!
//!   arti-web-poc serve            run the auth-gated onion service (host; no local socket)
//!   arti-web-poc tunnel <onion>   forward a remote onion to a local port (client)
//!
//! See `arti-web-poc --help` / `arti-web-poc <cmd> --help` for options.

mod server;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "arti-web-poc", about = "Tor onion service POC (serve + tunnel)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the auth-gated onion service (host side; opens no local socket).
    Serve(server::ServeArgs),
    /// Forward a remote onion service to a local TCP port (client side).
    Tunnel(tunnel::TunnelArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Serve(args) => server::run(args).await,
        Command::Tunnel(args) => tunnel::run(args).await,
    }
}
