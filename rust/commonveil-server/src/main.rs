//! Start a self-hosted Commonveil server (Rust). Settings come from environment variables, the
//! same as the Node.js server's: see docs/SELF_HOSTING.md.
//!
//!   ENTITIES_DIR=base44/entities DIST_DIR=dist cargo run -p commonveil-server
use std::path::PathBuf;

use commonveil_server::config::Config;
use commonveil_server::App;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let entities = std::env::var("ENTITIES_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../base44/entities"));
    let (bind, port, url, version) = (config.bind.clone(), config.port, config.site_url.clone(), config.version.clone());
    let app = App::new(config, &entities)?;
    // Scheduled tasks (on Base44 these are workflows).
    commonveil_server::maintenance::start(&app);
    commonveil_server::updates::start(&app);
    let listener = tokio::net::TcpListener::bind((bind.as_str(), port)).await?;
    println!("Commonveil {version} (Rust server) is running at {url} (listening on {bind}:{port})");
    axum::serve(listener, app.router())
        .with_graceful_shutdown(async {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
            #[cfg(unix)]
            tokio::select! { _ = ctrl_c => println!("SIGINT: stopping"), _ = term.recv() => println!("SIGTERM: stopping") }
            #[cfg(not(unix))]
            let _ = ctrl_c.await;
        })
        .await?;
    Ok(())
}
