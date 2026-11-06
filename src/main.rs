mod comar;
mod git;
mod server;
mod taf;

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use clap::{Parser, ValueEnum};
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use server::{ComarServer, SharedSnapshot, Snapshot};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use taf::{ExpirationPolicy, TafConfig};

/// Root metadata from the first commit of github.com/maryland-dsd/law (2025-10-20). TUF
/// walks forward from here through every signed root rotation, so this only needs to be
/// trusted once. Override with --trusted-root.
const DEFAULT_ROOT: &[u8] = include_bytes!("../trust/maryland-dsd-law.1.root.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TransportKind {
    /// MCP over stdin/stdout, for desktop clients that launch the server themselves.
    Stdio,
    /// MCP streamable HTTP at /mcp, for shared or public deployments.
    Http,
}

/// An MCP server for the Code of Maryland Regulations, authenticated with TUF/TAF.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[arg(long, value_enum, default_value = "stdio", env = "COMAR_MCP_TRANSPORT")]
    transport: TransportKind,

    /// Address to listen on with --transport http.
    #[arg(long, default_value = "127.0.0.1:8000", env = "COMAR_MCP_BIND")]
    bind: String,

    /// Host names (or host:port) accepted in the HTTP Host header. Defaults to loopback only,
    /// which protects local servers from DNS rebinding; public deployments must set this.
    #[arg(long = "allowed-host", env = "COMAR_MCP_ALLOWED_HOSTS", value_delimiter = ',')]
    allowed_hosts: Vec<String>,

    /// Where repository mirrors and TUF state are kept.
    #[arg(long, env = "COMAR_MCP_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// TAF authentication repository.
    #[arg(long, default_value = "https://github.com/maryland-dsd/law.git", env = "COMAR_MCP_AUTH_REPO")]
    auth_repo: String,

    #[arg(long, default_value = "main")]
    auth_branch: String,

    /// Content repository (as named in the signed repositories.json) holding codified COMAR XML.
    #[arg(long, default_value = "maryland-dsd/law-xml-codified")]
    content_repo: String,

    /// Initial trusted TUF root metadata. Defaults to the embedded Maryland root v1.
    #[arg(long, env = "COMAR_MCP_TRUSTED_ROOT")]
    trusted_root: Option<PathBuf>,

    #[arg(long, value_enum, default_value = "archival", env = "COMAR_MCP_EXPIRATION")]
    expiration: ExpirationPolicy,

    /// Seconds between checks for a newer signed edition. 0 disables refreshing.
    #[arg(long, default_value_t = 3600, env = "COMAR_MCP_REFRESH_SECS")]
    refresh_secs: u64,

    /// Don't touch the network: serve from mirrors already in --data-dir.
    #[arg(long, env = "COMAR_MCP_OFFLINE")]
    offline: bool,

    /// Verify, build the index, print a summary, and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // stdout belongs to the MCP stdio transport; logs go to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = Cli::parse();
    let data_dir = match &cli.data_dir {
        Some(d) => d.clone(),
        None => PathBuf::from(std::env::var("HOME").context("set --data-dir or HOME")?)
            .join(".cache/comar-mcp"),
    };
    let trusted_root = match &cli.trusted_root {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => DEFAULT_ROOT.to_vec(),
    };
    let cfg = TafConfig {
        auth_repo_url: cli.auth_repo.clone(),
        auth_branch: cli.auth_branch.clone(),
        content_repo: cli.content_repo.clone(),
        trusted_root,
        data_dir,
        expiration: cli.expiration,
        fetch: !cli.offline,
    };

    let snapshot: SharedSnapshot = Arc::new(ArcSwapOption::empty());

    if cli.check {
        refresh(&cfg, &snapshot).await?;
        let snap = snapshot.load_full().expect("refresh stored a snapshot");
        let p = &snap.publication;
        println!("auth commit     {}", p.auth_commit);
        println!("content commit  {} ({})", p.content_commit, p.content_repo);
        for r in &p.roles {
            println!("{:<10} v{:<6} expires {}{}", r.role, r.version, r.expires, if r.expired { " EXPIRED" } else { "" });
        }
        for w in &p.warnings {
            println!("warning: {w}");
        }
        println!(
            "{} titles, {} chapters, {} regulations",
            snap.library.titles.len(),
            snap.library.chapters.len(),
            snap.library.regulations.len()
        );
        return Ok(());
    }

    let refresher = {
        let (cfg, snapshot) = (cfg.clone(), snapshot.clone());
        let interval = (cli.refresh_secs > 0 && !cli.offline).then(|| Duration::from_secs(cli.refresh_secs));
        tokio::spawn(async move {
            loop {
                if let Err(e) = refresh(&cfg, &snapshot).await {
                    // Keep serving the last edition that verified, if there is one.
                    tracing::error!("refresh failed: {e:#}");
                }
                match interval {
                    Some(i) => tokio::time::sleep(i).await,
                    None => break,
                }
            }
        })
    };

    match cli.transport {
        TransportKind::Stdio => {
            let service = ComarServer::new(snapshot).serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
        }
        TransportKind::Http => {
            let ct = tokio_util::sync::CancellationToken::new();
            let mut config = StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token());
            if !cli.allowed_hosts.is_empty() {
                config = config.with_allowed_hosts(cli.allowed_hosts.clone());
            }
            let health = snapshot.clone();
            let service = StreamableHttpService::new(
                move || Ok(ComarServer::new(snapshot.clone())),
                LocalSessionManager::default().into(),
                config,
            );
            let router = axum::Router::new()
                .nest_service("/mcp", service)
                .route(
                    "/healthz",
                    axum::routing::get(move || {
                        let ready = health.load().is_some();
                        async move {
                            if ready {
                                (axum::http::StatusCode::OK, "ok")
                            } else {
                                (axum::http::StatusCode::SERVICE_UNAVAILABLE, "verifying")
                            }
                        }
                    }),
                );
            let listener = tokio::net::TcpListener::bind(&cli.bind).await?;
            tracing::info!("listening on http://{}/mcp", cli.bind);
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    ct.cancel();
                })
                .await?;
        }
    }
    refresher.abort();
    Ok(())
}

/// Verifies the latest signed edition and, if it differs from what is being served, rebuilds
/// the index and swaps it in.
async fn refresh(cfg: &TafConfig, snapshot: &SharedSnapshot) -> Result<()> {
    let publication = taf::verify(cfg).await?;
    for w in &publication.warnings {
        tracing::warn!("{w}");
    }
    let library = match snapshot.load_full() {
        Some(current) if current.publication.content_commit == publication.content_commit => {
            current.library.clone()
        }
        _ => {
            let p = publication.clone();
            let started = std::time::Instant::now();
            let lib = tokio::task::spawn_blocking(move || comar::Library::load(&p)).await??;
            tracing::info!(
                commit = %publication.content_commit,
                regulations = lib.regulations.len(),
                elapsed = ?started.elapsed(),
                "indexed COMAR"
            );
            Arc::new(lib)
        }
    };
    snapshot.store(Some(Arc::new(Snapshot { publication, library })));
    Ok(())
}
