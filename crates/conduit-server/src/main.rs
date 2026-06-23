//! Reference deployment of conduit-engine: a standalone binary wiring the
//! Dibs adapters and serving the MCP router over HTTP. Embedders should depend
//! on `conduit-engine` directly and mount [`conduit_engine::mcp_router`] into
//! their own app instead of running this binary.

use std::sync::Arc;

use anyhow::Context;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use conduit_core::crypto::MasterKey;
use conduit_core::policy::CommandPolicy;
use conduit_core::{AuditSink, Authorizer, ServerCatalog, TokenValidator};
use conduit_engine::{ingest_router, mcp_router, spawn_session_cleaner, AppState, RateLimiter};
use conduit_store_dibs::DibsStore;

#[derive(Parser, Debug)]
#[command(name = "conduit-server", version)]
struct Cli {
    /// Bind address. Defaults to localhost only; set explicitly (e.g.
    /// `0.0.0.0:7077`) or front it with a reverse proxy to expose it.
    #[arg(long, default_value = "127.0.0.1:7077", env = "CONDUIT_BIND")]
    bind: String,
    #[arg(long, default_value = "./conduit.db", env = "CONDUIT_DB")]
    db: String,
    #[arg(long, env = "CONDUIT_MASTER_KEY")]
    master_key: Option<String>,
    #[arg(long, default_value_t = 30, env = "CONDUIT_RATE_PER_MIN")]
    rate_per_minute: u32,
    #[arg(long, default_value_t = 1800, env = "CONDUIT_IDLE_TIMEOUT_SECS")]
    idle_timeout_secs: i64,
    /// Hard cap on bytes returned by sftp_download. Defaults to 1MB.
    #[arg(long, default_value_t = 1_048_576, env = "CONDUIT_MAX_DOWNLOAD_BYTES")]
    max_download_bytes: usize,
    /// Hard cap on bytes accepted by a single POST /ingest upload. Defaults to 16MB.
    #[arg(long, default_value_t = 16 << 20, env = "CONDUIT_MAX_UPLOAD_BYTES")]
    max_upload_bytes: usize,
    /// Directory where POST /ingest stages uploaded bytes. Defaults to a
    /// `conduit-ingest` subdir of the system temp dir.
    #[arg(long, env = "CONDUIT_INGEST_DIR")]
    ingest_dir: Option<String>,
    #[arg(long, env = "CONDUIT_BLACKLIST_FILE")]
    blacklist_file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let cli = Cli::parse();

    let key = match cli.master_key {
        Some(s) => MasterKey::from_hex(&s).context("invalid CONDUIT_MASTER_KEY")?,
        None => MasterKey::from_env("CONDUIT_MASTER_KEY").context("CONDUIT_MASTER_KEY not set")?,
    };

    // --- Adapter wiring: this is the only place that names a concrete backend.
    // Swap DibsStore / CommandPolicy here to plug in a different inventory,
    // permission model, auth source, or audit sink.
    let dibs = Arc::new(DibsStore::open(&cli.db, key).await.context("open store")?);

    let extra_patterns: Vec<String> = match &cli.blacklist_file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("read blacklist file {path}"))?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect(),
        None => Vec::new(),
    };
    let authz: Arc<dyn Authorizer> =
        Arc::new(CommandPolicy::new(extra_patterns).context("compile policy")?);

    let validator: Arc<dyn TokenValidator> = dibs.clone();
    let catalog: Arc<dyn ServerCatalog> = dibs.clone();
    let audit: Arc<dyn AuditSink> = dibs.clone();
    // --- end wiring

    let limiter = RateLimiter::new(cli.rate_per_minute);
    let ingest_dir = cli
        .ingest_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("conduit-ingest"));
    let state = Arc::new(
        AppState::new(catalog, authz, audit, limiter, cli.idle_timeout_secs)
            .with_max_download_bytes(cli.max_download_bytes)
            .with_ingest_config(ingest_dir, cli.max_upload_bytes),
    );

    spawn_session_cleaner(state.clone());

    let app = Router::new()
        .route("/healthz", get(healthz))
        .with_state(state.clone())
        .merge(mcp_router(state.clone(), validator.clone()))
        .merge(ingest_router(state.clone(), validator.clone()));

    let listener = tokio::net::TcpListener::bind(&cli.bind).await.context("bind")?;
    tracing::info!(addr = %cli.bind, "conduit-server listening");
    axum::serve(listener, app).await.context("serve")?;
    Ok(())
}

#[derive(serde::Serialize)]
struct HealthOutput {
    status: &'static str,
    version: &'static str,
    active_sessions: usize,
}

async fn healthz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthOutput {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            active_sessions: state.sessions.len(),
        }),
    )
}
