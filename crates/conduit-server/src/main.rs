mod auth;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use clap::Parser;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{StreamableHttpServerConfig, StreamableHttpService};
use tracing_subscriber::EnvFilter;

use conduit_core::crypto::MasterKey;
use conduit_core::policy::CommandPolicy;
use conduit_core::{AuditSink, Authorizer, ServerCatalog, TokenValidator};
use conduit_engine::{AppState, ConduitHandler, RateLimiter};
use conduit_store_dibs::DibsStore;

use crate::auth::bearer_auth;

#[derive(Parser, Debug)]
#[command(name = "conduit-server", version)]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:7077", env = "CONDUIT_BIND")]
    bind: String,
    #[arg(long, default_value = "./conduit.db", env = "CONDUIT_DB")]
    db: String,
    #[arg(long, env = "CONDUIT_MASTER_KEY")]
    master_key: Option<String>,
    #[arg(long, default_value_t = 30, env = "CONDUIT_RATE_PER_MIN")]
    rate_per_minute: u32,
    #[arg(long, default_value_t = 1800, env = "CONDUIT_IDLE_TIMEOUT_SECS")]
    idle_timeout_secs: i64,
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
    let state = Arc::new(AppState::new(catalog, authz, audit, limiter, cli.idle_timeout_secs));

    spawn_session_cleaner(state.clone());

    let handler_state = state.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(ConduitHandler::new(handler_state.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().disable_allowed_hosts(),
    );

    let mcp_router = Router::new()
        .nest_service("/mcp", mcp_service)
        .layer(axum::middleware::from_fn_with_state(validator.clone(), bearer_auth))
        .with_state(validator.clone());

    let health_state = state.clone();
    let app = Router::new()
        .route("/healthz", get(healthz))
        .with_state(health_state)
        .merge(mcp_router);

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

fn spawn_session_cleaner(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let cutoff = state.idle_timeout_secs;
            if cutoff <= 0 {
                continue;
            }
            let mut to_close: Vec<String> = Vec::new();
            for entry in state.sessions.iter() {
                if entry.value().idle_secs() > cutoff {
                    to_close.push(entry.key().clone());
                }
            }
            for id in to_close {
                if let Some((_, sess)) = state.sessions.remove(&id) {
                    tracing::info!(session = %id, idle = sess.idle_secs(), "cleaning idle session");
                    state.stop_jobs_for_session(&sess.id);
                    sess.close().await;
                }
            }
        }
    });
}
