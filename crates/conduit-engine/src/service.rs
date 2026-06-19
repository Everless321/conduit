//! Embeddable HTTP surface. A host application wires its own adapters into an
//! [`AppState`], then mounts [`mcp_router`] into its own `axum` app and serves
//! it on a listener **it** controls — conduit-engine never binds a socket or
//! decides a port. See the crate-level docs for an embedding example.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
    Router,
};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};

use conduit_core::models::AuthContext;
use conduit_core::TokenValidator;

use crate::state::AppState;
use crate::tools::ConduitHandler;

/// Bearer-token middleware. Delegates token validation to whichever
/// [`TokenValidator`] adapter is wired in, and stashes the resolved
/// [`AuthContext`] in request extensions for the MCP tools to read.
pub async fn bearer_auth(
    axum::extract::State(validator): axum::extract::State<Arc<dyn TokenValidator>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .trim();
    let ctx: AuthContext = validator
        .validate(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}

/// Build a self-contained, mountable router exposing the MCP tool surface at
/// `/mcp`, gated by [`bearer_auth`] against `validator`. The returned
/// `Router<()>` carries no outstanding state, so a host app can `merge` it into
/// its own router and serve it however it likes:
///
/// ```ignore
/// let state = Arc::new(AppState::new(catalog, authz, audit, limiter, idle));
/// conduit_engine::spawn_session_cleaner(state.clone());
/// let app = my_router.merge(conduit_engine::mcp_router(state, validator));
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:7077").await?;
/// axum::serve(listener, app).await?;
/// ```
///
/// Network exposure (bind address, TLS) and HTTP `Host`/origin validation are
/// the host application's responsibility — typically a reverse proxy or the
/// host's own bind config. The MCP endpoint here is already gated by a bearer
/// token, so it carries no ambient authority.
pub fn mcp_router(state: Arc<AppState>, validator: Arc<dyn TokenValidator>) -> Router {
    let handler_state = state;
    let mcp_service = StreamableHttpService::new(
        move || Ok(ConduitHandler::new(handler_state.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default().disable_allowed_hosts(),
    );
    Router::new()
        .nest_service("/mcp", mcp_service)
        .layer(axum::middleware::from_fn_with_state(validator.clone(), bearer_auth))
        .with_state(validator)
}

/// Spawn the background reaper that closes idle SSH sessions (and stops their
/// background jobs) once they exceed `state.idle_timeout_secs`. Call once after
/// building [`AppState`]; a non-positive timeout disables reaping.
pub fn spawn_session_cleaner(state: Arc<AppState>) {
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
