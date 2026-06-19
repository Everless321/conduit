//! conduit-engine: the reusable SSH-over-MCP core. It owns SSH session
//! lifecycle, the MCP tool surface (`list_servers`, `open_channel`, `exec`,
//! `exec_start`/`exec_poll`/`exec_stop`, `sftp_*`, `close_channel`), rate
//! limiting and audit emission — and depends ONLY on the trait ports in
//! `conduit-core`. It has no knowledge of SQLite, Dibs, or any concrete
//! storage. Wire it to adapters at assembly time.
//!
//! # Embedding
//!
//! This crate is designed to be embedded as middleware: a host application
//! supplies the four [`conduit_core`] adapters (`ServerCatalog`, `Authorizer`,
//! `AuditSink`, `TokenValidator`), then mounts the MCP router into its own
//! `axum` app and owns the listener/bind itself. conduit-engine never binds a
//! socket or picks a port.
//!
//! ```ignore
//! use std::sync::Arc;
//! use conduit_engine::{AppState, RateLimiter, mcp_router, spawn_session_cleaner};
//!
//! let state = Arc::new(AppState::new(catalog, authz, audit, RateLimiter::new(30), 1800));
//! spawn_session_cleaner(state.clone());
//!
//! // Mount into the host's own router; the host decides the bind address.
//! let app = host_router.merge(mcp_router(state, validator));
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:7077").await?;
//! axum::serve(listener, app).await?;
//! ```

pub mod audit;
pub mod ratelimit;
pub mod service;
pub mod session;
pub mod state;
pub mod tools;

pub use ratelimit::RateLimiter;
pub use service::{bearer_auth, mcp_router, spawn_session_cleaner};
pub use state::AppState;
pub use tools::ConduitHandler;
