//! Out-of-band file ingest. `sftp_upload` does not carry file bytes through the
//! MCP tool call — that would force the model to emit the whole file as base64.
//! Instead the client streams raw bytes to `POST /ingest` (a plain HTTP upload,
//! gated by the same bearer token as the MCP surface), receives a small opaque
//! `handle`, and passes that handle to `sftp_upload`. The bytes never enter the
//! model's token stream.
//!
//! Staged bytes live on disk (one temp file per handle) so large uploads don't
//! sit in RAM, and are consumed once: `sftp_upload` takes the handle, reads the
//! file, pushes it over SFTP, and the temp file is removed. Orphaned handles
//! (uploaded but never consumed) are reaped by TTL via the session cleaner.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    middleware::from_fn_with_state,
    routing::post,
    Extension, Json, Router,
};
use dashmap::DashMap;
use serde::Serialize;

use conduit_core::models::AuthContext;
use conduit_core::TokenValidator;

use crate::service::bearer_auth;
use crate::state::AppState;

/// Default cap on a single ingested upload (16MB).
pub const DEFAULT_MAX_UPLOAD_BYTES: usize = 16 << 20;
/// Default lifetime of an unconsumed staged upload before it is reaped.
pub const DEFAULT_INGEST_TTL_SECS: u64 = 3600;

/// A failure resolving an `upload_handle`. Deliberately opaque about whether a
/// handle exists when it belongs to another token.
#[derive(Debug)]
pub enum IngestError {
    /// No live handle by that name (never staged, already consumed, or expired).
    NotFound,
    /// Handle exists but was staged by a different token's user.
    Forbidden,
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::NotFound => f.write_str("unknown or expired upload_handle"),
            IngestError::Forbidden => f.write_str("upload_handle does not belong to token"),
        }
    }
}

impl std::error::Error for IngestError {}

/// One staged upload: bytes on disk plus the owner and an age clock for TTL.
/// Dropping it removes the backing temp file, so taking a handle out of the
/// store (or reaping it) cleans up automatically.
pub struct Staged {
    pub path: PathBuf,
    pub size: usize,
    pub user_id: i64,
    created: Instant,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Registry of staged uploads. Bytes are written under `dir`; the in-memory map
/// holds only small metadata keyed by handle.
pub struct IngestStore {
    dir: PathBuf,
    pub max_bytes: usize,
    ttl_secs: u64,
    entries: DashMap<String, Staged>,
}

impl IngestStore {
    pub fn new(dir: PathBuf, max_bytes: usize, ttl_secs: u64) -> Self {
        Self { dir, max_bytes, ttl_secs, entries: DashMap::new() }
    }

    /// Write `bytes` to a fresh temp file and register a handle owned by
    /// `user_id`. Returns the opaque handle the client passes to `sftp_upload`.
    /// Staged files can hold secrets (config, keys), so the dir is locked to
    /// `0700` and each file created `0600` on Unix.
    pub async fn stage(&self, bytes: &[u8], user_id: i64) -> std::io::Result<String> {
        self.ensure_dir().await?;
        let handle = format!("up_{}", uuid::Uuid::new_v4().simple());
        let path = self.dir.join(&handle);
        write_private(&path, bytes).await?;
        self.entries.insert(
            handle.clone(),
            Staged { path, size: bytes.len(), user_id, created: Instant::now() },
        );
        Ok(handle)
    }

    /// Ensure the staging dir exists and is owner-only (`0700`). Tightens the
    /// mode even if the dir pre-existed (e.g. an operator-supplied `--ingest-dir`).
    async fn ensure_dir(&self) -> std::io::Result<()> {
        tokio::fs::create_dir_all(&self.dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700)).await?;
        }
        Ok(())
    }

    /// Remove and return a handle's staged bytes, enforcing ownership. The
    /// caller reads `path` then drops the [`Staged`], which deletes the file.
    pub fn take(&self, handle: &str, user_id: i64) -> Result<Staged, IngestError> {
        match self.entries.get(handle) {
            None => return Err(IngestError::NotFound),
            Some(e) if e.user_id != user_id => return Err(IngestError::Forbidden),
            Some(_) => {}
        }
        self.entries
            .remove(handle)
            .map(|(_, s)| s)
            .ok_or(IngestError::NotFound)
    }

    /// Drop staged uploads older than the configured TTL. Dropping each entry
    /// removes its temp file. Called periodically by the session cleaner.
    pub fn sweep_expired(&self) {
        let ttl = Duration::from_secs(self.ttl_secs);
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.value().created.elapsed() > ttl)
            .map(|e| e.key().clone())
            .collect();
        for h in expired {
            if let Some((_, s)) = self.entries.remove(&h) {
                tracing::info!(handle = %h, size = s.size, "reaping expired upload");
            }
        }
    }
}

/// Create `path` exclusively (`O_EXCL`, so a pre-existing file or symlink is
/// never followed/clobbered) and, on Unix, with mode `0600`, then write `bytes`.
async fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).await?;
    f.write_all(bytes).await?;
    f.flush().await?;
    Ok(())
}

#[derive(Serialize)]
struct IngestResponse {
    handle: String,
    size: usize,
}

async fn ingest_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: Body,
) -> Result<Json<IngestResponse>, (StatusCode, String)> {
    let store = &state.ingest;
    let bytes = axum::body::to_bytes(body, store.max_bytes).await.map_err(|_| {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("upload exceeds max of {} bytes", store.max_bytes),
        )
    })?;
    let size = bytes.len();
    let handle = store
        .stage(&bytes, auth.user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("stage upload: {e}")))?;
    Ok(Json(IngestResponse { handle, size }))
}

/// Build a mountable router exposing `POST /ingest`, gated by [`bearer_auth`]
/// against `validator` — the same token surface as [`crate::mcp_router`]. Merge
/// it into the host app's router alongside the MCP router:
///
/// ```ignore
/// let app = my_router
///     .merge(conduit_engine::mcp_router(state.clone(), validator.clone()))
///     .merge(conduit_engine::ingest_router(state, validator));
/// ```
pub fn ingest_router(state: Arc<AppState>, validator: Arc<dyn TokenValidator>) -> Router {
    Router::new()
        .route("/ingest", post(ingest_handler))
        .layer(from_fn_with_state(validator, bearer_auth))
        .with_state(state)
}
