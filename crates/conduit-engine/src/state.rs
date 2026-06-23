use std::sync::Arc;

use dashmap::DashMap;

use conduit_core::{AuditSink, Authorizer, OutputFilter, ServerCatalog};

use crate::ingest::{IngestStore, DEFAULT_INGEST_TTL_SECS, DEFAULT_MAX_UPLOAD_BYTES};
use crate::ratelimit::RateLimiter;
use crate::session::{BgJob, SshSession, MAX_OUTPUT_BYTES};

/// Shared engine state. Holds the pluggable adapters as trait objects — the
/// engine is blind to which concrete backend provides them.
#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<dyn ServerCatalog>,
    pub authz: Arc<dyn Authorizer>,
    pub audit: Arc<dyn AuditSink>,
    pub sessions: Arc<DashMap<String, Arc<SshSession>>>,
    /// Background exec jobs, keyed by job id (see `exec_start`/`exec_poll`).
    pub jobs: Arc<DashMap<String, Arc<BgJob>>>,
    pub limiter: Arc<RateLimiter>,
    pub idle_timeout_secs: i64,
    /// Hard cap on bytes returned by `sftp_download`. A caller's `max_bytes`
    /// is clamped to this; defaults to [`MAX_OUTPUT_BYTES`] (1MB). Override
    /// with [`AppState::with_max_download_bytes`].
    pub max_download_bytes: usize,
    /// Optional post-execution transform on SSH output. `None` = passthrough.
    /// Install with [`AppState::with_output_filter`].
    pub output_filter: Option<Arc<dyn OutputFilter>>,
    /// Out-of-band staging for `sftp_upload`. Bytes arrive via `POST /ingest`
    /// (see [`crate::ingest_router`]) and are consumed by handle. Override the
    /// dir and size cap with [`AppState::with_ingest_config`].
    pub ingest: Arc<IngestStore>,
}

impl AppState {
    /// Stop and drop every background job belonging to a session. Called when
    /// the session is closed or reaped so jobs never outlive their channel.
    pub fn stop_jobs_for_session(&self, session_id: &str) {
        let ids: Vec<String> = self
            .jobs
            .iter()
            .filter(|e| e.value().session_id == session_id)
            .map(|e| e.key().clone())
            .collect();
        for id in ids {
            if let Some((_, job)) = self.jobs.remove(&id) {
                job.stop();
            }
        }
    }
}

impl AppState {
    pub fn new(
        catalog: Arc<dyn ServerCatalog>,
        authz: Arc<dyn Authorizer>,
        audit: Arc<dyn AuditSink>,
        limiter: RateLimiter,
        idle_timeout_secs: i64,
    ) -> Self {
        Self {
            catalog,
            authz,
            audit,
            sessions: Arc::new(DashMap::new()),
            jobs: Arc::new(DashMap::new()),
            limiter: Arc::new(limiter),
            idle_timeout_secs,
            max_download_bytes: MAX_OUTPUT_BYTES,
            output_filter: None,
            ingest: Arc::new(IngestStore::new(
                std::env::temp_dir().join("conduit-ingest"),
                DEFAULT_MAX_UPLOAD_BYTES,
                DEFAULT_INGEST_TTL_SECS,
            )),
        }
    }

    /// Override where `POST /ingest` stages uploaded bytes and the per-upload
    /// size cap (default 16MB). Chain it onto `new` at assembly time:
    /// `AppState::new(..).with_ingest_config(dir, 64 << 20)`.
    pub fn with_ingest_config(mut self, dir: std::path::PathBuf, max_bytes: usize) -> Self {
        self.ingest = Arc::new(IngestStore::new(dir, max_bytes, DEFAULT_INGEST_TTL_SECS));
        self
    }

    /// Override the `sftp_download` byte cap (default 1MB). Chain it onto `new`
    /// at assembly time: `AppState::new(..).with_max_download_bytes(50 << 20)`.
    pub fn with_max_download_bytes(mut self, max_bytes: usize) -> Self {
        self.max_download_bytes = max_bytes;
        self
    }

    /// Install an [`OutputFilter`] that rewrites SSH output before it is returned
    /// to the caller. Chain it onto `new` at assembly time:
    /// `Arc::new(AppState::new(..).with_output_filter(Arc::new(MyFilter)))`.
    pub fn with_output_filter(mut self, filter: Arc<dyn OutputFilter>) -> Self {
        self.output_filter = Some(filter);
        self
    }
}
