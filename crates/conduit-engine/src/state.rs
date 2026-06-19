use std::sync::Arc;

use dashmap::DashMap;

use conduit_core::{AuditSink, Authorizer, ServerCatalog};

use crate::ratelimit::RateLimiter;
use crate::session::{BgJob, SshSession};

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
        }
    }
}
