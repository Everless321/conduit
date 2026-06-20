//! The pluggable seams. Implement these in an adapter crate and wire them into
//! the engine at assembly time (`conduit-server`'s `main`). To swap permission
//! logic or the server inventory, ship a new impl of [`ServerCatalog`] /
//! [`Authorizer`] — the engine is untouched.

use async_trait::async_trait;

use crate::models::{AuditEntry, AuditQuery, AuthContext, ResolvedServer, ServerSummary};
use crate::Result;

/// Which call produced the output being filtered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStream {
    /// A one-shot `exec` result: complete stdout/stderr plus a final exit code.
    Exec,
    /// One incremental chunk from polling a background job (`exec_poll`). The
    /// filter is invoked once per poll, so a transform that could straddle a
    /// chunk boundary (e.g. a secret split across two reads) is not guaranteed
    /// to match — keep poll-chunk filters line- or byte-local.
    PollChunk,
}

/// Who and what produced the output, passed to [`OutputFilter::filter`].
pub struct OutputContext<'a> {
    pub auth: &'a AuthContext,
    pub server_alias: &'a str,
    /// The command that produced this output.
    pub command: &'a str,
    pub stream: OutputStream,
}

/// The mutable captured output handed to an [`OutputFilter`]. Rewrite the
/// fields in place to redact, filter, or rewrite what the caller receives.
pub struct CapturedOutput {
    pub stdout: String,
    pub stderr: String,
    /// Final exit code: `Some` for a completed `exec`, `None` for a poll chunk
    /// of a still-running job. A filter may override it.
    pub exit_code: Option<i32>,
}

/// Post-execution transform applied to SSH output just before it is returned to
/// the MCP caller (the fifth seam, alongside [`TokenValidator`], [`ServerCatalog`],
/// [`Authorizer`], and [`AuditSink`]). Deployments install none by default
/// (passthrough); wire one at assembly time with `AppState::with_output_filter`.
///
/// Note the audit trail records the **raw** output, not the filtered result —
/// the filter only shapes the caller-facing response. If you also need to keep
/// secrets out of the audit log, redact in your [`AuditSink`] implementation.
#[async_trait]
pub trait OutputFilter: Send + Sync {
    async fn filter(&self, ctx: &OutputContext<'_>, out: &mut CapturedOutput);
}

/// Resolves a presented MCP bearer token into an [`AuthContext`] (authentication).
#[async_trait]
pub trait TokenValidator: Send + Sync {
    async fn validate(&self, token: &str) -> Result<AuthContext>;
}

/// Provides the server inventory the caller is permitted to use (server
/// management + access control). The implementation is expected to enforce
/// per-user visibility itself — `list`/`resolve` only ever return servers the
/// `user_id` may access.
#[async_trait]
pub trait ServerCatalog: Send + Sync {
    async fn list(&self, user_id: i64) -> Result<Vec<ServerSummary>>;
    /// Resolve one alias to decrypted connection details, or `NotFound` if the
    /// user has no access / it does not exist.
    async fn resolve(&self, user_id: i64, alias: &str) -> Result<ResolvedServer>;
}

/// Command-level authorization (the blacklist / allow rules). Returns `Ok(())`
/// to permit, or `Forbidden` to block. Receives the caller and target so richer
/// policies (per-role, per-server) can be plugged in.
#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize_exec(
        &self,
        auth: &AuthContext,
        server_alias: &str,
        command: &str,
    ) -> Result<()>;
}

/// Sink for audit events. `write` is best-effort and must not fail the caller —
/// implementations log internally on error.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn write(&self, entry: &AuditEntry);
    async fn query(&self, q: &AuditQuery) -> Result<Vec<AuditEntry>>;
}
