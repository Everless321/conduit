//! The pluggable seams. Implement these in an adapter crate and wire them into
//! the engine at assembly time (`conduit-server`'s `main`). To swap permission
//! logic or the server inventory, ship a new impl of [`ServerCatalog`] /
//! [`Authorizer`] — the engine is untouched.

use async_trait::async_trait;

use crate::models::{AuditEntry, AuditQuery, AuthContext, ResolvedServer, ServerSummary};
use crate::Result;

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
