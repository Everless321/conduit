use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthKind {
    Password,
    Key,
    /// Private key authenticated with a CA-signed OpenSSH certificate
    /// (`*-cert.pub`). The private key lives in `secret`, the certificate
    /// text in `certificate`.
    Cert,
}

impl AuthKind {
    pub fn from_str_loose(s: &str) -> Self {
        if s.eq_ignore_ascii_case("cert") {
            AuthKind::Cert
        } else if s.eq_ignore_ascii_case("key") {
            AuthKind::Key
        } else {
            AuthKind::Password
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    /// Per-user record in an `mcp_tokens`-style table.
    UserToken,
    /// Legacy single token attached to the user row.
    Legacy,
}

/// Identity resolved from a presented MCP token by a [`crate::TokenValidator`].
/// Carries no credentials — only who the caller is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub token_id: i64,
    pub token_label: String,
    pub token_kind: TokenKind,
}

/// Metadata-only view of a server the caller may access. Returned by
/// [`crate::ServerCatalog::list`] — never includes secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSummary {
    pub alias: String,
    pub description: Option<String>,
    pub tags: Option<String>,
}

/// Fully resolved, **decrypted** connection details for one hop. Produced by
/// [`crate::ServerCatalog::resolve`]. The engine consumes this directly and
/// never touches encryption or the underlying storage — key management is the
/// adapter's concern.
#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub alias: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_kind: AuthKind,
    /// Password bytes (Password) or OpenSSH private key PEM bytes (Key, Cert).
    pub secret: Vec<u8>,
    /// Decrypted passphrase for an encrypted private key, if any.
    pub key_passphrase: Option<Vec<u8>>,
    /// CA-signed OpenSSH certificate text (`*-cert.pub` contents) for
    /// [`AuthKind::Cert`]. `None` for password/plain-key auth.
    pub certificate: Option<Vec<u8>>,
    /// Alias of the jump host to traverse before this hop, if any.
    pub jump_host_alias: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub user_id: i64,
    pub token_id: i64,
    pub server_alias: String,
    pub session_id: String,
    pub event: String,
    pub command: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i64>,
    pub duration_ms: Option<i64>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Filter passed to [`crate::AuditSink::query`].
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub user_id: Option<i64>,
    pub server: Option<String>,
    pub session_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub limit: i64,
}
