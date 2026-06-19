//! Dibs-backed SQLite adapter. Implements [`TokenValidator`], [`ServerCatalog`]
//! and [`AuditSink`] against the Dibs schema (`users`, `mcp_tokens`, `servers`,
//! `server_user_permissions`) plus its own `conduit_audit` table. This is the
//! swappable piece: to back conduit with a different inventory/permission/auth
//! source, write another crate implementing these same traits.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

use conduit_core::crypto::{sha256_hex, MasterKey};
use conduit_core::models::{
    AuditEntry, AuditQuery, AuthContext, AuthKind, ResolvedServer, ServerSummary, TokenKind,
};
use conduit_core::{AuditSink, Error, Result, ServerCatalog, TokenValidator};

const AUDIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS conduit_audit (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_id INTEGER NOT NULL,
    server_alias TEXT NOT NULL,
    session_id TEXT NOT NULL,
    event TEXT NOT NULL,
    command TEXT,
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    duration_ms INTEGER,
    error TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conduit_audit_session ON conduit_audit(session_id);
CREATE INDEX IF NOT EXISTS idx_conduit_audit_user ON conduit_audit(user_id);
"#;

/// Map a backend (sqlx) error into the storage-agnostic core error.
trait DbExt<T> {
    fn db(self) -> Result<T>;
}
impl<T> DbExt<T> for std::result::Result<T, sqlx::Error> {
    fn db(self) -> Result<T> {
        self.map_err(|e| Error::Db(e.to_string()))
    }
}

#[derive(Clone)]
pub struct DibsStore {
    pool: SqlitePool,
    key: MasterKey,
}

impl DibsStore {
    pub async fn open(path: impl AsRef<Path>, key: MasterKey) -> Result<Self> {
        let path = path.as_ref();
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|e| Error::Other(anyhow::anyhow!(e)))?
            .create_if_missing(false)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await
            .db()?;
        sqlx::query(AUDIT_SCHEMA).execute(&pool).await.db()?;
        // Conduit owns OpenSSH certificate support end-to-end; add the column
        // on its own so no external schema coordination is required. The ALTER
        // is non-destructive and idempotent — a "duplicate column" error just
        // means it already exists, so we ignore failures here.
        let _ = sqlx::query("ALTER TABLE servers ADD COLUMN certificate_enc BLOB")
            .execute(&pool)
            .await;
        Ok(Self { pool, key })
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.key
    }
}

#[async_trait]
impl TokenValidator for DibsStore {
    /// Resolve `Bearer <token>` against Dibs `mcp_tokens` (preferred) then legacy
    /// `users.mcp_token_hash` as a fallback.
    async fn validate(&self, presented: &str) -> Result<AuthContext> {
        let presented = presented.trim();
        if presented.is_empty() {
            return Err(Error::Unauthorized("empty token".into()));
        }
        let hash = sha256_hex(presented);

        // 1) preferred: mcp_tokens table (per-user multiple keys)
        let row: Option<McpTokenRow> = sqlx::query_as(
            "SELECT t.id, t.user_id, t.label, u.username, u.role, u.active
             FROM mcp_tokens t
             JOIN users u ON u.id = t.user_id
             WHERE t.token_hash = ?
               AND t.revoked_at IS NULL
               AND u.active = 1
             LIMIT 1",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .or_else(|e| {
            // Dibs may not have created mcp_tokens yet; fall through to legacy
            tracing::debug!(?e, "mcp_tokens lookup failed, will try legacy");
            Ok::<_, sqlx::Error>(None)
        })
        .db()?;
        if let Some(r) = row {
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query("UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?")
                .bind(&now)
                .bind(r.id)
                .execute(&self.pool)
                .await;
            return Ok(AuthContext {
                user_id: r.user_id,
                username: r.username,
                role: r.role,
                token_id: r.id,
                token_label: r.label,
                token_kind: TokenKind::UserToken,
            });
        }

        // 2) legacy: users.mcp_token_hash (single token per user)
        let legacy: Option<(i64, String, String, i64)> = sqlx::query_as(
            "SELECT id, username, role, active FROM users
             WHERE mcp_token_hash = ? AND active = 1 LIMIT 1",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .db()?;
        if let Some((id, username, role, _active)) = legacy {
            return Ok(AuthContext {
                user_id: id,
                username,
                role,
                token_id: 0,
                token_label: "legacy".into(),
                token_kind: TokenKind::Legacy,
            });
        }

        Err(Error::Unauthorized("invalid or revoked token".into()))
    }
}

#[async_trait]
impl ServerCatalog for DibsStore {
    /// Servers the user is granted access to via `server_user_permissions`.
    async fn list(&self, user_id: i64) -> Result<Vec<ServerSummary>> {
        let rows: Vec<SummaryRow> = sqlx::query_as(
            "SELECT s.alias, s.description, s.tags
             FROM servers s
             JOIN server_user_permissions p ON p.server_id = s.id
             WHERE p.user_id = ?
             ORDER BY s.alias",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .db()?;
        Ok(rows
            .into_iter()
            .map(|r| ServerSummary { alias: r.alias, description: r.description, tags: r.tags })
            .collect())
    }

    /// One server by alias, restricted to those the user may access, returned
    /// with secrets already decrypted.
    async fn resolve(&self, user_id: i64, alias: &str) -> Result<ResolvedServer> {
        let row: Option<ServerRow> = sqlx::query_as(
            "SELECT s.alias, s.host, s.port, s.username, s.auth_kind, s.secret_enc, s.key_passphrase_enc, s.certificate_enc, s.jump_host_alias
             FROM servers s
             JOIN server_user_permissions p ON p.server_id = s.id
             WHERE p.user_id = ? AND s.alias = ?
             LIMIT 1",
        )
        .bind(user_id)
        .bind(alias)
        .fetch_optional(&self.pool)
        .await
        .db()?;
        let row = row
            .ok_or_else(|| Error::NotFound(format!("server {alias} (no permission or not found)")))?;

        let secret = self.key.decrypt(&row.secret_enc)?;
        let key_passphrase = row
            .key_passphrase_enc
            .as_deref()
            .map(|b| self.key.decrypt(b))
            .transpose()?;
        let certificate = row
            .certificate_enc
            .as_deref()
            .map(|b| self.key.decrypt(b))
            .transpose()?;

        Ok(ResolvedServer {
            alias: row.alias,
            host: row.host,
            port: row.port as u16,
            username: row.username,
            auth_kind: AuthKind::from_str_loose(&row.auth_kind),
            secret,
            key_passphrase,
            certificate,
            jump_host_alias: row.jump_host_alias,
        })
    }
}

#[async_trait]
impl AuditSink for DibsStore {
    async fn write(&self, e: &AuditEntry) {
        let res = sqlx::query(
            "INSERT INTO conduit_audit(id,user_id,token_id,server_alias,session_id,event,command,stdout,stderr,exit_code,duration_ms,error,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&e.id)
        .bind(e.user_id)
        .bind(e.token_id)
        .bind(&e.server_alias)
        .bind(&e.session_id)
        .bind(&e.event)
        .bind(e.command.as_deref())
        .bind(e.stdout.as_deref())
        .bind(e.stderr.as_deref())
        .bind(e.exit_code)
        .bind(e.duration_ms)
        .bind(e.error.as_deref())
        .bind(e.created_at.to_rfc3339())
        .execute(&self.pool)
        .await;
        if let Err(err) = res {
            tracing::warn!(?err, "audit write failed");
        }
    }

    async fn query(&self, q: &AuditQuery) -> Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            "SELECT id,user_id,token_id,server_alias,session_id,event,command,stdout,stderr,exit_code,duration_ms,error,created_at FROM conduit_audit WHERE 1=1",
        );
        if q.user_id.is_some() { sql.push_str(" AND user_id=?"); }
        if q.server.is_some() { sql.push_str(" AND server_alias=?"); }
        if q.session_id.is_some() { sql.push_str(" AND session_id=?"); }
        if q.since.is_some() { sql.push_str(" AND created_at>=?"); }
        sql.push_str(" ORDER BY created_at DESC LIMIT ?");

        let mut query = sqlx::query_as::<_, AuditRow>(&sql);
        if let Some(u) = q.user_id { query = query.bind(u); }
        if let Some(s) = &q.server { query = query.bind(s.clone()); }
        if let Some(s) = &q.session_id { query = query.bind(s.clone()); }
        if let Some(t) = q.since { query = query.bind(t.to_rfc3339()); }
        query = query.bind(q.limit);

        let rows = query.fetch_all(&self.pool).await.db()?;
        Ok(rows.into_iter().map(AuditRow::into_entry).collect())
    }
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    alias: String,
    description: Option<String>,
    tags: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ServerRow {
    alias: String,
    host: String,
    port: i64,
    username: String,
    auth_kind: String,
    secret_enc: Vec<u8>,
    key_passphrase_enc: Option<Vec<u8>>,
    certificate_enc: Option<Vec<u8>>,
    jump_host_alias: Option<String>,
}

#[derive(sqlx::FromRow)]
struct McpTokenRow {
    id: i64,
    user_id: i64,
    label: String,
    username: String,
    role: String,
    #[allow(dead_code)]
    active: i64,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    user_id: i64,
    token_id: i64,
    server_alias: String,
    session_id: String,
    event: String,
    command: Option<String>,
    stdout: Option<String>,
    stderr: Option<String>,
    exit_code: Option<i64>,
    duration_ms: Option<i64>,
    error: Option<String>,
    created_at: String,
}

impl AuditRow {
    fn into_entry(self) -> AuditEntry {
        AuditEntry {
            id: self.id,
            user_id: self.user_id,
            token_id: self.token_id,
            server_alias: self.server_alias,
            session_id: self.session_id,
            event: self.event,
            command: self.command,
            stdout: self.stdout,
            stderr: self.stderr,
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            error: self.error,
            created_at: parse_ts(&self.created_at),
        }
    }
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
