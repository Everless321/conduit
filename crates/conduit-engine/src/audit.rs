use chrono::Utc;

use conduit_core::models::AuditEntry;
use conduit_core::AuditSink;

#[derive(Clone)]
pub struct AuditCtx {
    pub user_id: i64,
    pub token_id: i64,
    pub server_alias: String,
    pub session_id: String,
}

/// Build an [`AuditEntry`] from `ctx` + `event`, let `build` fill in the
/// event-specific fields, then hand it to the sink (best-effort).
pub async fn log(
    sink: &dyn AuditSink,
    ctx: &AuditCtx,
    event: &str,
    build: impl FnOnce(&mut AuditEntry),
) {
    let mut e = AuditEntry {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: ctx.user_id,
        token_id: ctx.token_id,
        server_alias: ctx.server_alias.clone(),
        session_id: ctx.session_id.clone(),
        event: event.into(),
        command: None,
        stdout: None,
        stderr: None,
        exit_code: None,
        duration_ms: None,
        error: None,
        created_at: Utc::now(),
    };
    build(&mut e);
    sink.write(&e).await;
}
