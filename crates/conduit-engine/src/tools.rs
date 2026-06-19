use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Implementation, ServerCapabilities, ServerInfo};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData, RoleServer, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use conduit_core::models::{AuthContext, ResolvedServer};

use crate::audit::{log, AuditCtx};
use crate::session::{DirEntry, SshSession, DEFAULT_JOB_MAX_SECS, MAX_JOBS_PER_SESSION, MAX_JUMP_HOPS};
use crate::state::AppState;

type McpError = ErrorData;

#[derive(Deserialize, JsonSchema, Default)]
pub struct OpenChannelParams {
    #[schemars(description = "Server alias as registered by the operator (use list_servers to discover)")]
    pub server: String,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct ExecParams {
    #[schemars(description = "Session id returned by open_channel")]
    pub session_id: String,
    #[schemars(description = "Shell command to execute on the remote host")]
    pub command: String,
    #[schemars(description = "Per-command timeout in seconds (default 60, max 600)")]
    pub timeout_secs: Option<u64>,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct CloseChannelParams {
    pub session_id: String,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct SftpListParams {
    pub session_id: String,
    #[schemars(description = "Absolute remote directory path")]
    pub path: String,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct SftpDownloadParams {
    pub session_id: String,
    #[schemars(description = "Absolute remote file path")]
    pub path: String,
    #[schemars(description = "Maximum bytes to read (default 1048576, hard cap 1MB)")]
    pub max_bytes: Option<u64>,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct SftpUploadParams {
    pub session_id: String,
    #[schemars(description = "Absolute remote file path; existing file is truncated")]
    pub path: String,
    #[schemars(description = "Base64-encoded file content")]
    pub content_base64: String,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct ExecStartParams {
    #[schemars(description = "Session id returned by open_channel")]
    pub session_id: String,
    #[schemars(description = "Long-running command to start in the background (e.g. 'docker logs -f web', 'top -b -d 5', 'tail -f /var/log/app.log')")]
    pub command: String,
    #[schemars(description = "Max wall-clock seconds before the job is auto-stopped (default 1800, max 86400)")]
    pub max_runtime_secs: Option<u64>,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct ExecPollParams {
    #[schemars(description = "Job id returned by exec_start")]
    pub job_id: String,
    #[schemars(description = "Resume reading stdout from this absolute offset (use stdout_offset from the previous poll; default 0)")]
    pub stdout_offset: Option<u64>,
    #[schemars(description = "Resume reading stderr from this absolute offset (default 0)")]
    pub stderr_offset: Option<u64>,
}

#[derive(Deserialize, JsonSchema, Default)]
pub struct ExecStopParams {
    #[schemars(description = "Job id returned by exec_start")]
    pub job_id: String,
}

#[derive(Serialize, JsonSchema)]
pub struct ExecStartOutput {
    pub job_id: String,
    pub session_id: String,
    pub started_at: String,
}

#[derive(Serialize, JsonSchema)]
pub struct ExecPollOutput {
    pub stdout: String,
    pub stderr: String,
    #[schemars(description = "Pass this back as stdout_offset on the next poll")]
    pub stdout_offset: u64,
    #[schemars(description = "Pass this back as stderr_offset on the next poll")]
    pub stderr_offset: u64,
    #[schemars(description = "True if stdout output was dropped before this offset (poll more frequently)")]
    pub stdout_gap: bool,
    pub stderr_gap: bool,
    #[schemars(description = "True while the command is still running")]
    pub running: bool,
    pub exit_code: Option<i32>,
}

#[derive(Serialize, JsonSchema)]
pub struct ExecStopOutput {
    pub stopped: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct ServerEntry {
    pub alias: String,
    pub description: Option<String>,
    pub tags: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct ListServersOutput {
    pub servers: Vec<ServerEntry>,
}

#[derive(Serialize, JsonSchema)]
pub struct OpenChannelOutput {
    pub session_id: String,
    pub server: String,
    pub opened_at: String,
    pub hop_path: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: i64,
    pub truncated: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct CloseOutput {
    pub closed: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct SftpListOutput {
    pub entries: Vec<DirEntry>,
}

#[derive(Serialize, JsonSchema)]
pub struct SftpDownloadOutput {
    pub content_base64: String,
    pub size: usize,
    pub truncated: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct SftpUploadOutput {
    pub bytes_written: usize,
}

#[derive(Clone)]
pub struct ConduitHandler {
    state: Arc<AppState>,
    #[allow(dead_code)]
    tool_router: ToolRouter<ConduitHandler>,
}

impl ConduitHandler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { tool_router: Self::tool_router(), state }
    }

    fn auth(&self, ctx: &RequestContext<RoleServer>) -> Result<AuthContext, McpError> {
        let parts = ctx
            .extensions
            .get::<http::request::Parts>()
            .ok_or_else(|| McpError::internal_error("missing http parts", None))?;
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .ok_or_else(|| McpError::invalid_request("missing auth context", None))
    }

    fn session_for(
        &self,
        session_id: &str,
        auth: &AuthContext,
    ) -> Result<Arc<SshSession>, McpError> {
        let s = self
            .state
            .sessions
            .get(session_id)
            .map(|s| s.clone())
            .ok_or_else(|| McpError::invalid_request("unknown session_id", None))?;
        if s.user_id != auth.user_id {
            return Err(McpError::invalid_request("session does not belong to token", None));
        }
        Ok(s)
    }

    fn audit_ctx(auth: &AuthContext, server_alias: &str, session_id: &str) -> AuditCtx {
        AuditCtx {
            user_id: auth.user_id,
            token_id: auth.token_id,
            server_alias: server_alias.to_string(),
            session_id: session_id.to_string(),
        }
    }
}

#[tool_router]
impl ConduitHandler {
    #[tool(name = "list_servers", description = "List servers the authenticated user may access (metadata only).")]
    async fn list_servers(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let all = self
            .state
            .catalog
            .list(auth.user_id)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let servers: Vec<ServerEntry> = all
            .into_iter()
            .map(|r| ServerEntry { alias: r.alias, description: r.description, tags: r.tags })
            .collect();
        Ok(CallToolResult::structured(
            serde_json::to_value(ListServersOutput { servers }).unwrap(),
        ))
    }

    #[tool(name = "open_channel", description = "Open an SSH channel to a registered server. Returns a session_id usable with exec/sftp_*.")]
    async fn open_channel(
        &self,
        Parameters(params): Parameters<OpenChannelParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let catalog = &self.state.catalog;

        let mut chain: Vec<ResolvedServer> = Vec::new();
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut next_alias = Some(params.server.clone());
        while let Some(alias) = next_alias.take() {
            if !visited.insert(alias.clone()) {
                return Err(McpError::invalid_request(
                    format!("jump host cycle detected at '{alias}'"),
                    None,
                ));
            }
            if chain.len() >= MAX_JUMP_HOPS {
                return Err(McpError::invalid_request(
                    format!("jump host chain exceeds {} hops", MAX_JUMP_HOPS),
                    None,
                ));
            }
            let rec = catalog
                .resolve(auth.user_id, &alias)
                .await
                .map_err(|e| McpError::invalid_request(e.to_string(), None))?;
            let jump = rec.jump_host_alias.clone();
            chain.push(rec);
            next_alias = jump;
        }
        chain.reverse();
        let target_alias = chain.last().unwrap().alias.clone();

        let session = SshSession::connect_chain(auth.user_id, auth.token_id, chain)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let session_id = session.id.clone();
        let opened_at = session.created_at.to_rfc3339();
        let hop_path = session.hop_path.clone();
        self.state.sessions.insert(session_id.clone(), session);

        log(
            &*self.state.audit,
            &Self::audit_ctx(&auth, &target_alias, &session_id),
            "open_channel",
            |_| {},
        )
        .await;

        Ok(CallToolResult::structured(
            serde_json::to_value(OpenChannelOutput {
                session_id,
                server: target_alias,
                opened_at,
                hop_path,
            })
            .unwrap(),
        ))
    }

    #[tool(name = "exec", description = "Execute a shell command in an open channel. Subject to authorizer + rate limit.")]
    async fn exec(
        &self,
        Parameters(params): Parameters<ExecParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let session = self.session_for(&params.session_id, &auth)?;
        let actx = Self::audit_ctx(&auth, &session.server_alias, &session.id);

        if let Err(err) = self
            .state
            .authz
            .authorize_exec(&auth, &session.server_alias, &params.command)
            .await
        {
            let msg = err.to_string();
            let cmd = params.command.clone();
            let log_msg = msg.clone();
            log(&*self.state.audit, &actx, "exec_blocked", move |a| {
                a.command = Some(cmd);
                a.error = Some(log_msg);
            })
            .await;
            return Err(McpError::invalid_request(msg, None));
        }

        if let Err(msg) = self.state.limiter.check_and_record(auth.token_id) {
            let log_msg = msg.clone();
            log(&*self.state.audit, &actx, "exec_rate_limited", move |a| {
                a.error = Some(log_msg);
            })
            .await;
            return Err(McpError::invalid_request(msg, None));
        }

        let to = params.timeout_secs.unwrap_or(60).min(600);

        match session.exec(&params.command, to).await {
            Ok(out) => {
                let cmd = params.command.clone();
                let stdout = out.stdout.clone();
                let stderr = out.stderr.clone();
                let ec = out.exit_code as i64;
                let dur = out.duration_ms;
                log(&*self.state.audit, &actx, "exec", move |e| {
                    e.command = Some(cmd);
                    e.stdout = Some(stdout);
                    e.stderr = Some(stderr);
                    e.exit_code = Some(ec);
                    e.duration_ms = Some(dur);
                })
                .await;
                Ok(CallToolResult::structured(
                    serde_json::to_value(ExecOutput {
                        stdout: out.stdout,
                        stderr: out.stderr,
                        exit_code: out.exit_code,
                        duration_ms: out.duration_ms,
                        truncated: out.truncated,
                    })
                    .unwrap(),
                ))
            }
            Err(e) => {
                let cmd = params.command.clone();
                let err = e.to_string();
                log(&*self.state.audit, &actx, "exec_error", move |a| {
                    a.command = Some(cmd);
                    a.error = Some(err);
                })
                .await;
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }

    #[tool(name = "exec_start", description = "Start a long-running command in the background and capture its output for incremental polling. Use for monitoring tasks that exceed exec's limits (docker logs -f, top -b, tail -f). Returns a job_id; read output with exec_poll and end it with exec_stop. Subject to authorizer + rate limit.")]
    async fn exec_start(
        &self,
        Parameters(params): Parameters<ExecStartParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let session = self.session_for(&params.session_id, &auth)?;
        let actx = Self::audit_ctx(&auth, &session.server_alias, &session.id);

        if let Err(err) = self
            .state
            .authz
            .authorize_exec(&auth, &session.server_alias, &params.command)
            .await
        {
            let msg = err.to_string();
            let cmd = params.command.clone();
            let log_msg = msg.clone();
            log(&*self.state.audit, &actx, "exec_blocked", move |a| {
                a.command = Some(cmd);
                a.error = Some(log_msg);
            })
            .await;
            return Err(McpError::invalid_request(msg, None));
        }

        if let Err(msg) = self.state.limiter.check_and_record(auth.token_id) {
            let log_msg = msg.clone();
            log(&*self.state.audit, &actx, "exec_rate_limited", move |a| {
                a.error = Some(log_msg);
            })
            .await;
            return Err(McpError::invalid_request(msg, None));
        }

        let running = self
            .state
            .jobs
            .iter()
            .filter(|e| e.value().session_id == session.id && e.value().is_running())
            .count();
        if running >= MAX_JOBS_PER_SESSION {
            return Err(McpError::invalid_request(
                format!("session already has {MAX_JOBS_PER_SESSION} active background jobs"),
                None,
            ));
        }

        let job_id = format!("job_{}", uuid::Uuid::new_v4().simple());
        let max_secs = params.max_runtime_secs.unwrap_or(DEFAULT_JOB_MAX_SECS);
        let job = session
            .start_job(
                job_id.clone(),
                auth.user_id,
                params.command.clone(),
                max_secs,
                self.state.audit.clone(),
                actx.clone(),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let started_at = job.started_at.to_rfc3339();
        self.state.jobs.insert(job_id.clone(), job);

        let cmd = params.command.clone();
        log(&*self.state.audit, &actx, "exec_start", move |a| {
            a.command = Some(cmd);
        })
        .await;

        Ok(CallToolResult::structured(
            serde_json::to_value(ExecStartOutput {
                job_id,
                session_id: session.id.clone(),
                started_at,
            })
            .unwrap(),
        ))
    }

    #[tool(name = "exec_poll", description = "Read newly captured output from a background job started with exec_start. Pass the stdout_offset/stderr_offset returned by the previous poll to get only new bytes. Returns running=false with exit_code once the command has ended.")]
    async fn exec_poll(
        &self,
        Parameters(params): Parameters<ExecPollParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let job = self
            .state
            .jobs
            .get(&params.job_id)
            .map(|j| j.clone())
            .ok_or_else(|| McpError::invalid_request("unknown job_id", None))?;
        if job.user_id != auth.user_id {
            return Err(McpError::invalid_request("job does not belong to token", None));
        }
        // Polling counts as activity so the idle reaper keeps the underlying
        // session alive while a job is being monitored.
        if let Some(sess) = self.state.sessions.get(&job.session_id) {
            sess.touch();
        }

        let snap = job.read(
            params.stdout_offset.unwrap_or(0),
            params.stderr_offset.unwrap_or(0),
        );
        Ok(CallToolResult::structured(
            serde_json::to_value(ExecPollOutput {
                stdout: String::from_utf8_lossy(&snap.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&snap.stderr).into_owned(),
                stdout_offset: snap.stdout_offset,
                stderr_offset: snap.stderr_offset,
                stdout_gap: snap.stdout_gap,
                stderr_gap: snap.stderr_gap,
                running: snap.running,
                exit_code: snap.exit_code,
            })
            .unwrap(),
        ))
    }

    #[tool(name = "exec_stop", description = "Stop a background job started with exec_start and free it. Sends SIGTERM to the remote command and closes its channel.")]
    async fn exec_stop(
        &self,
        Parameters(params): Parameters<ExecStopParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let job = self
            .state
            .jobs
            .get(&params.job_id)
            .map(|j| j.clone())
            .ok_or_else(|| McpError::invalid_request("unknown job_id", None))?;
        if job.user_id != auth.user_id {
            return Err(McpError::invalid_request("job does not belong to token", None));
        }
        job.stop();
        self.state.jobs.remove(&params.job_id);
        log(
            &*self.state.audit,
            &Self::audit_ctx(&auth, &job.server_alias, &job.session_id),
            "exec_stop",
            {
                let cmd = job.command.clone();
                move |a| a.command = Some(cmd)
            },
        )
        .await;
        Ok(CallToolResult::structured(
            serde_json::to_value(ExecStopOutput { stopped: true }).unwrap(),
        ))
    }

    #[tool(name = "sftp_list", description = "List entries of a remote directory via SFTP.")]
    async fn sftp_list(
        &self,
        Parameters(params): Parameters<SftpListParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let session = self.session_for(&params.session_id, &auth)?;
        let actx = Self::audit_ctx(&auth, &session.server_alias, &session.id);
        match session.sftp_list(&params.path).await {
            Ok(entries) => {
                let path = params.path.clone();
                log(&*self.state.audit, &actx, "sftp_list", move |a| {
                    a.command = Some(format!("LIST {path}"));
                })
                .await;
                Ok(CallToolResult::structured(
                    serde_json::to_value(SftpListOutput { entries }).unwrap(),
                ))
            }
            Err(e) => {
                let path = params.path.clone();
                let err = e.to_string();
                log(&*self.state.audit, &actx, "sftp_list_error", move |a| {
                    a.command = Some(format!("LIST {path}"));
                    a.error = Some(err);
                })
                .await;
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }

    #[tool(name = "sftp_download", description = "Download a remote file via SFTP. Returns base64-encoded content, hard cap 1MB.")]
    async fn sftp_download(
        &self,
        Parameters(params): Parameters<SftpDownloadParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let session = self.session_for(&params.session_id, &auth)?;
        let cap = params.max_bytes.unwrap_or(1_048_576) as usize;
        let actx = Self::audit_ctx(&auth, &session.server_alias, &session.id);
        match session.sftp_download(&params.path, cap).await {
            Ok((buf, truncated)) => {
                let size = buf.len();
                let path = params.path.clone();
                log(&*self.state.audit, &actx, "sftp_download", move |a| {
                    a.command = Some(format!("GET {path}"));
                    a.duration_ms = Some(size as i64);
                })
                .await;
                Ok(CallToolResult::structured(
                    serde_json::to_value(SftpDownloadOutput {
                        content_base64: B64.encode(&buf),
                        size,
                        truncated,
                    })
                    .unwrap(),
                ))
            }
            Err(e) => {
                let path = params.path.clone();
                let err = e.to_string();
                log(&*self.state.audit, &actx, "sftp_download_error", move |a| {
                    a.command = Some(format!("GET {path}"));
                    a.error = Some(err);
                })
                .await;
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }

    #[tool(name = "sftp_upload", description = "Upload a file via SFTP. Pass content as base64. Existing file is truncated.")]
    async fn sftp_upload(
        &self,
        Parameters(params): Parameters<SftpUploadParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let session = self.session_for(&params.session_id, &auth)?;
        let bytes = B64
            .decode(params.content_base64.as_bytes())
            .map_err(|e| McpError::invalid_request(format!("base64 decode: {e}"), None))?;
        let actx = Self::audit_ctx(&auth, &session.server_alias, &session.id);
        match session.sftp_upload(&params.path, &bytes).await {
            Ok(n) => {
                let path = params.path.clone();
                log(&*self.state.audit, &actx, "sftp_upload", move |a| {
                    a.command = Some(format!("PUT {path}"));
                    a.duration_ms = Some(n as i64);
                })
                .await;
                Ok(CallToolResult::structured(
                    serde_json::to_value(SftpUploadOutput { bytes_written: n }).unwrap(),
                ))
            }
            Err(e) => {
                let path = params.path.clone();
                let err = e.to_string();
                log(&*self.state.audit, &actx, "sftp_upload_error", move |a| {
                    a.command = Some(format!("PUT {path}"));
                    a.error = Some(err);
                })
                .await;
                Err(McpError::internal_error(e.to_string(), None))
            }
        }
    }

    #[tool(name = "close_channel", description = "Close an open SSH channel and free its session.")]
    async fn close_channel(
        &self,
        Parameters(params): Parameters<CloseChannelParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let auth = self.auth(&ctx)?;
        let removed = self.state.sessions.remove(&params.session_id);
        if let Some((_, sess)) = removed {
            if sess.user_id != auth.user_id {
                self.state.sessions.insert(sess.id.clone(), sess);
                return Err(McpError::invalid_request("session does not belong to token", None));
            }
            self.state.stop_jobs_for_session(&sess.id);
            sess.close().await;
            log(
                &*self.state.audit,
                &Self::audit_ctx(&auth, &sess.server_alias, &sess.id),
                "close_channel",
                |_| {},
            )
            .await;
        }
        Ok(CallToolResult::structured(
            serde_json::to_value(CloseOutput { closed: true }).unwrap(),
        ))
    }
}

#[tool_handler]
impl ServerHandler for ConduitHandler {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        let mut imp = Implementation::from_build_env();
        imp.name = "conduit".into();
        imp.version = env!("CARGO_PKG_VERSION").into();
        info.server_info = imp;
        info.instructions = Some(
            "Conduit SSH channel MCP. Tools: list_servers, open_channel, exec, \
             exec_start, exec_poll, exec_stop, sftp_list, sftp_download, \
             sftp_upload, close_channel. Use exec for one-shot commands (<=600s); \
             use exec_start + exec_poll + exec_stop to monitor long-running output \
             (docker logs -f, top -b, tail -f). AI never receives credentials; \
             only opaque session_ids and job_ids."
                .into(),
        );
        info
    }
}
