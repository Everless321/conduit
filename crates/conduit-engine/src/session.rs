use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::Mutex as StdMutex;

use chrono::{DateTime, Utc};
use russh::client::{self, Handle};
use russh::keys::{ssh_key, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg, Disconnect, Sig};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::timeout;

use conduit_core::models::{AuthKind, ResolvedServer};
use conduit_core::{AuditSink, Result};

use crate::audit::{log, AuditCtx};

pub const MAX_OUTPUT_BYTES: usize = 1_048_576;
pub const MAX_JUMP_HOPS: usize = 5;

/// Per-stream ring-buffer cap for a background job. Keeps the **most recent**
/// bytes (oldest dropped) so long-running `-f`/`top -b` captures stay bounded.
pub const MAX_JOB_STREAM_BYTES: usize = 2 * 1024 * 1024;
/// Default wall-clock limit for a background job when the caller omits one.
pub const DEFAULT_JOB_MAX_SECS: u64 = 1800;
/// Hard ceiling on a background job's wall-clock limit (24h).
pub const MAX_JOB_MAX_SECS: u64 = 86_400;
/// Max concurrent background jobs per SSH session.
pub const MAX_JOBS_PER_SESSION: usize = 8;

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: i64,
    pub truncated: bool,
}

#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mode: u32,
}

struct ClientCb;

impl client::Handler for ClientCb {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _key: &ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

pub struct SshSession {
    pub id: String,
    pub user_id: i64,
    #[allow(dead_code)]
    pub token_id: i64,
    pub server_alias: String,
    pub hop_path: Vec<String>,
    pub created_at: DateTime<Utc>,
    last_used_epoch: AtomicI64,
    handles: AsyncMutex<Vec<Arc<Handle<ClientCb>>>>,
}

/// Parse the OpenSSH private key in `hop.secret`, decrypting it with
/// `hop.key_passphrase` when the key is encrypted. Shared by `Key` and `Cert`.
fn load_private_key(hop: &ResolvedServer) -> Result<ssh_key::PrivateKey> {
    let pem = std::str::from_utf8(&hop.secret)
        .map_err(|_| conduit_core::Error::Invalid("key not utf8".into()))?;
    let key = ssh_key::PrivateKey::from_openssh(pem)
        .map_err(|e| conduit_core::Error::Invalid(format!("parse key: {e}")))?;
    if let Some(p) = hop
        .key_passphrase
        .as_deref()
        .and_then(|p| std::str::from_utf8(p).ok())
    {
        key.decrypt(p.as_bytes())
            .map_err(|e| conduit_core::Error::Invalid(format!("decrypt key: {e}")))
    } else {
        Ok(key)
    }
}

async fn authenticate(handle: &mut Handle<ClientCb>, hop: &ResolvedServer) -> Result<()> {
    let ok = match hop.auth_kind {
        AuthKind::Password => {
            let pwd = String::from_utf8(hop.secret.clone())
                .map_err(|_| conduit_core::Error::Invalid("password not utf8".into()))?;
            handle
                .authenticate_password(&hop.username, &pwd)
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("auth: {e}")))?
                .success()
        }
        AuthKind::Key => {
            let key = load_private_key(hop)?;
            let best = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("rsa hash: {e}")))?
                .flatten();
            let pkh = PrivateKeyWithHashAlg::new(Arc::new(key), best);
            handle
                .authenticate_publickey(&hop.username, pkh)
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("auth: {e}")))?
                .success()
        }
        AuthKind::Cert => {
            let key = load_private_key(hop)?;
            let cert_pem = hop
                .certificate
                .as_deref()
                .ok_or_else(|| conduit_core::Error::Invalid("cert auth without certificate".into()))?;
            let cert_str = std::str::from_utf8(cert_pem)
                .map_err(|_| conduit_core::Error::Invalid("certificate not utf8".into()))?;
            let cert = ssh_key::Certificate::from_openssh(cert_str.trim())
                .map_err(|e| conduit_core::Error::Invalid(format!("parse certificate: {e}")))?;
            handle
                .authenticate_openssh_cert(&hop.username, Arc::new(key), cert)
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("auth: {e}")))?
                .success()
        }
    };
    if !ok {
        return Err(conduit_core::Error::Unauthorized(format!(
            "ssh authentication rejected for {}@{}",
            hop.username, hop.host
        )));
    }
    Ok(())
}

impl SshSession {
    /// `chain` is ordered outer-most first, target last (at least 1 element).
    pub async fn connect_chain(
        user_id: i64,
        token_id: i64,
        chain: Vec<ResolvedServer>,
    ) -> Result<Arc<Self>> {
        if chain.is_empty() {
            return Err(conduit_core::Error::Invalid("empty chain".into()));
        }
        let target_alias = chain.last().unwrap().alias.clone();
        let hop_path: Vec<String> = chain.iter().map(|h| h.alias.clone()).collect();
        let mut handles: Vec<Arc<Handle<ClientCb>>> = Vec::with_capacity(chain.len());

        for (i, hop) in chain.into_iter().enumerate() {
            let config = Arc::new(client::Config::default());
            let mut handle = if i == 0 {
                client::connect(config, (hop.host.as_str(), hop.port), ClientCb)
                    .await
                    .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!(
                        "ssh connect {}: {e}", hop.host
                    )))?
            } else {
                let prev = handles[i - 1].clone();
                let channel = prev
                    .channel_open_direct_tcpip(
                        hop.host.clone(),
                        hop.port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!(
                        "direct-tcpip to {}:{}: {e}", hop.host, hop.port
                    )))?;
                let stream = channel.into_stream();
                client::connect_stream(config, stream, ClientCb)
                    .await
                    .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!(
                        "tunneled handshake to {}: {e}", hop.host
                    )))?
            };
            authenticate(&mut handle, &hop).await?;
            handles.push(Arc::new(handle));
        }

        let now = Utc::now();
        Ok(Arc::new(Self {
            id: format!("cs_{}", uuid::Uuid::new_v4().simple()),
            user_id,
            token_id,
            server_alias: target_alias,
            hop_path,
            created_at: now,
            last_used_epoch: AtomicI64::new(now.timestamp()),
            handles: AsyncMutex::new(handles),
        }))
    }

    pub fn touch(&self) {
        self.last_used_epoch.store(Utc::now().timestamp(), Ordering::Relaxed);
    }

    pub fn idle_secs(&self) -> i64 {
        Utc::now().timestamp() - self.last_used_epoch.load(Ordering::Relaxed)
    }

    async fn target_handle(&self) -> Option<Arc<Handle<ClientCb>>> {
        self.handles.lock().await.last().cloned()
    }

    pub async fn exec(&self, command: &str, timeout_secs: u64) -> Result<ExecOutput> {
        let handle = self
            .target_handle()
            .await
            .ok_or_else(|| conduit_core::Error::Invalid("session closed".into()))?;
        let start = Instant::now();
        let fut = async {
            let mut channel = handle
                .channel_open_session()
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("open channel: {e}")))?;
            channel
                .exec(true, command)
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("exec: {e}")))?;

            let mut stdout: Vec<u8> = Vec::new();
            let mut stderr: Vec<u8> = Vec::new();
            let mut exit_code: i32 = -1;
            let mut truncated = false;
            let mut closed = false;

            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        if stdout.len() + data.len() > MAX_OUTPUT_BYTES {
                            let room = MAX_OUTPUT_BYTES.saturating_sub(stdout.len());
                            stdout.extend_from_slice(&data[..room]);
                            truncated = true;
                        } else {
                            stdout.extend_from_slice(&data);
                        }
                    }
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        if stderr.len() + data.len() > MAX_OUTPUT_BYTES {
                            let room = MAX_OUTPUT_BYTES.saturating_sub(stderr.len());
                            stderr.extend_from_slice(&data[..room]);
                            truncated = true;
                        } else {
                            stderr.extend_from_slice(&data);
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
                    ChannelMsg::Close => {
                        closed = true;
                        break;
                    }
                    _ => {}
                }
            }
            if !closed {
                let _ = channel.close().await;
            }
            Ok::<_, conduit_core::Error>((stdout, stderr, exit_code, truncated))
        };

        let (stdout, stderr, exit_code, truncated) =
            timeout(Duration::from_secs(timeout_secs), fut)
                .await
                .map_err(|_| {
                    conduit_core::Error::Invalid(format!("exec timeout after {timeout_secs}s"))
                })??;

        self.touch();
        Ok(ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code,
            duration_ms: start.elapsed().as_millis() as i64,
            truncated,
        })
    }

    async fn open_sftp(&self) -> Result<SftpSession> {
        let handle = self
            .target_handle()
            .await
            .ok_or_else(|| conduit_core::Error::Invalid("session closed".into()))?;
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("open channel: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("subsystem: {e}")))?;
        SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("sftp init: {e}")))
    }

    pub async fn sftp_list(&self, path: &str) -> Result<Vec<DirEntry>> {
        let sftp = self.open_sftp().await?;
        let entries = sftp
            .read_dir(path)
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("readdir: {e}")))?;
        let mut out = Vec::new();
        for e in entries {
            out.push(DirEntry {
                name: e.file_name(),
                is_dir: e.metadata().is_dir(),
                size: e.metadata().size.unwrap_or(0),
                mode: e.metadata().permissions.unwrap_or(0),
            });
        }
        let _ = sftp.close().await;
        self.touch();
        Ok(out)
    }

    /// Read up to `cap` bytes from `path`. The caller is responsible for
    /// clamping `cap` to its configured limit (see `AppState::max_download_bytes`).
    pub async fn sftp_download(&self, path: &str, cap: usize) -> Result<(Vec<u8>, bool)> {
        let sftp = self.open_sftp().await?;
        let mut file = sftp
            .open(path)
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("open: {e}")))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 32 * 1024];
        let mut truncated = false;
        loop {
            let n = file
                .read(&mut chunk)
                .await
                .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("read: {e}")))?;
            if n == 0 {
                break;
            }
            if buf.len() + n > cap {
                let room = cap.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..room]);
                truncated = true;
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let _ = file.shutdown().await;
        let _ = sftp.close().await;
        self.touch();
        Ok((buf, truncated))
    }

    pub async fn sftp_upload(&self, path: &str, content: &[u8]) -> Result<usize> {
        let sftp = self.open_sftp().await?;
        let mut file = sftp
            .open_with_flags(
                path,
                OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            )
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("open: {e}")))?;
        file.write_all(content)
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("write: {e}")))?;
        let _ = file.shutdown().await;
        let _ = sftp.close().await;
        self.touch();
        Ok(content.len())
    }

    /// Start a long-running command on its own channel, capturing output into a
    /// ring buffer that the caller polls with [`BgJob::read`]. The command keeps
    /// running after this returns; the channel is closed when the command exits,
    /// the deadline elapses, or [`BgJob::stop`] is called.
    pub async fn start_job(
        &self,
        job_id: String,
        user_id: i64,
        command: String,
        max_secs: u64,
        audit: Arc<dyn AuditSink>,
        actx: AuditCtx,
    ) -> Result<Arc<BgJob>> {
        let handle = self
            .target_handle()
            .await
            .ok_or_else(|| conduit_core::Error::Invalid("session closed".into()))?;
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("open channel: {e}")))?;
        channel
            .exec(true, command.clone())
            .await
            .map_err(|e| conduit_core::Error::Other(anyhow::anyhow!("exec: {e}")))?;

        let job = Arc::new(BgJob {
            id: job_id,
            user_id,
            session_id: self.id.clone(),
            server_alias: self.server_alias.clone(),
            command,
            started_at: Utc::now(),
            inner: StdMutex::new(JobInner {
                out: RingStream::new(),
                err: RingStream::new(),
                running: true,
                exit_code: None,
            }),
            stop: Notify::new(),
        });

        let max_secs = max_secs.clamp(1, MAX_JOB_MAX_SECS);
        tokio::spawn(run_job(job.clone(), channel, max_secs, audit, actx));
        self.touch();
        Ok(job)
    }

    pub async fn close(&self) {
        let mut guard = self.handles.lock().await;
        let drained: Vec<_> = guard.drain(..).rev().collect();
        drop(guard);
        for h in drained {
            let _ = h.disconnect(Disconnect::ByApplication, "", "en").await;
        }
    }
}

/// Cumulative-offset ring buffer: appends are unbounded in offset space, but
/// only the most recent `cap` bytes are retained. A reader tracks an absolute
/// offset; if it falls behind past the retained window the read reports a gap.
struct RingStream {
    data: Vec<u8>,
    /// Absolute offset of `data[0]`.
    start_offset: u64,
}

impl RingStream {
    fn new() -> Self {
        Self { data: Vec::new(), start_offset: 0 }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        if self.data.len() > MAX_JOB_STREAM_BYTES {
            let excess = self.data.len() - MAX_JOB_STREAM_BYTES;
            self.data.drain(0..excess);
            self.start_offset += excess as u64;
        }
    }

    fn total(&self) -> u64 {
        self.start_offset + self.data.len() as u64
    }

    /// Return bytes from absolute `offset` onward, the new offset to resume
    /// from, and whether data before `offset` was dropped (a gap).
    fn read_from(&self, offset: u64) -> (Vec<u8>, u64, bool) {
        let total = self.total();
        if offset >= total {
            return (Vec::new(), total, false);
        }
        let gap = offset < self.start_offset;
        let from = offset.max(self.start_offset);
        let idx = (from - self.start_offset) as usize;
        (self.data[idx..].to_vec(), total, gap)
    }
}

struct JobInner {
    out: RingStream,
    err: RingStream,
    running: bool,
    exit_code: Option<i32>,
}

/// A background command capturing output for incremental polling.
pub struct BgJob {
    pub id: String,
    pub user_id: i64,
    pub session_id: String,
    pub server_alias: String,
    pub command: String,
    pub started_at: DateTime<Utc>,
    inner: StdMutex<JobInner>,
    stop: Notify,
}

/// One incremental read of a [`BgJob`].
pub struct JobSnapshot {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_offset: u64,
    pub stderr_offset: u64,
    pub stdout_gap: bool,
    pub stderr_gap: bool,
    pub running: bool,
    pub exit_code: Option<i32>,
}

impl BgJob {
    /// Read new output since the given absolute offsets.
    pub fn read(&self, stdout_offset: u64, stderr_offset: u64) -> JobSnapshot {
        let inner = self.inner.lock().unwrap();
        let (stdout, so, sg) = inner.out.read_from(stdout_offset);
        let (stderr, eo, eg) = inner.err.read_from(stderr_offset);
        JobSnapshot {
            stdout,
            stderr,
            stdout_offset: so,
            stderr_offset: eo,
            stdout_gap: sg,
            stderr_gap: eg,
            running: inner.running,
            exit_code: inner.exit_code,
        }
    }

    pub fn is_running(&self) -> bool {
        self.inner.lock().unwrap().running
    }

    /// Request the job to stop; the reader task tears down the channel.
    pub fn stop(&self) {
        self.stop.notify_one();
    }
}

/// Reader task: pumps channel output into the job's ring buffers until the
/// command exits, the deadline elapses, or a stop is requested.
async fn run_job(
    job: Arc<BgJob>,
    mut channel: Channel<client::Msg>,
    max_secs: u64,
    audit: Arc<dyn AuditSink>,
    actx: AuditCtx,
) {
    let deadline = tokio::time::sleep(Duration::from_secs(max_secs));
    tokio::pin!(deadline);
    let stopped = job.stop.notified();
    tokio::pin!(stopped);

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        job.inner.lock().unwrap().out.push(&data);
                    }
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                        job.inner.lock().unwrap().err.push(&data);
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        job.inner.lock().unwrap().exit_code = Some(exit_status as i32);
                    }
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            _ = &mut stopped => {
                let _ = channel.signal(Sig::TERM).await;
                let _ = channel.close().await;
                break;
            }
            _ = &mut deadline => {
                let _ = channel.signal(Sig::TERM).await;
                let _ = channel.close().await;
                break;
            }
        }
    }

    let exit_code = {
        let mut inner = job.inner.lock().unwrap();
        inner.running = false;
        inner.exit_code
    };
    let cmd = job.command.clone();
    let ec = exit_code.map(|c| c as i64);
    log(&*audit, &actx, "exec_bg_done", move |a| {
        a.command = Some(cmd);
        a.exit_code = ec;
    })
    .await;
}
