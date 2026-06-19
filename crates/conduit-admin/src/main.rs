use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use conduit_core::crypto::MasterKey;
use conduit_core::models::AuditQuery;
use conduit_core::AuditSink;
use conduit_store_dibs::DibsStore;

#[derive(Parser, Debug)]
#[command(
    name = "conduit-admin",
    version,
    about = "Conduit admin CLI (Dibs-integrated build). User/server/token management lives in the Dibs UI."
)]
struct Cli {
    #[arg(long, default_value = "/Users/everless/project/dibs/server/data/dibs.db", env = "CONDUIT_DB")]
    db: PathBuf,
    #[arg(long, env = "CONDUIT_MASTER_KEY")]
    master_key: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh 32-byte master key (hex). Save it as CONDUIT_MASTER_KEY.
    Genkey,
    /// Inspect the conduit_audit table written by conduit-server.
    #[command(subcommand)]
    Audit(AuditCmd),
}

#[derive(Subcommand, Debug)]
enum AuditCmd {
    Query {
        #[arg(long)]
        user_id: Option<i64>,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long, help = "RFC3339 timestamp lower bound, e.g. 2026-05-13T00:00:00Z")]
        since: Option<chrono::DateTime<chrono::Utc>>,
        #[arg(long, default_value_t = 50)]
        limit: i64,
        #[arg(long, default_value_t = false, help = "Include stdout/stderr bodies in output")]
        full: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.cmd, Cmd::Genkey) {
        println!("{}", MasterKey::generate_hex());
        return Ok(());
    }

    let key = match &cli.master_key {
        Some(s) => MasterKey::from_hex(s).context("invalid CONDUIT_MASTER_KEY")?,
        None => MasterKey::from_env("CONDUIT_MASTER_KEY").context("CONDUIT_MASTER_KEY not set")?,
    };
    let store = DibsStore::open(&cli.db, key).await.context("open store")?;

    match cli.cmd {
        Cmd::Genkey => unreachable!(),
        Cmd::Audit(AuditCmd::Query { user_id, server, session, since, limit, full }) => {
            let rows = store
                .query(&AuditQuery { user_id, server, session_id: session, since, limit })
                .await?;
            for r in rows {
                let cmd = r.command.unwrap_or_default();
                let cmd_short = if cmd.len() > 80 { format!("{}…", &cmd[..80]) } else { cmd.clone() };
                println!(
                    "{}\t{}\tuser={}\t{}\t{}\tec={:?}\tdur={:?}ms\t{}",
                    r.created_at.format("%Y-%m-%d %H:%M:%S"),
                    r.event,
                    r.user_id,
                    r.server_alias,
                    r.session_id,
                    r.exit_code,
                    r.duration_ms,
                    cmd_short
                );
                if full {
                    if let Some(s) = &r.stdout {
                        if !s.is_empty() {
                            println!("  stdout:\n{}", indent(s, "    "));
                        }
                    }
                    if let Some(s) = &r.stderr {
                        if !s.is_empty() {
                            println!("  stderr:\n{}", indent(s, "    "));
                        }
                    }
                    if let Some(e) = &r.error {
                        println!("  error: {}", e);
                    }
                }
            }
        }
    }
    Ok(())
}

fn indent(s: &str, prefix: &str) -> String {
    s.lines().map(|l| format!("{prefix}{l}")).collect::<Vec<_>>().join("\n")
}
