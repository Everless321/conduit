//! conduit-engine: the reusable SSH-over-MCP core. It owns SSH session
//! lifecycle, the MCP tool surface (`list_servers`, `open_channel`, `exec`,
//! `sftp_*`, `close_channel`), rate limiting and audit emission — and depends
//! ONLY on the trait ports in `conduit-core`. It has no knowledge of SQLite,
//! Dibs, or any concrete storage. Wire it to adapters at assembly time.

pub mod audit;
pub mod ratelimit;
pub mod session;
pub mod state;
pub mod tools;

pub use ratelimit::RateLimiter;
pub use state::AppState;
pub use tools::ConduitHandler;
