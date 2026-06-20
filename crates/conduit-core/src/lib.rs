//! conduit-core: storage-agnostic types and the trait ports that make the
//! engine pluggable. Adapters (a SQLite/Dibs store, a Postgres catalog, a
//! static-config catalog, ...) implement these traits; the engine depends only
//! on the traits, never on a concrete backend.

pub mod crypto;
pub mod error;
pub mod models;
pub mod policy;
pub mod ports;

pub use error::{Error, Result};
pub use ports::{
    AuditSink, Authorizer, CapturedOutput, OutputContext, OutputFilter, OutputStream,
    ServerCatalog, TokenValidator,
};
