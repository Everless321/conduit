# Conduit

可扩展的 SSH-over-MCP 基础库。AI 通过 MCP 工具操作远端服务器，**永远拿不到凭据**，只拿到不透明的 `session_id`。

权限、服务器目录、认证、审计都是**可插拔的端口（trait）**——内核引擎只依赖 trait，不认识任何具体存储。要换数据源或权限模型，写一个新 crate 实现对应 trait，在 `conduit-server` 的装配处改几行即可，引擎零改动。

## 架构（Ports & Adapters）

```
conduit-core        纯类型 + 4 个 trait 端口（无 sqlx / axum）
conduit-engine      SSH 会话 + MCP 工具 + 限流 + 审计 + 可挂载的 HTTP 路由 ← 复用内核（中间件）
conduit-store-dibs  SQLite/Dibs 适配器，实现 3 个存储 trait ← 可替换
conduit-server      参考部署：装配适配器 + 引擎 + 自己 bind/serve（可不用，改用嵌入）
conduit-admin       运维 CLI（genkey、审计查询）
```

## 作为中间件嵌入（推荐）

`conduit-engine` 自身**不绑定端口、不决定监听地址**。宿主程序提供 4 个端口适配器，
把 `mcp_router` 挂进自己的 `axum` app，由宿主决定 bind/TLS/Host 校验：

```rust
use std::sync::Arc;
use conduit_engine::{AppState, RateLimiter, mcp_router, spawn_session_cleaner};

let state = Arc::new(AppState::new(catalog, authz, audit, RateLimiter::new(30), 1800));
spawn_session_cleaner(state.clone());

// 挂进宿主自己的路由；监听地址由宿主决定
let app = host_router.merge(mcp_router(state, validator));
let listener = tokio::net::TcpListener::bind("127.0.0.1:7077").await?;
axum::serve(listener, app).await?;
```

`/mcp` 已被 Bearer token 网关保护（无环境凭据），网络暴露与 Host 校验交给宿主/反向代理。
不想嵌入、想直接跑独立服务，用下面的 `conduit-server`。

## 四个端口（`conduit-core/src/ports.rs`）

| Trait | 职责 | 默认实现 |
|-------|------|---------|
| `TokenValidator` | 认证：token → 身份 | `DibsStore` |
| `ServerCatalog` | 服务器目录 + 访问控制（list/resolve，吐已解密凭据） | `DibsStore` |
| `Authorizer` | 命令级权限（黑名单/放行规则） | `CommandPolicy`（core 内置） |
| `AuditSink` | 审计落盘 / 查询 | `DibsStore` |

## 四个端口的最小 demo

下面是每个端口的最小可跑实现（内存 / 静态，仅演示与本地起步用）。完整契约、字段表、错误映射见 [docs/INTEGRATION.md §1.1](docs/INTEGRATION.md)。

### `TokenValidator` — 认证

```rust
use std::collections::HashMap;
use async_trait::async_trait;
use conduit_core::models::AuthContext;
use conduit_core::{Error, Result, TokenValidator};

pub struct StaticTokens(pub HashMap<String, AuthContext>);

#[async_trait]
impl TokenValidator for StaticTokens {
    async fn validate(&self, token: &str) -> Result<AuthContext> {
        if token.is_empty() {
            return Err(Error::Unauthorized("empty token".into())); // 空 token 必拒
        }
        self.0
            .get(token)
            .cloned()
            .ok_or_else(|| Error::Unauthorized("unknown token".into()))
    }
}
```

### `ServerCatalog` — 服务器目录 + 访问控制

`resolve` 里直接吐明文凭据——真实场景在此解密 / 调 Vault。

```rust
use async_trait::async_trait;
use conduit_core::models::{ResolvedServer, ServerSummary};
use conduit_core::{Error, Result, ServerCatalog};

pub struct StaticCatalog {
    /// user_id → 该用户可见的服务器（含解密后的凭据）
    pub by_user: std::collections::HashMap<i64, Vec<ResolvedServer>>,
}

#[async_trait]
impl ServerCatalog for StaticCatalog {
    async fn list(&self, user_id: i64) -> Result<Vec<ServerSummary>> {
        Ok(self
            .by_user
            .get(&user_id)
            .into_iter()
            .flatten()
            .map(|s| ServerSummary { alias: s.alias.clone(), description: None, tags: None })
            .collect())
    }

    async fn resolve(&self, user_id: i64, alias: &str) -> Result<ResolvedServer> {
        self.by_user
            .get(&user_id)
            .into_iter()
            .flatten()
            .find(|s| s.alias == alias)
            .cloned()
            // 无权 == 不存在：统一回 NotFound，不泄露存在性
            .ok_or_else(|| Error::NotFound(alias.to_string()))
    }
}
```

### `Authorizer` — 命令级权限

按 `role` 做 RBAC：admin 放行一切，其余角色禁 `sudo` / 关机。

```rust
use async_trait::async_trait;
use conduit_core::models::AuthContext;
use conduit_core::{Authorizer, Error, Result};

pub struct RoleAuthorizer;

#[async_trait]
impl Authorizer for RoleAuthorizer {
    async fn authorize_exec(&self, auth: &AuthContext, _server: &str, command: &str) -> Result<()> {
        if auth.role == "admin" {
            return Ok(());
        }
        let c = command.trim_start();
        if c.starts_with("sudo ") || c.contains("shutdown") || c.contains("reboot") {
            return Err(Error::Forbidden(format!("role '{}' may not run: {command}", auth.role)));
        }
        Ok(())
    }
}
```

> `authorize_exec` 是 `async`，实现里可做网络 I/O——可调外部 HTTP/gRPC 策略服务做**动态鉴权**（注意超时、fail-open/closed、保留本地硬红线）。

### `AuditSink` — 审计

只打日志、不持久化；`query` 返回空。

```rust
use async_trait::async_trait;
use conduit_core::models::{AuditEntry, AuditQuery};
use conduit_core::{AuditSink, Result};

pub struct LogAudit;

#[async_trait]
impl AuditSink for LogAudit {
    async fn write(&self, e: &AuditEntry) {
        // write 无 Result——失败只能内部 warn，绝不能让调用方失败
        tracing::info!(
            user = e.user_id, server = %e.server_alias,
            event = %e.event, command = ?e.command, "audit"
        );
    }

    async fn query(&self, _q: &AuditQuery) -> Result<Vec<AuditEntry>> {
        Ok(vec![])
    }
}
```

## 接一个新后端

举例：把服务器目录与权限换成静态 YAML / Postgres / Vault / REST——

1. 新建 `conduit-store-xxx`，`impl ServerCatalog`（+ 按需 `Authorizer`/`TokenValidator`/`AuditSink`）。
2. 在 `conduit-server/src/main.rs` 的「Adapter wiring」段把 `DibsStore` 换成你的实现。
3. 重新编译。`conduit-engine` 不动。

认证、审计可继续复用 `DibsStore`，只换 `ServerCatalog`+`Authorizer`——每个端口独立可换。

## 运行

```bash
export CONDUIT_MASTER_KEY=$(cargo run -p conduit-admin -- genkey)
cargo run -p conduit-server -- --db ./conduit.db
```

默认只监听 `127.0.0.1:7077`。要对外暴露，显式设 `CONDUIT_BIND=0.0.0.0:7077`（或在前面架反向代理）。
