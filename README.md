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
