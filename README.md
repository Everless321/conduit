# Conduit

可扩展的 SSH-over-MCP 基础库。AI 通过 MCP 工具操作远端服务器，**永远拿不到凭据**，只拿到不透明的 `session_id`。

权限、服务器目录、认证、审计都是**可插拔的端口（trait）**——内核引擎只依赖 trait，不认识任何具体存储。要换数据源或权限模型，写一个新 crate 实现对应 trait，在 `conduit-server` 的装配处改几行即可，引擎零改动。

## 架构（Ports & Adapters）

```
conduit-core        纯类型 + 4 个 trait 端口（无 sqlx / axum）
conduit-engine      SSH 会话 + MCP 工具 + 限流 + 审计发射，只依赖 trait ← 复用内核
conduit-store-dibs  SQLite/Dibs 适配器，实现 3 个存储 trait ← 可替换
conduit-server      薄壳：装配适配器 + 引擎 + axum/rmcp 传输
conduit-admin       运维 CLI（genkey、审计查询）
```

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
