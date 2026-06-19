use std::sync::Arc;

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};

use conduit_core::models::AuthContext;
use conduit_core::TokenValidator;

/// Bearer-token middleware. Delegates token validation to whichever
/// [`TokenValidator`] adapter is wired in, and stashes the resolved
/// [`AuthContext`] in request extensions for the MCP tools to read.
pub async fn bearer_auth(
    axum::extract::State(validator): axum::extract::State<Arc<dyn TokenValidator>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .trim();
    let ctx: AuthContext = validator
        .validate(token)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}
