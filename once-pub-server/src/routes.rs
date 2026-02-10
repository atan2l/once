use crate::app_state::AppState;
use axum::Router;
use axum::routing::{get, post};

mod jwks_json;
mod oauth_authorization_server;
mod openid_configuration;
mod token;

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/.well-known/jwks.json", get(jwks_json::get_jwks_json))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server::get_oauth_authorization_server),
        )
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration::get_openid_configuration),
        )
        .route("/token", post(token::post_token))
}
