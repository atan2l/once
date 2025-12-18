use crate::app_state::AppState;
use axum::Router;
use axum::routing::post;

mod token;

pub fn create_routes() -> Router<AppState> {
    Router::new().route("/token", post(token::post_token))
}
