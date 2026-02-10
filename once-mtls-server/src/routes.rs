mod authorize;
use crate::app_state::AppState;
use axum::Router;
use axum::routing::{get, post};

pub fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/authorize", get(authorize::get_authorize))
        .route("/authorize", post(authorize::post_authorize))
}
