use crate::app_state::AppState;
use crate::routes::test::get_test;
use crate::routes::token::post_token;
use axum::Router;
use axum::routing::{get, post};

mod test;
mod token;

pub(crate) fn create_routes() -> Router<AppState> {
    Router::new()
        .route("/test", get(get_test))
        .route("/token", post(post_token))
}
