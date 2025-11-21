use crate::routes::test::get_test;
use crate::routes::token::get_token;
use axum::Router;
use axum::routing::get;

mod test;
mod token;

pub(crate) fn create_routes() -> Router {
    Router::new()
        .route("/test", get(get_test))
        .route("/token", get(get_token))
}
