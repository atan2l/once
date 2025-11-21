use crate::routes::test::get_test;
use axum::routing::get;
use axum::Router;

mod test;

pub(crate) fn create_routes() -> Router {
    Router::new().route("/test", get(get_test))
}
