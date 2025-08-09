use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use jsonwebtoken_aws_lc::EncodingKey;

type Pool = bb8::Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) jwt_private_key: EncodingKey,
    pub(crate) db_pool: Pool
}
