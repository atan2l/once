use crate::oauth::pg_registrar::PgRegistrar;
use jsonwebtoken_aws_lc::EncodingKey;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) jwt_private_key: EncodingKey,
    pub(crate) registrar : Arc<PgRegistrar>
}
