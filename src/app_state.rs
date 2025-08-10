use crate::oauth::pg_registrar::PgRegistrar;
use jsonwebtoken_aws_lc::EncodingKey;
use std::sync::Arc;
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::generator::RandomGenerator;
use tokio::sync::RwLock;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) jwt_private_key: EncodingKey,
    pub(crate) registrar : Arc<PgRegistrar>,
    pub(crate) authorizer: Arc<RwLock<AuthMap<RandomGenerator>>>
}
