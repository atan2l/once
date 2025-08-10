use crate::oauth::pg_registrar::PgRegistrar;
use crate::oauth::rsa_jwt_issuer::RsaJwtIssuer;
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::generator::RandomGenerator;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) registrar: Arc<PgRegistrar>,
    pub(crate) authorizer: Arc<RwLock<AuthMap<RandomGenerator>>>,
    pub(crate) issuer: Arc<RsaJwtIssuer>,
}
