use crate::oauth::dnie_endpoint::DnieEndpoint;
use crate::oauth::pg_registrar::PgRegistrar;
use crate::oauth::rsa_jwt_issuer::RsaJwtIssuer;
use oxide_auth::frontends::simple::endpoint::Vacant;
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::generator::RandomGenerator;
use oxide_auth_async::primitives::{Issuer, Registrar};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub(crate) struct AppState {
    registrar: PgRegistrar,
    authorizer: Arc<Mutex<AuthMap<RandomGenerator>>>,
    issuer: Arc<Mutex<RsaJwtIssuer>>,
}

impl AppState {
    pub fn new(registrar: PgRegistrar, issuer: RsaJwtIssuer) -> Self {
        Self {
            registrar,
            authorizer: Arc::new(Mutex::new(AuthMap::new(RandomGenerator::new(16)))),
            issuer: Arc::new(Mutex::new(issuer)),
        }
    }

    pub async fn endpoint(&self) -> DnieEndpoint<'_, impl Registrar, impl Issuer, Vacant, Vacant> {
        DnieEndpoint {
            registrar: &self.registrar,
            authorizer: self.authorizer.lock().await,
            issuer: self.issuer.lock().await,
            solicitor: Vacant,
            scopes: Vacant,
        }
    }
}
