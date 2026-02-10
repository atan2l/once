use once_common::db;
use once_common::oauth::dnie_endpoint::DnieEndpoint;
use once_common::oauth::pg_authorizer::PgAuthorizer;
use once_common::oauth::pg_issuer::{CoreRsaPrivateSigningKey, PgIssuer};
use once_common::oauth::pg_registrar::PgRegistrar;
use oxide_auth::frontends::simple::endpoint::Vacant;
use std::sync::Arc;

pub struct AppState {
    pub signing_key: Arc<CoreRsaPrivateSigningKey>,
    db_pool: db::Pool,
    authorizer: PgAuthorizer,
    issuer: PgIssuer,
    registrar: PgRegistrar,
    solicitor: Vacant,
    scopes: Vacant,
}

impl AppState {
    pub fn new(db_pool: db::Pool, signing_key: CoreRsaPrivateSigningKey, issuer: String) -> Self {
        let signing_key = Arc::new(signing_key);
        Self {
            signing_key: signing_key.clone(),
            authorizer: PgAuthorizer::new(db_pool.clone()),
            registrar: PgRegistrar::new(db_pool.clone()),
            issuer: PgIssuer::new(signing_key, db_pool.clone(), issuer),
            solicitor: Vacant,
            scopes: Vacant,
            db_pool,
        }
    }

    pub fn endpoint(
        &'_ mut self,
    ) -> DnieEndpoint<'_, PgRegistrar, PgAuthorizer, PgIssuer, Vacant, Vacant> {
        DnieEndpoint {
            registrar: &self.registrar,
            authorizer: &mut self.authorizer,
            issuer: &mut self.issuer,
            solicitor: &mut self.solicitor,
            scopes: &mut self.scopes,
        }
    }
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            signing_key: self.signing_key.clone(),
            db_pool: self.db_pool.clone(),
            authorizer: self.authorizer.clone(),
            issuer: self.issuer.clone(),
            registrar: self.registrar.clone(),
            solicitor: Vacant,
            scopes: Vacant,
        }
    }
}
