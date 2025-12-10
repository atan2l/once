use crate::testing::TestSolicitor;
use oxide_auth::frontends::simple::endpoint::Vacant;
use once_common::db;
use once_common::oauth::dnie_endpoint::DnieEndpoint;
use once_common::oauth::pg_authorizer::PgAuthorizer;
use once_common::oauth::pg_issuer::{CoreRsaPrivateSigningKey, PgIssuer};
use once_common::oauth::pg_registrar::PgRegistrar;

pub struct AppState {
    db_pool: db::Pool,
    authorizer: PgAuthorizer,
    issuer: PgIssuer,
    registrar: PgRegistrar,
    solicitor: TestSolicitor,
    scopes: Vacant,
}

impl AppState {
    pub fn new(db_pool: db::Pool, rsa_key: CoreRsaPrivateSigningKey, issuer: String) -> Self {
        Self {
            authorizer: PgAuthorizer::new(db_pool.clone()),
            registrar: PgRegistrar::new(db_pool.clone()),
            issuer: PgIssuer::new(rsa_key, db_pool.clone(), issuer),
            solicitor: TestSolicitor,
            scopes: Vacant,
            db_pool,
        }
    }

    pub fn endpoint(
        &'_ mut self,
    ) -> DnieEndpoint<'_, PgRegistrar, PgAuthorizer, PgIssuer, TestSolicitor, Vacant> {
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
            db_pool: self.db_pool.clone(),
            authorizer: self.authorizer.clone(),
            issuer: self.issuer.clone(),
            registrar: self.registrar.clone(),
            solicitor: self.solicitor.clone(),
            scopes: Vacant,
        }
    }
}
