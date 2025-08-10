use crate::Pool;
use crate::models::{AuthClient, ClientRedirectUri};
use crate::schema::auth_clients::dsl::*;
use crate::schema::client_allowed_scopes::dsl::client_allowed_scopes;
use crate::schema::client_allowed_scopes::scope;
use crate::schema::client_redirect_uris::uri;
use async_trait::async_trait;
use diesel::associations::HasTable;
use diesel::dsl::{exists, select};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use log::debug;
use oxide_auth::endpoint::{PreGrant, Scope};
use oxide_auth::primitives::prelude::ClientUrl;
use oxide_auth::primitives::registrar::{BoundClient, RegisteredUrl, RegistrarError};
use oxide_auth_async::primitives::Registrar;
use std::borrow::Cow;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgRegistrar {
    db_pool: Arc<Pool>,
}

impl PgRegistrar {
    pub fn new(db_pool: Arc<Pool>) -> Self {
        Self { db_pool }
    }

    async fn get_auth_client(&self, client_id: &str) -> Result<AuthClient, RegistrarError> {
        debug!("Getting auth client for {}", client_id);
        let pool = self.db_pool.clone();
        let mut pool = pool.get().await.map_err(|_| RegistrarError::Unspecified)?;

        auth_clients
            .filter(id.eq(client_id.parse::<Uuid>().unwrap_or_default()))
            .select(AuthClient::as_select())
            .first(&mut pool)
            .await
            .map_err(|_| RegistrarError::Unspecified)
    }
}

#[async_trait]
impl Registrar for PgRegistrar {
    async fn bound_redirect<'a>(
        &self,
        bound: ClientUrl<'a>,
    ) -> Result<BoundClient<'a>, RegistrarError> {
        let pool = self.db_pool.clone();
        let mut pool = pool.get().await.map_err(|_| RegistrarError::Unspecified)?;
        let auth_client = self.get_auth_client(&bound.client_id).await?;

        debug!("Bound redirect with client_id \"{}\"", &bound.client_id);
        debug!(
            "Bound redirect with redirect_uri \"{}\"",
            match &bound.redirect_uri {
                Some(u) => u.as_str(),
                None => "None",
            }
        );
        let client_uri = ClientRedirectUri::belonging_to(&auth_client)
            .filter(
                uri.eq(bound
                    .redirect_uri
                    .ok_or(RegistrarError::Unspecified)?
                    .as_str()),
            )
            .select(ClientRedirectUri::as_select())
            .first(&mut pool)
            .await
            .map_err(|_| RegistrarError::Unspecified)?;
        debug!("Valid redirect URI found");

        let registered_uri = RegisteredUrl::Exact(
            client_uri
                .uri
                .parse()
                .map_err(|_| RegistrarError::Unspecified)?,
        );

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_uri),
        })
    }

    async fn negotiate<'a>(
        &self,
        client: BoundClient<'a>,
        provided_scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let pool = self.db_pool.clone();
        let mut pool = pool.get().await.map_err(|_| RegistrarError::Unspecified)?;
        let auth_client = self.get_auth_client(&client.client_id).await?;

        let client_scope = if let Some(provided_scope) = provided_scope {
            &provided_scope.to_string()
        } else {
            &auth_client.default_scope
        };
        debug!("Negotiated scope \"{}\"", client_scope);

        let allowed_scope_exists = select(exists(
            client_allowed_scopes::table().filter(scope.eq(client_scope)),
        ))
        .get_result::<bool>(&mut pool)
        .await
        .map_err(|_| RegistrarError::Unspecified)? || client_scope == &auth_client.default_scope;

        if allowed_scope_exists {
            debug!("Allowed scope found");
            Ok(PreGrant {
                client_id: client.client_id.into_owned(),
                redirect_uri: client.redirect_uri.into_owned(),
                scope: client_scope
                    .parse()
                    .map_err(|_| RegistrarError::Unspecified)?,
            })
        } else {
            debug!("Allowed scope not found");
            Err(RegistrarError::Unspecified)
        }
    }

    async fn check(
        &self,
        client_id: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<(), RegistrarError> {
        let auth_client = self.get_auth_client(client_id).await?;

        if auth_client.confidential
            && let Some(_) = passphrase
        {
            debug!("Client is confidential");
            // TODO: Check passphrase with Argon2 or similar
            Ok(())
        } else {
            debug!("Client is public");
            Ok(())
        }
    }
}
