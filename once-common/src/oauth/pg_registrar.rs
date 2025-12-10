use crate::db;
use crate::db::models::{AuthClient, AuthClientAllowedScope, AuthClientRedirectUri};
use crate::db::schema::auth_client_redirect_uris::uri;
use crate::db::schema::auth_clients::dsl::auth_clients;
use crate::db::schema::auth_clients::id;
use crate::logging::{debug, error, info, warn};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use diesel::{BelongingToDsl, QueryDsl};
use diesel::{ExpressionMethods, SelectableHelper};
use diesel_async::RunQueryDsl;
use oxide_auth::endpoint::{PreGrant, Scope};
use oxide_auth::primitives::prelude::ClientUrl;
use oxide_auth::primitives::registrar::{BoundClient, RegisteredUrl, RegistrarError};
use oxide_auth_async::primitives::Registrar;
use std::borrow::Cow;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgRegistrar {
    pool: db::Pool,
}

impl PgRegistrar {
    pub fn new(pool: db::Pool) -> Self {
        Self { pool }
    }

    async fn get_auth_client(&self, client_id: &Uuid) -> Option<AuthClient> {
        info!("Fetching client {}", client_id);
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(
                    "Failed to get connection from pool for client {}: {:?}",
                    client_id, e
                );
                return None;
            }
        };
        match auth_clients
            .filter(id.eq(client_id))
            .select(AuthClient::as_select())
            .first(&mut conn)
            .await
        {
            Ok(client) => Some(client),
            Err(e) => {
                warn!("Failed to fetch client {}: {:?}", client_id, e);
                None
            }
        }
    }

    async fn get_matching_client_redirect_uri(
        &self,
        client: &AuthClient,
        redirect_uri: &str,
    ) -> Option<AuthClientRedirectUri> {
        info!(
            "Checking redirect URI {} for client {}",
            redirect_uri, client.id
        );
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(
                    "Failed to get connection from pool for client {} redirect URI check: {:?}",
                    client.id, e
                );
                return None;
            }
        };
        match AuthClientRedirectUri::belonging_to(client)
            .filter(uri.eq(redirect_uri))
            .select(AuthClientRedirectUri::as_select())
            .first(&mut conn)
            .await
        {
            Ok(u) => Some(u),
            Err(e) => {
                warn!(
                    "Failed to fetch redirect URI {} for client {}: {:?}",
                    redirect_uri, client.id, e
                );
                None
            }
        }
    }

    async fn get_client_scopes(&self, client: &AuthClient) -> Option<Vec<AuthClientAllowedScope>> {
        info!("Fetching scopes for client {}", client.id);
        let mut conn = match self.pool.get().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(
                    "Failed to get connection from pool for client {} scopes: {:?}",
                    client.id, e
                );
                return None;
            }
        };
        let client_scopes = match AuthClientAllowedScope::belonging_to(client)
            .select(AuthClientAllowedScope::as_select())
            .load(&mut conn)
            .await
        {
            Ok(scopes) => Some(scopes),
            Err(e) => {
                warn!("Failed to fetch scopes for client {}: {:?}", client.id, e);
                None
            }
        };

        info!(
            "Fetched scopes for client {}: {:?}",
            client.id, client_scopes
        );

        client_scopes
    }
}

#[async_trait]
impl Registrar for PgRegistrar {
    async fn bound_redirect<'a>(
        &self,
        bound: ClientUrl<'a>,
    ) -> Result<BoundClient<'a>, RegistrarError> {
        debug!(
            "Starting bound_redirect for client_id: {}, redirect_uri: {:?}",
            bound.client_id, bound.redirect_uri
        );

        let client_id = &bound.client_id.parse::<Uuid>().map_err(|e| {
            warn!("Failed to parse client_id {}: {:?}", bound.client_id, e);
            RegistrarError::PrimitiveError
        })?;

        let client = self.get_auth_client(client_id).await.ok_or_else(|| {
            warn!("Client {} not found in bound_redirect", client_id);
            RegistrarError::Unspecified
        })?;

        let client_uri = bound.redirect_uri.ok_or_else(|| {
            warn!("Redirect URI is missing for client {}", client_id);
            RegistrarError::PrimitiveError
        })?;

        let matching_client_uri = self
            .get_matching_client_redirect_uri(&client, client_uri.as_str())
            .await
            .ok_or_else(|| {
                warn!(
                    "No matching redirect URI found for client {}, URI: {}",
                    client_id,
                    client_uri.as_str()
                );
                RegistrarError::PrimitiveError
            })?;

        info!(
            "Successfully found matching redirect URI for client {}: {}",
            client_id, matching_client_uri.uri
        );

        let registered_uri =
            RegisteredUrl::Exact(matching_client_uri.uri.parse().map_err(|e| {
                error!(
                    "Failed to parse registered URL for client {}: {:?}",
                    client_id, e
                );
                RegistrarError::PrimitiveError
            })?);

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_uri),
        })
    }

    async fn negotiate<'a>(
        &self,
        client: BoundClient<'a>,
        scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        debug!(
            "Starting negotiate for client_id: {}, scope: {:?}",
            client.client_id, scope
        );

        let client_id = &client.client_id.parse::<Uuid>().map_err(|e| {
            warn!(
                "Failed to parse client_id {} in negotiate: {:?}",
                client.client_id, e
            );
            RegistrarError::PrimitiveError
        })?;

        let auth_client = self.get_auth_client(client_id).await.ok_or_else(|| {
            warn!("Client {} not found in negotiate", client_id);
            RegistrarError::Unspecified
        })?;

        let scope = if let Some(scope) = scope {
            &scope.to_string()
        } else {
            info!(
                "No scope provided for client {}, using default scope: {}",
                client_id, auth_client.default_scope
            );
            &auth_client.default_scope
        };

        let client_scopes = self.get_client_scopes(&auth_client).await.ok_or_else(|| {
            warn!(
                "Failed to fetch scopes for client {} in negotiate",
                client_id
            );
            RegistrarError::PrimitiveError
        })?;

        if client_scopes.iter().map(|x| &x.scope).any(|x| x == scope) {
            info!(
                "Successfully negotiated scope {} for client {}",
                scope, client_id
            );
            Ok(PreGrant {
                client_id: client.client_id.into_owned(),
                redirect_uri: client.redirect_uri.into_owned(),
                scope: scope.parse().map_err(|_| RegistrarError::PrimitiveError)?,
            })
        } else {
            warn!(
                "Requested scope {} is not allowed for client {}",
                scope, client_id
            );
            Err(RegistrarError::Unspecified)
        }
    }

    async fn check(
        &self,
        client_id: &str,
        passphrase: Option<&[u8]>,
    ) -> Result<(), RegistrarError> {
        debug!("Starting check for client_id: {}", client_id);

        let client_id = client_id.parse::<Uuid>().map_err(|e| {
            warn!("Failed to parse client_id {} in check: {:?}", client_id, e);
            RegistrarError::PrimitiveError
        })?;

        let client = self.get_auth_client(&client_id).await.ok_or_else(|| {
            warn!("Client {} not found in check", client_id);
            RegistrarError::Unspecified
        })?;

        if !client.confidential {
            info!("Client {} is public, skipping verification", client_id);
            return Ok(());
        }

        if let Some(passphrase) = passphrase
            && let Some(secret_hash) = &client.client_secret_hash
        {
            let argon2 = Argon2::default();
            let secret_hash = PasswordHash::new(secret_hash).map_err(|e| {
                warn!(
                    "Failed to parse secret hash for client {}: {:?}",
                    client_id, e
                );
                RegistrarError::PrimitiveError
            })?;
            argon2
                .verify_password(passphrase, &secret_hash)
                .map(|_| {
                    info!("Successfully verified passphrase for client {}", client_id);
                })
                .map_err(|e| {
                    warn!(
                        "Failed to verify passphrase for client {}: {:?}",
                        client_id, e
                    );
                    RegistrarError::PrimitiveError
                })
        } else {
            warn!(
                "Client {} is confidential but missing passphrase or secret hash",
                client_id
            );
            Err(RegistrarError::Unspecified)
        }
    }
}
