use crate::db;
use crate::db::models::{OAuthGrant, OAuthGrantExtension};
use crate::db::schema::oauth_grants::code_hash;
use crate::db::schema::oauth_grants::dsl::oauth_grants;
use crate::logging::{debug, error, info, warn};
use crate::oauth::client_cert_data::ClientCertData;
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE;
use chrono::Utc;
use diesel::{BelongingToDsl, ExpressionMethods, Identifiable, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
pub use openidconnect::core::CoreRsaPrivateSigningKey;
use openidconnect::core::{CoreIdToken, CoreIdTokenClaims};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserBirthday, EndUserFamilyName, EndUserGivenName,
    IssuerUrl, LanguageTag, LocalizedClaim, StandardClaims, SubjectIdentifier,
};
use oxide_auth::primitives::grant::{Extensions, Grant, Value};
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken, TokenType};
use oxide_auth_async::primitives::Issuer;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct PgIssuer {
    rsa_signing_key: Arc<CoreRsaPrivateSigningKey>,
    pool: db::Pool,
    issuer: String,
}

impl PgIssuer {
    pub fn new(rsa_signing_key: CoreRsaPrivateSigningKey, pool: db::Pool, issuer: String) -> Self {
        info!("Creating new PgIssuer with issuer: {}", issuer);
        Self {
            rsa_signing_key: Arc::new(rsa_signing_key),
            pool,
            issuer,
        }
    }

    async fn get_grant(&self, code: &str) -> Option<OAuthGrant> {
        debug!("Attempting to get grant for code hash");
        let mut conn = self.pool.get().await.ok()?;
        let result = oauth_grants
            .filter(code_hash.eq(code))
            .select(OAuthGrant::as_select())
            .first(&mut conn)
            .await
            .ok();

        if result.is_some() {
            debug!("Grant found for code hash");
        } else {
            debug!("No grant found for code hash");
        }

        result
    }

    async fn get_grant_extensions(&self, grant: &OAuthGrant) -> Option<Vec<OAuthGrantExtension>> {
        debug!(
            "Attempting to get grant extensions for grant id: {}",
            grant.id()
        );
        let mut conn = self.pool.get().await.ok()?;
        let result = OAuthGrantExtension::belonging_to(grant)
            .select(OAuthGrantExtension::as_select())
            .load(&mut conn)
            .await
            .ok();

        if let Some(ref extensions) = result {
            debug!("Loaded {} grant extensions", extensions.len());
        } else {
            debug!("Failed to load grant extensions");
        }

        result
    }
}

#[async_trait]
impl Issuer for PgIssuer {
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        info!(
            "Issuing token for grant with client_id: {}",
            grant.client_id
        );
        let mtls_extension = grant
            .extensions
            .public()
            .find_map(|x| if x.0 == "mtls" { x.1 } else { None })
            .ok_or_else(|| {
                error!("mtls extension not found in grant extensions");
            })?;
        let deserialized_mtls_data: ClientCertData =
            serde_json::from_str(mtls_extension).map_err(|e| {
                error!("Failed to deserialize mTLS data: {}", e);
            })?;
        let issuer_url = IssuerUrl::new(self.issuer.clone()).map_err(|e| {
            error!("Failed to create issuer URL: {}", e);
        })?;
        let subject = SubjectIdentifier::new(deserialized_mtls_data.serial_number);
        let standard_claims = StandardClaims::new(subject);

        let mut localized_given_name = LocalizedClaim::new();
        localized_given_name.insert(
            Some(LanguageTag::new(deserialized_mtls_data.country.clone())),
            EndUserGivenName::new(deserialized_mtls_data.given_name.clone()),
        );

        let mut localized_family_name = LocalizedClaim::new();
        localized_family_name.insert(
            Some(LanguageTag::new(deserialized_mtls_data.country.clone())),
            EndUserFamilyName::new(deserialized_mtls_data.surname.clone()),
        );

        debug!(
            "Building standard claims with given_name: {}, family_name: {}, country: {}, date_of_birth: {:?}",
            deserialized_mtls_data.given_name,
            deserialized_mtls_data.surname,
            deserialized_mtls_data.country,
            deserialized_mtls_data.date_of_birth
        );
        let standard_claims = standard_claims.set_given_name(Some(localized_given_name));
        let standard_claims = standard_claims.set_family_name(Some(localized_family_name));
        let standard_claims = standard_claims.set_birthdate(Some(EndUserBirthday::new(
            deserialized_mtls_data.date_of_birth.to_rfc3339(),
        )));

        let now = Utc::now();
        debug!(
            "Creating ID token claims with expiration: {:?}",
            grant.until
        );
        let id_token_claims = CoreIdTokenClaims::new(
            issuer_url,
            vec![Audience::new(grant.client_id)],
            now,
            grant.until,
            standard_claims,
            EmptyAdditionalClaims::default(),
        );

        let id_token = CoreIdToken::new(
            id_token_claims,
            &*self.rsa_signing_key,
            RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .map_err(|e| {
            error!("Failed to create ID token: {}", e);
        })?;

        let random_bytes = rand::random::<[u8; 32]>();

        info!("Successfully issued token for owner_id: {}", grant.owner_id);
        Ok(IssuedToken {
            id_token: id_token.to_string(),
            // Opaque token, not used anywhere, valid for nothing
            token: BASE64_URL_SAFE.encode(random_bytes),
            refresh: None,
            until: grant.until,
            token_type: TokenType::Bearer,
        })
    }

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, ()> {
        info!("Token refresh attempted but not supported");
        Err(())
    }

    async fn recover_token(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        debug!("Attempting to recover token for code hash");
        let base_grant = self.get_grant(code).await.ok_or(())?;
        let grant_extensions = self.get_grant_extensions(&base_grant).await.ok_or(())?;

        debug!("Processing {} grant extensions", grant_extensions.len());
        let mut extensions = Extensions::new();
        for grant_extension in grant_extensions {
            debug!("Adding extension: {}", grant_extension.name);
            extensions.set_raw(
                grant_extension.name,
                Value::Public(Some(grant_extension.value)),
            )
        }

        let scope = base_grant.scope.parse().map_err(|e| {
            error!("Failed to parse scope: {:?}", e);
        })?;
        let redirect_uri = base_grant.redirect_uri.parse().map_err(|e| {
            error!("Failed to parse redirect_uri: {:?}", e);
        })?;

        info!(
            "Successfully recovered token for client_id: {}",
            base_grant.client_id
        );
        Ok(Some(Grant {
            owner_id: base_grant.owner_id.to_string(),
            client_id: base_grant.client_id.to_string(),
            scope,
            redirect_uri,
            until: Utc::now() + Duration::from_mins(5),
            extensions,
        }))
    }

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()> {
        debug!("Refresh token recovery attempted but not supported");
        Ok(None)
    }
}
