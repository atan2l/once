use crate::db;
use crate::db::models::{OAuthGrant, OAuthGrantExtension};
use crate::db::schema::oauth_grant_extensions::dsl::oauth_grant_extensions;
use crate::db::schema::oauth_grants::code_hash;
use crate::db::schema::oauth_grants::dsl::oauth_grants;
use crate::logging::{debug, error, info, warn};
use aes_gcm::KeyInit;
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, Key};
use async_trait::async_trait;
use base64::Engine;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use diesel::dsl::insert_into;
use diesel::{BelongingToDsl, ExpressionMethods};
use diesel::{QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use hkdf::Hkdf;
use oxide_auth::primitives::grant::{Extensions, Grant, Value};
use oxide_auth_async::primitives::Authorizer;
use rand::TryRngCore;
use rand::rand_core::OsRng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone)]
pub struct PgAuthorizer {
    pool: db::Pool,
}

impl PgAuthorizer {
    pub fn new(pool: db::Pool) -> Self {
        Self { pool }
    }

    fn generate_code() -> Option<[u8; 32]> {
        let mut bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut bytes).ok()?;
        debug!("Generated authorization code");
        Some(bytes)
    }

    fn derive_key(code: &[u8]) -> Option<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(b"auth-code-key-salt-v1"), code);
        let mut okm = [0u8; 32];

        hk.expand(b"auth-code-key-info-v1", &mut okm).ok()?;
        debug!("Derived encryption key from code");
        Some(okm)
    }

    fn hash_code(code: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"auth-code-hash-v1");
        hasher.update(code);

        let result = hasher.finalize();
        debug!("Hashed authorization code");
        BASE64_STANDARD.encode(result)
    }

    fn encrypt_value(key_bytes: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.try_fill_bytes(&mut nonce_bytes).ok()?;

        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext).ok()?;

        let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        debug!("Encrypted extension value");
        Some(combined)
    }

    fn decrypt_value(key_bytes: &[u8], value: &str) -> Option<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        let combined = BASE64_STANDARD.decode(value).ok()?;
        if combined.len() < 12 {
            warn!("Decryption failed: encrypted value too short");
            return None;
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::<Aes256Gcm>::from_slice(nonce_bytes);

        let result = cipher.decrypt(nonce, ciphertext).ok()?;
        debug!("Decrypted extension value");
        Some(result)
    }
}

#[async_trait]
impl Authorizer for PgAuthorizer {
    async fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {:?}", e);
        })?;

        let code = Self::generate_code().ok_or_else(|| {
            error!("Failed to generate authorization code");
        })?;
        let derived_key = Self::derive_key(&code).ok_or_else(|| {
            error!("Failed to derive encryption key");
        })?;
        let hashed_code = Self::hash_code(&code);

        let oauth_grant = OAuthGrant {
            code_hash: hashed_code.clone(),
            client_id: grant.client_id.parse().map_err(|_| ())?,
            owner_id: Uuid::new_v4(),
            redirect_uri: grant.redirect_uri.to_string(),
            scope: grant.scope.to_string(),
            until: grant.until,
        };

        info!("Generated grant {:?}", oauth_grant);

        insert_into(oauth_grants)
            .values(&vec![oauth_grant])
            .get_result::<OAuthGrant>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to insert OAuth grant: {:?}", e);
            })?;

        let mut grant_extensions = vec![];
        for extension in grant
            .extensions
            .public()
            .filter_map(|x| x.1.map(|v| (x.0, v)))
        {
            let encrypted_value =
                Self::encrypt_value(&derived_key, extension.1.as_bytes()).ok_or(())?;
            let encoded_value = BASE64_STANDARD.encode(&encrypted_value);

            grant_extensions.push(OAuthGrantExtension {
                code_hash: hashed_code.clone(),
                name: extension.0.to_owned(),
                value: encoded_value,
            });
        }

        insert_into(oauth_grant_extensions)
            .values(&grant_extensions)
            .get_results::<OAuthGrantExtension>(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to insert grant extensions: {:?}", e);
            })?;

        info!(
            "Generated grant extensions {:?} for client {}",
            grant_extensions, &grant.client_id
        );

        Ok(BASE64_URL_SAFE_NO_PAD.encode(code))
    }

    async fn extract(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        let mut conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get database connection: {:?}", e);
        })?;

        let code = BASE64_URL_SAFE_NO_PAD.decode(code).map_err(|e| {
            error!("Failed to decode authorization code: {:?}", e);
        })?;
        let derived_key = Self::derive_key(&code).ok_or_else(|| {
            error!("Failed to derive encryption key");
        })?;
        let hashed_code = Self::hash_code(&code);

        let oauth_grant = oauth_grants
            .filter(code_hash.eq(hashed_code))
            .select(OAuthGrant::as_select())
            .first(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to query OAuth grant: {:?}", e);
            })?;

        info!("Found grant {:?}", oauth_grant);

        let grant_extensions = OAuthGrantExtension::belonging_to(&oauth_grant)
            .select(OAuthGrantExtension::as_select())
            .load(&mut conn)
            .await
            .map_err(|e| {
                error!("Failed to query grant extensions: {:?}", e);
            })?;

        info!(
            "Found grant extensions {:?} for client {}",
            grant_extensions, &oauth_grant.client_id
        );

        let mut recovered_grant = Grant {
            owner_id: oauth_grant.owner_id.to_string(),
            client_id: oauth_grant.client_id.to_string(),
            scope: oauth_grant.scope.parse().map_err(|_| ())?,
            redirect_uri: oauth_grant.redirect_uri.parse().map_err(|_| ())?,
            until: oauth_grant.until,
            extensions: Extensions::default(),
        };

        for extension in grant_extensions {
            let decrypted_value = Self::decrypt_value(&derived_key, &extension.value).ok_or(())?;
            debug!("Decrypted value for extension {:?}", extension);
            let decrypted_value = String::from_utf8(decrypted_value).map_err(|_| {
                warn!("Failed to convert decrypted value to UTF-8");
            })?;

            recovered_grant
                .extensions
                .set_raw(extension.name, Value::Public(Some(decrypted_value)));
        }

        info!(
            "Successfully extracted grant for client {}",
            recovered_grant.client_id
        );
        Ok(Some(recovered_grant))
    }
}
