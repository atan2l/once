use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken_aws_lc::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use oxide_auth::primitives::grant::Grant;
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken, TokenType};
use oxide_auth_async::primitives::Issuer;
use serde::{Deserialize, Serialize};

pub(crate) struct RsaJwtIssuer {
    enc_key: EncodingKey,
    dec_key: DecodingKey,
    kid: String,
    issuer: String,
    access_ttl: Duration,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Claims {
    sub: String,
    aud: String,
    iss: String,
    exp: DateTime<Utc>,
    iat: DateTime<Utc>,
    scope: String,
    redir: String,
}

impl RsaJwtIssuer {
    pub fn new(
        enc_key: EncodingKey,
        dec_key: DecodingKey,
        kid: impl Into<String>,
        issuer: impl Into<String>,
        access_ttl: Duration,
    ) -> Self {
        Self {
            enc_key,
            dec_key,
            kid: kid.into(),
            issuer: issuer.into(),
            access_ttl,
        }
    }

    fn to_claims(&self, grant: &Grant) -> Claims {
        let iat = Utc::now();
        let exp = iat + self.access_ttl;
        Claims {
            sub: grant.client_id.clone(),
            aud: grant.client_id.clone(),
            iss: self.issuer.clone(),
            exp,
            iat,
            scope: grant.scope.to_string(),
            redir: grant.redirect_uri.to_string(),
        }
    }

    fn from_claims(c: Claims) -> Result<Grant, ()> {
        let redirect_uri = c.redir.parse().map_err(|_| ())?;
        let scope = c.scope.parse().map_err(|_| ())?;

        Ok(Grant {
            owner_id: c.sub,
            client_id: c.aud,
            scope,
            redirect_uri,
            until: c.exp,
            extensions: Default::default(),
        })
    }
}

#[async_trait]
impl Issuer for RsaJwtIssuer {
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let claims = self.to_claims(&grant);
        let token = encode(&header, &claims, &self.enc_key).map_err(|_| ())?;

        Ok(IssuedToken {
            token,
            refresh: None,
            until: claims.exp,
            token_type: TokenType::Bearer,
        })
    }

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, ()> {
        Err(())
    }

    async fn recover_token(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        let token_data = decode(token, &self.dec_key, &validation).map_err(|_| ())?;
        Ok(Some(Self::from_claims(token_data.claims)?))
    }

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()> {
        Ok(None)
    }
}
