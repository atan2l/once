use crate::middleware::client_cert_auth::ClientCertData;
use axum::Extension;
use axum::response::IntoResponse;
use chrono::{Duration, Utc};
use openidconnect::core::CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256;
use openidconnect::core::{
    CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreRsaPrivateSigningKey,
};
use openidconnect::{
    EmptyAdditionalClaims, EndUserFamilyName, EndUserGivenName, IssuerUrl, LanguageTag,
    LocalizedClaim, StandardClaims, SubjectIdentifier,
};

pub async fn get_token(
    Extension(client_cert_data): Extension<ClientCertData>,
) -> impl IntoResponse {
    let issuer = IssuerUrl::new(String::from("https://mtls.auth.castellan.systems"));

    if issuer.is_err() {
        return "Invalid issuer URL".to_string();
    }

    let issuer = issuer.unwrap();

    let subject = SubjectIdentifier::new(client_cert_data.serial_number);
    let standard_claims = StandardClaims::<CoreGenderClaim>::new(subject);

    let mut localized_given_name = LocalizedClaim::new();
    localized_given_name.insert(
        Some(LanguageTag::new(client_cert_data.country.clone())),
        EndUserGivenName::new(client_cert_data.given_name),
    );

    let mut localized_family_name = LocalizedClaim::new();
    localized_family_name.insert(
        Some(LanguageTag::new(client_cert_data.country.clone())),
        EndUserFamilyName::new(client_cert_data.surname),
    );

    let standard_claims = standard_claims.set_given_name(Some(localized_given_name));
    let standard_claims = standard_claims.set_family_name(Some(localized_family_name));

    let now = Utc::now();
    let id_token_claims = CoreIdTokenClaims::new(
        issuer,
        vec![],
        now,
        now + Duration::minutes(5),
        standard_claims,
        EmptyAdditionalClaims::default(),
    );

    let rsa_signing_key = CoreRsaPrivateSigningKey::from_pem("", None).unwrap();

    let id_token = CoreIdToken::new(
        id_token_claims,
        &rsa_signing_key,
        RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();

    id_token.to_string()
}
