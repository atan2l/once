use axum::Json;
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
struct OpenIdConfiguration {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
}

pub async fn get_openid_configuration() -> impl IntoResponse {
    Json(OpenIdConfiguration {
        issuer: String::from("https://auth.castellan.systems"),
        authorization_endpoint: String::from("https://mtls.auth.castellan.systems/authorize"),
        token_endpoint: String::from("https://auth.castellan.systems/token"),
        jwks_uri: String::from("https://auth.castellan.systems/.well-known/jwks.json"),
        response_types_supported: vec![String::from("code")],
        grant_types_supported: vec![String::from("authorization_code")],
        subject_types_supported: vec![String::from("public")],
        id_token_signing_alg_values_supported: vec![String::from("RS256")],
        scopes_supported: vec![String::from("openid")],
        token_endpoint_auth_methods_supported: vec![String::from("none")],
        code_challenge_methods_supported: vec![String::from("S256")],
        claims_supported: vec![String::from("sub")],
    })
}
