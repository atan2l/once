use axum::Json;
use axum::response::IntoResponse;
use serde::Serialize;

#[derive(Serialize)]
struct OAuthAuthorizationServer {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    grant_types_supported: Vec<String>,
    response_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
    jwks_uri: String,
}

pub async fn get_oauth_authorization_server() -> impl IntoResponse {
    Json(OAuthAuthorizationServer {
        issuer: String::from("https://auth.castellan.systems"),
        authorization_endpoint: String::from("https://mtls.auth.castellan.systems/authorize"),
        token_endpoint: String::from("https://auth.castellan.systems/token"),
        grant_types_supported: vec![String::from("authorization_code")],
        response_types_supported: vec![String::from("code")],
        code_challenge_methods_supported: vec![String::from("S256")],
        token_endpoint_auth_methods_supported: vec![String::from("none")],
        scopes_supported: vec![String::from("openid")],
        jwks_uri: String::from("https://auth.castellan.systems/.well-known/jwks.json"),
    })
}
