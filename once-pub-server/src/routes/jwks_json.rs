use crate::app_state::AppState;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use once_common::oauth::pg_issuer::{CoreJsonWebKeySet, PrivateSigningKey};

pub async fn get_jwks_json(State(app_state): State<AppState>) -> impl IntoResponse {
    let jwks = CoreJsonWebKeySet::new(vec![app_state.signing_key.as_verification_key()]);
    Json(jwks)
}
