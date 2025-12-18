use crate::app_state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use once_common::oauth::mtls_access_token_extension::MtlsAccessTokenExtension;
use oxide_auth::frontends::simple::extensions::{AddonList, Extended};
use oxide_auth_async::endpoint::access_token::AccessTokenFlow;
use oxide_auth_axum::OAuthRequest;
use std::sync::Arc;

pub async fn post_token(
    State(mut app_state): State<AppState>,
    request: OAuthRequest,
) -> impl IntoResponse {
    let mut extensions = AddonList::new();
    extensions
        .access_token
        .push(Arc::new(MtlsAccessTokenExtension));
    let endpoint = Extended::extend_with(app_state.endpoint(), extensions);
    match AccessTokenFlow::prepare(endpoint) {
        Ok(mut flow) => flow
            .execute(request)
            .await
            .map(IntoResponse::into_response)
            .map_err(|e| e.into_response()),
        Err(e) => Err(e.into_response()),
    }
}
