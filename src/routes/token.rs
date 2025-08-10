use crate::app_state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use log::debug;
use oxide_auth::endpoint::QueryParameter;
use oxide_auth_axum::OAuthRequest;

pub async fn post_token(State(state): State<AppState>, request: OAuthRequest) -> impl IntoResponse {
    let grant_type = &*request
        .body()
        .map(|x| x.unique_value("grant_type").unwrap_or_default())
        .unwrap_or_default();
    debug!("Grant type {:?}", &grant_type);

    match grant_type {
        "client_credentials" => state
            .endpoint()
            .await
            .client_credentials_flow()
            .execute(request)
            .await
            .map(|x| x.into_response())
            .map_err(|x| x.into_response()),
        &_ => state
            .endpoint()
            .await
            .access_token_flow()
            .execute(request)
            .await
            .map(|x| x.into_response())
            .map_err(|x| x.into_response()),
    }
}
