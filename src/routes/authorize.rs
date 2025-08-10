use crate::app_state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use oxide_auth_axum::OAuthRequest;

pub async fn get_authorize(State(state): State<AppState>, req: OAuthRequest) -> impl IntoResponse {
    state.endpoint()
        .await
        .authorization_flow()
        .execute(req)
        .await
        .map(IntoResponse::into_response)
        .map_err(|e| e.into_response())
}
