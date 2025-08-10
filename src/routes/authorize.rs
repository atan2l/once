use crate::app_state::AppState;
use axum::extract::State;
use axum::response::IntoResponse;
use oxide_auth_axum::OAuthRequest;
use crate::oauth::test_solicitor::TestSolicitor;

pub async fn get_authorize(State(state): State<AppState>, req: OAuthRequest) -> impl IntoResponse {
    state.endpoint()
        .await
        .with_scopes(&["default".parse().unwrap()])
        .with_solicitor(TestSolicitor)
        .authorization_flow()
        .execute(req)
        .await
        .map(IntoResponse::into_response)
        .map_err(|e| e.into_response())
}
