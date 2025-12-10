use crate::app_state::AppState;
use axum::Extension;
use axum::extract::State;
use axum::response::IntoResponse;
use once_common::oauth::client_cert_data::ClientCertData;
use once_common::oauth::mtls_auth_extension::MtlsAuthExtension;
use oxide_auth::frontends::simple::extensions::{AddonList, Extended};
use oxide_auth_async::endpoint::authorization::AuthorizationFlow;
use oxide_auth_axum::OAuthRequest;

pub async fn get_authorize(
    State(mut app_state): State<AppState>,
    Extension(client_cert_data): Extension<ClientCertData>,
    request: OAuthRequest,
) -> impl IntoResponse {
    let mut extensions = AddonList::new();
    let mtls_extension = MtlsAuthExtension::new(client_cert_data);
    extensions.push_authorization(mtls_extension);
    let endpoint = Extended::extend_with(app_state.endpoint(), extensions);
    match AuthorizationFlow::prepare(endpoint) {
        Ok(mut flow) => flow
            .execute(request)
            .await
            .map(IntoResponse::into_response)
            .map_err(|e| e.into_response()),
        Err(e) => Err(e.into_response()),
    }
}
