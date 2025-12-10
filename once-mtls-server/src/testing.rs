use async_trait::async_trait;
use oxide_auth::endpoint::{OwnerConsent, Solicitation};
use oxide_auth_async::endpoint::OwnerSolicitor;
use oxide_auth_axum::{OAuthRequest, OAuthResponse};

#[derive(Clone)]
pub struct TestSolicitor;

#[async_trait]
impl OwnerSolicitor<OAuthRequest> for TestSolicitor {
    async fn check_consent(
        &mut self,
        _req: &mut OAuthRequest,
        _solicitation: Solicitation<'_>,
    ) -> OwnerConsent<OAuthResponse> {
        OwnerConsent::Authorized(String::from(""))
    }
}
