use async_trait::async_trait;
use log::debug;
use oxide_auth::endpoint::{OwnerConsent, Solicitation};
use oxide_auth_async::endpoint::OwnerSolicitor;
use oxide_auth_axum::{OAuthRequest, OAuthResponse};

pub(crate) struct TestSolicitor;

#[async_trait]
impl OwnerSolicitor<OAuthRequest> for TestSolicitor {
    async fn check_consent(
        &mut self,
        req: &mut OAuthRequest,
        solicitation: Solicitation<'_>,
    ) -> OwnerConsent<OAuthResponse> {
        debug!("Checking consent, consent is authorised");
        OwnerConsent::Authorized("".to_string())
    }
}
