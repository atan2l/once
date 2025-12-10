use askama::Template;
use async_trait::async_trait;
use once_common::oauth::client_cert_data::ClientCertData;
use oxide_auth::endpoint::{OwnerConsent, QueryParameter, Solicitation, WebResponse};
use oxide_auth_async::endpoint::OwnerSolicitor;
use oxide_auth_axum::{OAuthRequest, OAuthResponse};

#[derive(Clone)]
pub struct HtmlSolicitor {
    client_cert_data: ClientCertData,
}

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthoriseTemplate {
    client_id: String,
    redirect_uri: String,
    scopes: String,
    given_name: String,
    family_name: String,
    id_number: String,
    state: Option<String>,
}

impl HtmlSolicitor {
    pub fn new(client_cert_data: ClientCertData) -> Self {
        Self { client_cert_data }
    }
}

#[async_trait]
impl OwnerSolicitor<OAuthRequest> for HtmlSolicitor {
    async fn check_consent(
        &mut self,
        req: &mut OAuthRequest,
        solicitation: Solicitation<'_>,
    ) -> OwnerConsent<OAuthResponse> {
        if let Some(body) = req.body()
            && let Some(decision) = body.unique_value("decision")
        {
            match decision.as_ref() {
                "approve" => {
                    return OwnerConsent::Authorized(self.client_cert_data.serial_number.clone());
                }
                "deny" => return OwnerConsent::Denied,
                _ => {
                    // Fall through and show the consent form again
                }
            }
        }

        let pre = solicitation.pre_grant();

        let tmpl = AuthoriseTemplate {
            client_id: pre.client_id.clone(),
            redirect_uri: pre.redirect_uri.to_string(),
            scopes: pre.scope.to_string(),
            given_name: self.client_cert_data.given_name.clone(),
            family_name: self.client_cert_data.surname.clone(),
            id_number: self.client_cert_data.serial_number.clone(),
            state: solicitation.state().map(ToOwned::to_owned),
        };

        let html = tmpl
            .render()
            .expect("authorize.html template must be valid at compile time");
        let mut resp = OAuthResponse::default();

        resp.ok().expect("setting the status code cannot fail");

        let resp = resp
            .content_type("text/html; charset=utf-8")
            .expect("setting the content type cannot fail")
            .body(&html);

        OwnerConsent::InProgress(resp)
    }
}
