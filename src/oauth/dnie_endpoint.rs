use oxide_auth::endpoint;
use oxide_auth::endpoint::{OAuthError, Scope, Template, WebRequest};
use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::prelude::RandomGenerator;
use oxide_auth_async::endpoint::access_token::AccessTokenFlow;
use oxide_auth_async::endpoint::authorization::AuthorizationFlow;
use oxide_auth_async::endpoint::client_credentials::ClientCredentialsFlow;
use oxide_auth_async::endpoint::refresh::RefreshFlow;
use oxide_auth_async::endpoint::resource::ResourceFlow;
use oxide_auth_async::endpoint::{Endpoint, OwnerSolicitor};
use oxide_auth_async::primitives;
use oxide_auth_async::primitives::Authorizer;
use oxide_auth_axum::{OAuthRequest, WebError};
use tokio::sync::MutexGuard;

pub(crate) struct DnieEndpoint<'a, Registrar, Issuer, Solicitor, Scopes> {
    pub registrar: &'a Registrar,
    pub authorizer: MutexGuard<'a, AuthMap<RandomGenerator>>,
    pub issuer: MutexGuard<'a, Issuer>,
    pub solicitor: Solicitor,
    pub scopes: Scopes,
}

impl<'a, Registrar, Issuer, Solicitor, Scopes>
    DnieEndpoint<'a, Registrar, Issuer, Solicitor, Scopes>
where
    Registrar: primitives::Registrar + Send + Sync,
    Issuer: primitives::Issuer + Send + Sync,
    Solicitor: OwnerSolicitor<OAuthRequest> + Send + Sync,
    Scopes: endpoint::Scopes<OAuthRequest> + Send + Sync,
{
    pub fn with_scopes(
        self,
        scopes: &'a [Scope],
    ) -> DnieEndpoint<'a, Registrar, Issuer, Solicitor, &'a [Scope]> {
        DnieEndpoint {
            registrar: self.registrar,
            authorizer: self.authorizer,
            issuer: self.issuer,
            solicitor: self.solicitor,
            scopes,
        }
    }

    pub fn with_solicitor<S>(self, solicitor: S) -> DnieEndpoint<'a, Registrar, Issuer, S, Scopes>
    where
        Solicitor: OwnerSolicitor<OAuthRequest>,
    {
        DnieEndpoint {
            registrar: self.registrar,
            authorizer: self.authorizer,
            issuer: self.issuer,
            solicitor,
            scopes: self.scopes,
        }
    }

    pub fn authorization_flow(self) -> AuthorizationFlow<Self, OAuthRequest> {
        match AuthorizationFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    pub fn access_token_flow(self) -> AccessTokenFlow<Self, OAuthRequest> {
        match AccessTokenFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    pub fn client_credentials_flow(self) -> ClientCredentialsFlow<Self, OAuthRequest> {
        match ClientCredentialsFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    pub fn refresh_flow(self) -> RefreshFlow<Self, OAuthRequest> {
        match RefreshFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    pub fn resource_flow(self) -> ResourceFlow<Self, OAuthRequest> {
        match ResourceFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }
}

impl<'a, Registrar, Issuer, Solicitor, Scopes> Endpoint<OAuthRequest>
    for DnieEndpoint<'a, Registrar, Issuer, Solicitor, Scopes>
where
    Registrar: primitives::Registrar + Send + Sync,
    Issuer: primitives::Issuer + Send + Sync,
    Solicitor: OwnerSolicitor<OAuthRequest> + Send + Sync,
    Scopes: endpoint::Scopes<OAuthRequest> + Send + Sync,
{
    type Error = WebError;

    fn registrar(&self) -> Option<&(dyn primitives::Registrar + Sync)> {
        Some(self.registrar)
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        Some(&mut *self.authorizer)
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn primitives::Issuer + Send)> {
        Some(&mut *self.issuer)
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<OAuthRequest> + Send)> {
        Some(&mut self.solicitor)
    }

    fn scopes(&mut self) -> Option<&mut dyn endpoint::Scopes<OAuthRequest>> {
        Some(&mut self.scopes)
    }

    fn response(
        &mut self,
        _: &mut OAuthRequest,
        _: Template,
    ) -> Result<<OAuthRequest as WebRequest>::Response, Self::Error> {
        Ok(Default::default())
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        err.into()
    }

    fn web_error(&mut self, err: WebError) -> Self::Error {
        err
    }
}
