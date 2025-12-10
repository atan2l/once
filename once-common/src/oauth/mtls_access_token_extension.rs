use oxide_auth::code_grant::accesstoken::Request;
use oxide_auth::frontends::simple::extensions::{AccessTokenAddon, AddonResult};
use oxide_auth::primitives::grant::{GrantExtension, Value};

pub struct MtlsAccessTokenExtension;

impl GrantExtension for MtlsAccessTokenExtension {
    fn identifier(&self) -> &'static str {
        "mtls"
    }
}

impl AccessTokenAddon for MtlsAccessTokenExtension {
    fn execute(&self, _request: &dyn Request, code_data: Option<Value>) -> AddonResult {
        match code_data {
            None => AddonResult::Ok,
            Some(data) => AddonResult::Data(data),
        }
    }
}
