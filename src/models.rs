use diesel::prelude::*;
use uuid::Uuid;

#[derive(Queryable, Identifiable, Selectable, Debug, PartialEq)]
#[diesel(table_name = crate::schema::auth_clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub(crate) struct AuthClient {
    pub id: Uuid,
    pub client_secret_hash: Option<Vec<u8>>,
    pub default_scope: String,
    pub confidential: bool,
}

#[derive(Queryable, Identifiable, Selectable, Insertable, Associations, Debug, PartialEq)]
#[diesel(table_name = crate::schema::client_redirect_uris)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(AuthClient, foreign_key = client_id))]
pub(crate) struct ClientRedirectUri {
    pub id: Uuid,
    pub client_id: Uuid,
    pub uri: String,
}

#[derive(Queryable, Identifiable, Selectable, Insertable, Associations, Debug, PartialEq)]
#[diesel(table_name = crate::schema::client_allowed_scopes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
#[diesel(belongs_to(AuthClient, foreign_key = client_id))]
pub(crate) struct ClientAllowedScope {
    pub id: Uuid,
    pub client_id: Uuid,
    pub scope: String,
}
