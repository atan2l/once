-- Your SQL goes here

ALTER TABLE "oauth_grants"
    ADD CONSTRAINT "oauth_grants_auth_clients_id_fk"
        FOREIGN KEY ("client_id") REFERENCES "auth_clients";

