-- This file should undo anything in `up.sql`

ALTER TABLE "oauth_grants"
DROP
CONSTRAINT oauth_grants_auth_clients_id_fk;
