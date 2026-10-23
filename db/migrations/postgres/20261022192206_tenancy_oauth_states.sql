-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- keel:global states are made before sign-in; the tenant is kept so a connection finishes only in the tenant that started it
-- +goose Up
alter table oauth_states add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id) on delete cascade;

-- +goose Down
alter table oauth_states drop column tenant_id;
