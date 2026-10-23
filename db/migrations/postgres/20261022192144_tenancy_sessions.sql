-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table sessions add column current_tenant_id uuid references tenants (id) on delete set null;
create index sessions_current_tenant_id on sessions (current_tenant_id);

-- +goose Down
alter table sessions drop column current_tenant_id;
