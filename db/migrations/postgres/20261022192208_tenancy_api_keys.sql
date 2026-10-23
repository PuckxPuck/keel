-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table api_keys add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table api_keys drop constraint api_keys_pkey;
alter table api_keys add constraint api_keys_pkey primary key (tenant_id, id);
drop index api_keys_created_at;
create index api_keys_created_at on api_keys (tenant_id, created_at, id);
drop index api_keys_expires_at;
create index api_keys_expires_at on api_keys (tenant_id, expires_at);
drop index api_keys_created_by;
create index api_keys_created_by on api_keys (tenant_id, created_by);
drop index api_keys_revoked_by;
create index api_keys_revoked_by on api_keys (tenant_id, revoked_by);
alter table api_keys enable row level security;
alter table api_keys force row level security;
create policy tenant_isolation on api_keys
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on api_keys;
alter table api_keys no force row level security;
alter table api_keys disable row level security;
drop index api_keys_created_at;
create index api_keys_created_at on api_keys (created_at, id);
drop index api_keys_expires_at;
create index api_keys_expires_at on api_keys (expires_at);
drop index api_keys_created_by;
create index api_keys_created_by on api_keys (created_by);
drop index api_keys_revoked_by;
create index api_keys_revoked_by on api_keys (revoked_by);
alter table api_keys drop constraint api_keys_pkey;
alter table api_keys add constraint api_keys_pkey primary key (id);
alter table api_keys drop column tenant_id;
