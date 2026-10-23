-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table connections add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table connections drop constraint connections_pkey;
alter table connections add constraint connections_pkey primary key (tenant_id, id);
alter table connections drop constraint connections_provider_external_account_id_key;
alter table connections add constraint connections_provider_external_account_id_key
    unique (tenant_id, provider, external_account_id);
drop index connections_created_by;
create index connections_created_by on connections (tenant_id, created_by);
alter table connections enable row level security;
alter table connections force row level security;
create policy tenant_isolation on connections
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on connections;
alter table connections no force row level security;
alter table connections disable row level security;
drop index connections_created_by;
create index connections_created_by on connections (created_by);
alter table connections drop constraint connections_provider_external_account_id_key;
alter table connections add constraint connections_provider_external_account_id_key unique (provider, external_account_id);
alter table connections drop constraint connections_pkey;
alter table connections add constraint connections_pkey primary key (id);
alter table connections drop column tenant_id;
