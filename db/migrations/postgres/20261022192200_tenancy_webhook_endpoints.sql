-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table webhook_endpoints add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table webhook_endpoints drop constraint webhook_endpoints_pkey cascade;
alter table webhook_endpoints add constraint webhook_endpoints_pkey primary key (tenant_id, id);
drop index webhook_endpoints_status;
create index webhook_endpoints_status on webhook_endpoints (tenant_id, status);
alter table webhook_endpoints enable row level security;
alter table webhook_endpoints force row level security;
create policy tenant_isolation on webhook_endpoints
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on webhook_endpoints;
alter table webhook_endpoints no force row level security;
alter table webhook_endpoints disable row level security;
drop index webhook_endpoints_status;
create index webhook_endpoints_status on webhook_endpoints (status);
alter table webhook_endpoints drop constraint webhook_endpoints_pkey;
alter table webhook_endpoints add constraint webhook_endpoints_pkey primary key (id);
alter table webhook_endpoints drop column tenant_id;
alter table webhook_out_deliveries add constraint webhook_out_deliveries_endpoint_id_fkey
    foreign key (endpoint_id) references webhook_endpoints (id) on delete cascade;
