-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table webhook_out_deliveries add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table webhook_out_deliveries drop constraint webhook_out_deliveries_pkey;
alter table webhook_out_deliveries add constraint webhook_out_deliveries_pkey primary key (tenant_id, id);
alter table webhook_out_deliveries add constraint webhook_out_deliveries_event_fkey
    foreign key (tenant_id, event_id) references webhook_events (tenant_id, id) on delete cascade;
alter table webhook_out_deliveries add constraint webhook_out_deliveries_endpoint_fkey
    foreign key (tenant_id, endpoint_id) references webhook_endpoints (tenant_id, id) on delete cascade;
drop index webhook_out_deliveries_event;
create index webhook_out_deliveries_event on webhook_out_deliveries (tenant_id, event_id);
drop index webhook_out_deliveries_endpoint;
create index webhook_out_deliveries_endpoint on webhook_out_deliveries (tenant_id, endpoint_id, created_at);
alter table webhook_out_deliveries enable row level security;
alter table webhook_out_deliveries force row level security;
create policy tenant_isolation on webhook_out_deliveries
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on webhook_out_deliveries;
alter table webhook_out_deliveries no force row level security;
alter table webhook_out_deliveries disable row level security;
drop index webhook_out_deliveries_event;
create index webhook_out_deliveries_event on webhook_out_deliveries (event_id);
drop index webhook_out_deliveries_endpoint;
create index webhook_out_deliveries_endpoint on webhook_out_deliveries (endpoint_id, created_at);
alter table webhook_out_deliveries drop constraint webhook_out_deliveries_endpoint_fkey;
alter table webhook_out_deliveries drop constraint webhook_out_deliveries_event_fkey;
alter table webhook_out_deliveries drop constraint webhook_out_deliveries_pkey;
alter table webhook_out_deliveries add constraint webhook_out_deliveries_pkey primary key (id);
alter table webhook_out_deliveries drop column tenant_id;
