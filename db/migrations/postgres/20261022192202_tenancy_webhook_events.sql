-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table webhook_events add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table webhook_events drop constraint webhook_events_pkey cascade;
alter table webhook_events add constraint webhook_events_pkey primary key (tenant_id, id);
drop index webhook_events_created_at;
create index webhook_events_created_at on webhook_events (tenant_id, created_at);
alter table webhook_events enable row level security;
alter table webhook_events force row level security;
create policy tenant_isolation on webhook_events
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on webhook_events;
alter table webhook_events no force row level security;
alter table webhook_events disable row level security;
drop index webhook_events_created_at;
create index webhook_events_created_at on webhook_events (created_at);
alter table webhook_events drop constraint webhook_events_pkey;
alter table webhook_events add constraint webhook_events_pkey primary key (id);
alter table webhook_events drop column tenant_id;
alter table webhook_out_deliveries add constraint webhook_out_deliveries_event_id_fkey
    foreign key (event_id) references webhook_events (id) on delete cascade;
