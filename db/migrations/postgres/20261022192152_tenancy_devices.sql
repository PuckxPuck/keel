-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table devices add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table devices drop constraint devices_pkey;
alter table devices add constraint devices_pkey primary key (tenant_id, id);
drop index devices_created_by;
create index devices_created_by on devices (tenant_id, created_by);
alter table devices enable row level security;
alter table devices force row level security;
create policy tenant_isolation on devices
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on devices;
alter table devices no force row level security;
alter table devices disable row level security;
drop index devices_created_by;
create index devices_created_by on devices (created_by);
alter table devices drop constraint devices_pkey;
alter table devices add constraint devices_pkey primary key (id);
alter table devices drop column tenant_id;
