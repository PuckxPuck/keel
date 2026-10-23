-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table tombstones add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table tombstones drop constraint tombstones_pkey;
alter table tombstones add constraint tombstones_pkey primary key (tenant_id, entity, id);
drop index tombstones_feed;
create index tombstones_feed on tombstones (tenant_id, entity, change_xid, id);
drop index tombstones_deleted_at;
create index tombstones_deleted_at on tombstones (tenant_id, deleted_at);
alter table tombstones enable row level security;
alter table tombstones force row level security;
create policy tenant_isolation on tombstones
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on tombstones;
alter table tombstones no force row level security;
alter table tombstones disable row level security;
drop index tombstones_feed;
create index tombstones_feed on tombstones (entity, change_xid, id);
drop index tombstones_deleted_at;
create index tombstones_deleted_at on tombstones (deleted_at);
alter table tombstones drop constraint tombstones_pkey;
alter table tombstones add constraint tombstones_pkey primary key (entity, id);
alter table tombstones drop column tenant_id;
