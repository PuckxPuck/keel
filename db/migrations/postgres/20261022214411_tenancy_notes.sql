-- Makes notes a tenant table right after the migration that creates it, while it is still empty.
-- keel:contract
-- +goose Up
alter table notes add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table notes drop constraint notes_pkey;
alter table notes add constraint notes_pkey primary key (tenant_id, id);
alter table notes drop constraint notes_client_id_key;
alter table notes add constraint notes_client_id_key unique (tenant_id, client_id);
drop index notes_title;
create index notes_title on notes (tenant_id, title, id);
drop index notes_created_at;
create index notes_created_at on notes (tenant_id, created_at, id);
drop index notes_updated_at;
create index notes_updated_at on notes (tenant_id, updated_at, id);
drop index notes_change_xid;
create index notes_change_xid on notes (tenant_id, change_xid, id);
drop index notes_archived_by;
create index notes_archived_by on notes (tenant_id, archived_by);
drop index notes_created_by;
create index notes_created_by on notes (tenant_id, created_by);
drop index notes_updated_by;
create index notes_updated_by on notes (tenant_id, updated_by);
alter table notes enable row level security;
alter table notes force row level security;
create policy tenant_isolation on notes
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on notes;
alter table notes no force row level security;
alter table notes disable row level security;
drop index notes_updated_by;
create index notes_updated_by on notes (updated_by);
drop index notes_created_by;
create index notes_created_by on notes (created_by);
drop index notes_archived_by;
create index notes_archived_by on notes (archived_by);
drop index notes_change_xid;
create index notes_change_xid on notes (change_xid, id);
drop index notes_updated_at;
create index notes_updated_at on notes (updated_at, id);
drop index notes_created_at;
create index notes_created_at on notes (created_at, id);
drop index notes_title;
create index notes_title on notes (title, id);
alter table notes drop constraint notes_client_id_key;
alter table notes add constraint notes_client_id_key unique (client_id);
alter table notes drop constraint notes_pkey;
alter table notes add constraint notes_pkey primary key (id);
alter table notes drop column tenant_id;
