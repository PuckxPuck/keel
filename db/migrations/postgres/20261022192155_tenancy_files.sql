-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table files add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table files drop constraint files_pkey;
alter table files add constraint files_pkey primary key (tenant_id, id);
alter table files drop constraint files_storage_key_key;
alter table files add constraint files_storage_key_key unique (tenant_id, storage_key);
drop index files_owner;
create index files_owner on files (tenant_id, owner_type, owner_id);
drop index files_unattached;
create index files_unattached on files (tenant_id, updated_at) where state <> 'attached';
alter table files enable row level security;
alter table files force row level security;
create policy tenant_isolation on files
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on files;
alter table files no force row level security;
alter table files disable row level security;
drop index files_owner;
create index files_owner on files (owner_type, owner_id);
drop index files_unattached;
create index files_unattached on files (updated_at) where state <> 'attached';
alter table files drop constraint files_storage_key_key;
alter table files add constraint files_storage_key_key unique (storage_key);
alter table files drop constraint files_pkey;
alter table files add constraint files_pkey primary key (id);
alter table files drop column tenant_id;
