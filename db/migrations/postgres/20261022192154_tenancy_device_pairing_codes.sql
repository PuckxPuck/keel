-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table device_pairing_codes add column tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table device_pairing_codes drop constraint device_pairing_codes_pkey;
alter table device_pairing_codes add constraint device_pairing_codes_pkey primary key (tenant_id, code_hash);
drop index device_pairing_codes_created_by;
create index device_pairing_codes_created_by on device_pairing_codes (tenant_id, created_by);
drop index device_pairing_codes_expires_at;
create index device_pairing_codes_expires_at on device_pairing_codes (tenant_id, expires_at);
alter table device_pairing_codes enable row level security;
alter table device_pairing_codes force row level security;
create policy tenant_isolation on device_pairing_codes
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on device_pairing_codes;
alter table device_pairing_codes no force row level security;
alter table device_pairing_codes disable row level security;
drop index device_pairing_codes_created_by;
create index device_pairing_codes_created_by on device_pairing_codes (created_by);
drop index device_pairing_codes_expires_at;
create index device_pairing_codes_expires_at on device_pairing_codes (expires_at);
alter table device_pairing_codes drop constraint device_pairing_codes_pkey;
alter table device_pairing_codes add constraint device_pairing_codes_pkey primary key (code_hash);
alter table device_pairing_codes drop column tenant_id;
