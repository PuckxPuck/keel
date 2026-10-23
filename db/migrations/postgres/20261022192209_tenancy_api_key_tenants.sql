-- +goose Up
create table api_key_tenants (
    key_id uuid primary key,
    tenant_id uuid not null default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id),
    foreign key (tenant_id, key_id) references api_keys (tenant_id, id) on delete cascade
);
create index api_key_tenants_tenant_id on api_key_tenants (tenant_id, key_id);
alter table api_key_tenants enable row level security;
alter table api_key_tenants force row level security;
create policy tenant_isolation on api_key_tenants
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
-- A presented key is located here before its tenant is known, so every row is readable; writes stay in the key's tenant.
create policy locate on api_key_tenants for select using (true);

-- +goose Down
drop table api_key_tenants;
