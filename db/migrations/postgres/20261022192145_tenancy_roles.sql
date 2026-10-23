-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table roles add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table roles drop constraint roles_realm_code_key;
create unique index roles_tenant_realm_code_key on roles (tenant_id, realm, code) nulls not distinct;
create unique index roles_tenant_id_key on roles (tenant_id, id);
alter table roles enable row level security;
alter table roles force row level security;
create policy tenant_isolation on roles
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
-- Operator-realm rows have no tenant: readable where no tenant is set, written only by the operator role.
create policy global_read on roles for select
    using (tenant_id is null and (select nullif(current_setting('app.tenant_id', true), '')::uuid) is null);

-- +goose Down
drop policy global_read on roles;
drop policy tenant_isolation on roles;
alter table roles no force row level security;
alter table roles disable row level security;
drop index roles_tenant_id_key;
drop index roles_tenant_realm_code_key;
alter table roles add constraint roles_realm_code_key unique (realm, code);
alter table roles drop column tenant_id;
