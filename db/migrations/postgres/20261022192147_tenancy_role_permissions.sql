-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table role_permissions add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table role_permissions drop constraint role_permissions_pkey;
alter table role_permissions drop constraint role_permissions_role_id_fkey;
create unique index role_permissions_key on role_permissions (tenant_id, role_id, permission) nulls not distinct;
alter table role_permissions add constraint role_permissions_role_fkey
    foreign key (tenant_id, role_id) references roles (tenant_id, id) on delete cascade;
alter table role_permissions enable row level security;
alter table role_permissions force row level security;
create policy tenant_isolation on role_permissions
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
-- Operator-realm rows have no tenant: readable where no tenant is set, written only by the operator role.
create policy global_read on role_permissions for select
    using (tenant_id is null and (select nullif(current_setting('app.tenant_id', true), '')::uuid) is null);

-- +goose Down
drop policy global_read on role_permissions;
drop policy tenant_isolation on role_permissions;
alter table role_permissions no force row level security;
alter table role_permissions disable row level security;
alter table role_permissions drop constraint role_permissions_role_fkey;
drop index role_permissions_key;
alter table role_permissions add constraint role_permissions_role_id_fkey foreign key (role_id) references roles (id) on delete cascade;
alter table role_permissions add constraint role_permissions_pkey primary key (role_id, permission);
alter table role_permissions drop column tenant_id;
