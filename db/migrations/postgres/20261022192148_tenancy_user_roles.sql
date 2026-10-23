-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table user_roles add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table user_roles drop constraint user_roles_user_id_role_id_scope_type_scope_id_key;
alter table user_roles drop constraint user_roles_role_id_fkey;
create unique index user_roles_grant_key on user_roles (tenant_id, user_id, role_id, scope_type, scope_id) nulls not distinct;
drop index user_roles_role_id;
create index user_roles_role_id on user_roles (tenant_id, role_id);
drop index user_roles_granted_by;
create index user_roles_granted_by on user_roles (tenant_id, granted_by);
alter table user_roles add constraint user_roles_role_fkey
    foreign key (tenant_id, role_id) references roles (tenant_id, id) on delete cascade;
alter table user_roles enable row level security;
alter table user_roles force row level security;
create policy tenant_isolation on user_roles
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid));
-- Operator-realm rows have no tenant: readable where no tenant is set, written only by the operator role.
create policy global_read on user_roles for select
    using (tenant_id is null and (select nullif(current_setting('app.tenant_id', true), '')::uuid) is null);

-- +goose Down
drop policy global_read on user_roles;
drop policy tenant_isolation on user_roles;
alter table user_roles no force row level security;
alter table user_roles disable row level security;
alter table user_roles drop constraint user_roles_role_fkey;
drop index user_roles_role_id;
create index user_roles_role_id on user_roles (role_id);
drop index user_roles_granted_by;
create index user_roles_granted_by on user_roles (granted_by);
drop index user_roles_grant_key;
alter table user_roles add constraint user_roles_role_id_fkey foreign key (role_id) references roles (id) on delete cascade;
alter table user_roles add constraint user_roles_user_id_role_id_scope_type_scope_id_key
    unique nulls not distinct (user_id, role_id, scope_type, scope_id);
alter table user_roles drop column tenant_id;
