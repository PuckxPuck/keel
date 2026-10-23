-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table audit_log add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
drop index audit_log_entity;
create index audit_log_entity on audit_log (tenant_id, entity, entity_id, occurred_at);
drop index audit_log_actor;
create index audit_log_actor on audit_log (tenant_id, actor_id, occurred_at);
drop index audit_log_occurred_at;
create index audit_log_occurred_at on audit_log (tenant_id, occurred_at);
alter table audit_log enable row level security;
alter table audit_log force row level security;
create policy tenant_isolation on audit_log
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid));
-- Each tenant's chain head is its own row; the global head (no tenant) is reachable only where no tenant is set.
alter table audit_chain add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table audit_chain add constraint audit_chain_tenant_check check (chain_key = coalesce(tenant_id::text, 'global'));
alter table audit_chain enable row level security;
alter table audit_chain force row level security;
create policy tenant_isolation on audit_chain
    using (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on audit_chain;
alter table audit_chain no force row level security;
alter table audit_chain disable row level security;
alter table audit_chain drop constraint audit_chain_tenant_check;
alter table audit_chain drop column tenant_id;
drop policy tenant_isolation on audit_log;
alter table audit_log no force row level security;
alter table audit_log disable row level security;
drop index audit_log_entity;
create index audit_log_entity on audit_log (entity, entity_id, occurred_at);
drop index audit_log_actor;
create index audit_log_actor on audit_log (actor_id, occurred_at);
drop index audit_log_occurred_at;
create index audit_log_occurred_at on audit_log (occurred_at);
alter table audit_log drop column tenant_id;
