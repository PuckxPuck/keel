-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table idempotency_keys add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table idempotency_keys drop constraint idempotency_keys_realm_principal_idem_key_key;
create unique index idempotency_keys_scope_key on idempotency_keys (tenant_id, realm, principal, idem_key) nulls not distinct;
drop index idempotency_keys_expires_at;
create index idempotency_keys_expires_at on idempotency_keys (tenant_id, expires_at);
alter table idempotency_keys enable row level security;
alter table idempotency_keys force row level security;
-- A key is scoped to its realm and principal too, so a request without a tenant may see keys without one.
create policy tenant_isolation on idempotency_keys
    using (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on idempotency_keys;
alter table idempotency_keys no force row level security;
alter table idempotency_keys disable row level security;
drop index idempotency_keys_expires_at;
create index idempotency_keys_expires_at on idempotency_keys (expires_at);
drop index idempotency_keys_scope_key;
alter table idempotency_keys add constraint idempotency_keys_realm_principal_idem_key_key unique (realm, principal, idem_key);
alter table idempotency_keys drop column tenant_id;
