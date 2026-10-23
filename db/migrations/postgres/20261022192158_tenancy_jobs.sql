-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table jobs add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
drop index jobs_open_unique;
create unique index jobs_open_unique on jobs (tenant_id, unique_key) nulls not distinct
    where status in ('queued', 'running') and unique_key is not null;
drop index jobs_finished;
create index jobs_finished on jobs (tenant_id, finished_at) where status in ('done', 'failed', 'cancelled');
alter table jobs enable row level security;
alter table jobs force row level security;
create policy tenant_isolation on jobs
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on jobs;
alter table jobs no force row level security;
alter table jobs disable row level security;
drop index jobs_finished;
create index jobs_finished on jobs (finished_at) where status in ('done', 'failed', 'cancelled');
drop index jobs_open_unique;
create unique index jobs_open_unique on jobs (unique_key) where status in ('queued', 'running');
alter table jobs drop column tenant_id;
