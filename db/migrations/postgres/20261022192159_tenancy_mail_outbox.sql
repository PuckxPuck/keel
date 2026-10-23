-- Tenancy is installed with the app (keel init), on empty tables.
-- keel:contract
-- +goose Up
alter table mail_outbox add column tenant_id uuid default (nullif(current_setting('app.tenant_id', true), '')::uuid) references tenants (id);
alter table mail_outbox drop constraint mail_outbox_message_id_seq_key;
create unique index mail_outbox_message_id_seq_key on mail_outbox (tenant_id, message_id, seq) nulls not distinct;
drop index mail_outbox_created_at;
create index mail_outbox_created_at on mail_outbox (tenant_id, created_at);
alter table mail_outbox enable row level security;
alter table mail_outbox force row level security;
create policy tenant_isolation on mail_outbox
    using (tenant_id = (select nullif(current_setting('app.tenant_id', true), '')::uuid))
    with check (tenant_id is not distinct from (select nullif(current_setting('app.tenant_id', true), '')::uuid));

-- +goose Down
drop policy tenant_isolation on mail_outbox;
alter table mail_outbox no force row level security;
alter table mail_outbox disable row level security;
drop index mail_outbox_created_at;
create index mail_outbox_created_at on mail_outbox (created_at);
drop index mail_outbox_message_id_seq_key;
alter table mail_outbox add constraint mail_outbox_message_id_seq_key unique (message_id, seq);
alter table mail_outbox drop column tenant_id;
