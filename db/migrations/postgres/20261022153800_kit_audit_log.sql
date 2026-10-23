-- keel:procedural revokes update, delete and truncate on audit_log from every grantee
-- +goose Up
create table audit_log (
    id uuid primary key,
    seq bigint generated always as identity unique,
    occurred_at timestamptz not null,
    realm text check (char_length(realm) between 1 and 64),
    actor_type text not null check (actor_type in ('user', 'system', 'apikey', 'device')),
    actor_id uuid,
    on_behalf_of uuid,
    action text not null check (char_length(action) between 1 and 64),
    entity text not null check (char_length(entity) <= 64),
    entity_id text not null check (char_length(entity_id) <= 128),
    before jsonb,
    after jsonb,
    ip text check (char_length(ip) <= 45),
    request_id text check (char_length(request_id) <= 64),
    prev_hash bytea,
    hash bytea
);
create index audit_log_entity on audit_log (entity, entity_id, occurred_at);
create index audit_log_actor on audit_log (actor_id, occurred_at);
create index audit_log_occurred_at on audit_log (occurred_at);

-- Append-only: whoever the default privileges granted UPDATE, DELETE or TRUNCATE to loses them here.
-- +goose StatementBegin
do $$
declare
    grantee text;
begin
    for grantee in
        select distinct a.grantee::regrole::text
        from pg_class c, aclexplode(c.relacl) a
        where c.oid = 'audit_log'::regclass
          and a.privilege_type in ('UPDATE', 'DELETE', 'TRUNCATE')
          and a.grantee <> c.relowner
          and a.grantee <> 0
    loop
        execute format('revoke update, delete, truncate on audit_log from %s', grantee);
    end loop;
end
$$;
-- +goose StatementEnd

-- +goose Down
drop table audit_log;
