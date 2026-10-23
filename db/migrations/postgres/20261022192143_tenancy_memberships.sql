-- keel:global sign-in reads a user's memberships before a tenant is chosen; the operator pool writes them
-- keel:procedural revokes writes on memberships from every role under row-level security
-- +goose Up
create table memberships (
    tenant_id uuid not null references tenants (id) on delete cascade,
    user_id uuid not null references users (id) on delete cascade,
    status text not null default 'active' check (status in ('active', 'disabled')),
    is_default boolean not null default false,
    created_at timestamptz not null,
    primary key (tenant_id, user_id)
);
create index memberships_user_id on memberships (user_id);
create unique index memberships_one_default on memberships (user_id) where is_default;

-- +goose StatementBegin
do $$
declare
    grantee text;
begin
    for grantee in
        select distinct a.grantee::regrole::text
        from pg_class c, aclexplode(c.relacl) a, pg_roles r
        where c.oid = 'memberships'::regclass and r.oid = a.grantee
          and a.grantee <> c.relowner and not r.rolbypassrls
    loop
        execute format('revoke insert, update, delete, truncate on memberships from %s', grantee);
    end loop;
end
$$;
-- +goose StatementEnd

-- +goose Down
drop table memberships;
