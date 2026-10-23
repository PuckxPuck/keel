-- keel:global the tenant list itself, read before a tenant is chosen
-- keel:procedural revokes writes on tenants from every role under row-level security
-- +goose Up
create table tenants (
    id uuid primary key,
    slug text not null check (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    name text not null check (char_length(name) between 1 and 200),
    status text not null default 'active' check (status in ('active', 'read_only', 'suspended')),
    status_reason text check (char_length(status_reason) <= 200),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    version integer not null default 1 check (version >= 1)
);
create unique index tenants_slug_key on tenants (slug);

-- Roles held by row-level security (the app role) only read tenants; the operator pool writes them.
-- +goose StatementBegin
do $$
declare
    grantee text;
begin
    for grantee in
        select distinct a.grantee::regrole::text
        from pg_class c, aclexplode(c.relacl) a, pg_roles r
        where c.oid = 'tenants'::regclass and r.oid = a.grantee
          and a.grantee <> c.relowner and not r.rolbypassrls
    loop
        execute format('revoke insert, update, delete, truncate on tenants from %s', grantee);
    end loop;
end
$$;
-- +goose StatementEnd

-- +goose Down
drop table tenants;
