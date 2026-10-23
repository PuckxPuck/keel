-- keel:global resolves a host before a tenant is chosen; the operator pool writes it
-- keel:procedural revokes writes on tenant_domains from every role under row-level security
-- +goose Up
create table tenant_domains (
    host text primary key check (char_length(host) between 1 and 253 and host = lower(host)),
    tenant_id uuid not null references tenants (id) on delete cascade,
    created_at timestamptz not null
);
create index tenant_domains_tenant_id on tenant_domains (tenant_id);

-- +goose StatementBegin
do $$
declare
    grantee text;
begin
    for grantee in
        select distinct a.grantee::regrole::text
        from pg_class c, aclexplode(c.relacl) a, pg_roles r
        where c.oid = 'tenant_domains'::regclass and r.oid = a.grantee
          and a.grantee <> c.relowner and not r.rolbypassrls
    loop
        execute format('revoke insert, update, delete, truncate on tenant_domains from %s', grantee);
    end loop;
end
$$;
-- +goose StatementEnd

-- +goose Down
drop table tenant_domains;
