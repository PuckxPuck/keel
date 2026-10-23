-- The app and operator roles cannot read keel_migrations; serve's schema check reads applied versions through this.
-- keel:procedural grants the ledger function to the app and operator roles where they exist
-- +goose Up
create or replace function public.keel_migrations_applied() returns setof bigint
    language sql stable security definer set search_path = pg_catalog, pg_temp
    as $$ select version_id from keel_migrations.goose_db_version where version_id > 0 $$;
revoke all on function public.keel_migrations_applied() from public;
-- +goose StatementBegin
do $$
begin
    if exists (select from pg_roles where rolname = 'keel_app') then
        grant execute on function public.keel_migrations_applied() to keel_app;
    end if;
    if exists (select from pg_roles where rolname = 'keel_operator') then
        grant execute on function public.keel_migrations_applied() to keel_operator;
    end if;
end
$$;
-- +goose StatementEnd

-- +goose Down
drop function public.keel_migrations_applied();
