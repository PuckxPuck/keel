-- Creates the owner and app roles. Requires: psql -v owner_password=... -v app_password=...
-- part:tenancy
-- With tenancy it also creates the operator login, which bypasses row-level security: -v operator_password=...
-- /part:tenancy
-- Safe to rerun: it resets any role attribute that would let the app or owner escape row-level security.
-- Append-only tables revoke UPDATE and DELETE in their own migrations.
\set ON_ERROR_STOP on

\if :{?owner_password}
\else
DO $$ BEGIN RAISE EXCEPTION 'owner_password is required: psql -v owner_password=...'; END $$;
\endif
\if :{?app_password}
\else
DO $$ BEGIN RAISE EXCEPTION 'app_password is required: psql -v app_password=...'; END $$;
\endif
-- part:tenancy
\if :{?operator_password}
\else
DO $$ BEGIN RAISE EXCEPTION 'operator_password is required: psql -v operator_password=...'; END $$;
\endif
-- /part:tenancy

SELECT format('CREATE ROLE keel_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'owner_password')
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keel_owner') \gexec
SELECT format('CREATE ROLE keel_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'app_password')
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keel_app') \gexec
-- part:tenancy
SELECT format('CREATE ROLE keel_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS PASSWORD %L', :'operator_password')
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'keel_operator') \gexec
-- /part:tenancy

-- Altering only roles that drifted means a rerun on a managed host needs no superuser when nothing is wrong.
SELECT format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', rolname)
    FROM pg_roles
    WHERE rolname IN ('keel_owner', 'keel_app')
      AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) \gexec
-- part:tenancy
SELECT format('ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS', rolname)
    FROM pg_roles
    WHERE rolname = 'keel_operator'
      AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR NOT rolbypassrls) \gexec
-- /part:tenancy

SELECT format('ALTER DATABASE %I OWNER TO keel_owner', current_database()) \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO keel_app', current_database()) \gexec

GRANT USAGE ON SCHEMA public TO keel_app;

ALTER DEFAULT PRIVILEGES FOR ROLE keel_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO keel_app;
ALTER DEFAULT PRIVILEGES FOR ROLE keel_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO keel_app;
-- part:tenancy

SELECT format('GRANT CONNECT ON DATABASE %I TO keel_operator', current_database()) \gexec
GRANT USAGE ON SCHEMA public TO keel_operator;
ALTER DEFAULT PRIVILEGES FOR ROLE keel_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO keel_operator;
ALTER DEFAULT PRIVILEGES FOR ROLE keel_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO keel_operator;
-- /part:tenancy
