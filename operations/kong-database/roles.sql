\set ON_ERROR_STOP on

-- Passwords are set separately by the protected deployment secret authority.
-- This file is safe for Git and intentionally contains no role passwords.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kong_owner') THEN
    CREATE ROLE kong_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kong_runtime') THEN
    CREATE ROLE kong_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kong_migration_admin') THEN
    CREATE ROLE kong_migration_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kong_monitor') THEN
    CREATE ROLE kong_monitor LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kong_replication') THEN
    CREATE ROLE kong_replication LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      REPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kong_backup') THEN
    CREATE ROLE kong_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
      REPLICATION NOBYPASSRLS;
  END IF;
END
$roles$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Execute this bootstrap as the existing database owner/superuser. Move the
-- existing Kong objects to a non-login owner so the migration role can alter
-- them through membership without inheriting bootstrap-superuser authority.
REASSIGN OWNED BY kong TO kong_owner;
ALTER SCHEMA public OWNER TO kong_owner;
GRANT kong_owner TO kong_migration_admin;
GRANT CONNECT ON DATABASE kong TO kong_runtime, kong_migration_admin, kong_monitor;
GRANT USAGE, CREATE ON SCHEMA public TO kong_migration_admin;
GRANT USAGE ON SCHEMA public TO kong_runtime, kong_monitor;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kong_runtime;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO kong_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO kong_monitor;
ALTER DEFAULT PRIVILEGES FOR ROLE kong_migration_admin IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kong_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE kong_migration_admin IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO kong_runtime;
