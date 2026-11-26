-- Bootstrap SQL: prepare an Aurora/RDS PostgreSQL database for the
-- application user. Executed by the `bootstrap` subcommand with master
-- credentials; every statement is idempotent so re-running is a no-op.
--
-- Post-bootstrap the master user is reserved for bootstrap and break-glass:
-- trusted_actions_app owns the database and schema and holds CREATEDB for
-- the per-test databases the LocalStack test helper creates.

-- The application role. No password: it authenticates with IAM tokens
-- (rds_iam membership), which is orthogonal to a login password.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'trusted_actions_app') THEN
        CREATE ROLE trusted_actions_app LOGIN;
    END IF;
END
$$;
-- Cover a pre-existing role created without LOGIN (idempotent fixup).
ALTER ROLE trusted_actions_app LOGIN;

-- Membership and privileges: the application role gets rds_iam (IAM token
-- auth) and CREATEDB (per-test databases). The master user gets membership
-- in the application role WITH SET TRUE: on RDS the master is not a
-- superuser, and the ownership transfers below require it to SET ROLE to
-- the new owner. The grant also covers a pre-existing application role the
-- master was never granted into.
GRANT rds_iam TO trusted_actions_app;
ALTER ROLE trusted_actions_app CREATEDB;
GRANT trusted_actions_app TO CURRENT_USER WITH SET TRUE;

-- Schema ownership, and coverage for a database initialized through the
-- legacy DATABASE_URL path: tables created by the legacy user (including
-- schema_migrations) stay owned by it, and PostgreSQL checks table
-- privileges separately from schema ownership — the application role would
-- get permission errors from runMigrations. Re-owning every object in the
-- schema to the application role fixes both at once, and is a no-op on a
-- database where the application role already owns everything. (Indexes
-- follow their table; altering them directly fails.)
ALTER SCHEMA public OWNER TO trusted_actions_app;
DO $$
DECLARE
    obj record;
BEGIN
    FOR obj IN
        SELECT c.relname, c.relkind
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
    LOOP
        EXECUTE format('ALTER %s public.%I OWNER TO trusted_actions_app',
            CASE obj.relkind
                WHEN 'r' THEN 'TABLE'
                WHEN 'p' THEN 'TABLE'
                WHEN 'v' THEN 'VIEW'
                WHEN 'm' THEN 'MATERIALIZED VIEW'
                WHEN 'S' THEN 'SEQUENCE'
            END,
            obj.relname);
    END LOOP;
END
$$;

-- The database-level ownership transfer (ALTER DATABASE ... OWNER TO) is
-- issued by the bootstrap subcommand after this file, as a DO block using
-- format('%I') server-side — ALTER DATABASE cannot take CURRENT_DATABASE().
