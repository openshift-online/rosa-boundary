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

GRANT rds_iam TO trusted_actions_app;
ALTER ROLE trusted_actions_app CREATEDB;

-- Hand the application database and its public schema to the application
-- user. The master user (a member of every role it creates) keeps its
-- privileges, so break-glass connections still work after the transfer.
-- The database-level ALTER is executed by BootstrapDatabase itself
-- (ALTER DATABASE cannot take CURRENT_DATABASE()), scoped to the database
-- the DSN names.
ALTER SCHEMA public OWNER TO trusted_actions_app;
