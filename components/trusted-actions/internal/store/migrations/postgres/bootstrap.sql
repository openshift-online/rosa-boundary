-- Bootstrap SQL (phase 1): prepare the roles and grants.
-- Executed by the `bootstrap` subcommand with master credentials, BEFORE
-- the database-level ownership transfer and before phase 2. Every statement
-- is idempotent so re-running is a no-op.
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
-- superuser, and the ownership transfers that follow require it to SET ROLE
-- to the new owner. The grant also covers a pre-existing application role
-- the master was never granted into.
GRANT rds_iam TO trusted_actions_app;
ALTER ROLE trusted_actions_app CREATEDB;
GRANT trusted_actions_app TO CURRENT_USER WITH SET TRUE;
