-- Bootstrap SQL (phase 2): ownership transfers. Executed by the `bootstrap`
-- subcommand AFTER the database-level ALTER DATABASE ... OWNER TO (which the
-- subcommand issues between phase 1 and this file — the schema transfer
-- below requires the new owner to already hold CREATE on the database,
-- which database ownership confers). Idempotent like phase 1.

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
