package store

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/postgres/bootstrap.sql
var bootstrapSQL string

// appRoleName is the single database role the application authenticates as.
// It matches the role the SQL file creates.
const appRoleName = "trusted_actions_app"

// BootstrapDatabase applies the idempotent bootstrap SQL to the database the
// DSN points at, using master credentials. It creates the trusted_actions_app
// role (LOGIN, IAM-token authentication, CREATEDB), grants it rds_iam, and
// transfers database and schema ownership to it. Re-running is a no-op.
//
// The DSN is used for this one connection only and never logged.
func BootstrapDatabase(ctx context.Context, dsn string, logger *logrus.Logger) error {
	if dsn == "" {
		return fmt.Errorf("bootstrap requires a master-credentials DSN")
	}

	// Single connection, no pool tuning: a one-shot administrative command.
	db, err := sqlx.Connect("pgx", dsn)
	if err != nil {
		return fmt.Errorf("connecting with master credentials: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			logger.WithError(closeErr).Warn("Failed to close bootstrap connection")
		}
	}()

	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		return fmt.Errorf("applying bootstrap SQL: %w", err)
	}

	// ALTER DATABASE cannot take CURRENT_DATABASE(), so the database-level
	// ownership transfer is issued separately, quoted for the database the
	// DSN selected. Idempotent like the SQL file.
	if _, err := db.ExecContext(ctx,
		fmt.Sprintf(`ALTER DATABASE %s OWNER TO %s`,
			quoteIdent(currentDatabaseName(ctx, db)), appRoleName)); err != nil {
		return fmt.Errorf("transferring database ownership: %w", err)
	}

	// Post-conditions: the role exists, can log in, holds rds_iam and
	// CREATEDB, and owns the current database. Asserted rather than assumed
	// so a partial bootstrap (e.g. an interrupted run) fails loudly instead
	// of leaving a half-prepared database behind.
	var ok bool
	for _, check := range []struct {
		name  string
		query string
	}{
		{"role exists", `SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = '` + appRoleName + `')`},
		{"role can log in", `SELECT rolcanlogin FROM pg_roles WHERE rolname = '` + appRoleName + `'`},
		{"rds_iam membership", `SELECT pg_has_role('` + appRoleName + `', 'rds_iam', 'MEMBER')`},
		{"CREATEDB attribute", `SELECT rolcreatedb FROM pg_roles WHERE rolname = '` + appRoleName + `'`},
		{"database ownership", `SELECT pg_catalog.pg_get_userbyid(datdba) = '` + appRoleName + `' FROM pg_database WHERE datname = current_database()`},
	} {
		if err := db.GetContext(ctx, &ok, check.query); err != nil {
			return fmt.Errorf("checking %s: %w", check.name, err)
		}
		if !ok {
			return fmt.Errorf("bootstrap post-condition failed: %s", check.name)
		}
	}

	return nil
}

// currentDatabaseName resolves the database the DSN selected. On query
// error it returns the empty string, which makes the ownership ALTER fail
// loudly rather than guess.
func currentDatabaseName(ctx context.Context, db *sqlx.DB) string {
	var name string
	_ = db.GetContext(ctx, &name, `SELECT current_database()`)
	return name
}

// quoteIdent double-quotes a SQL identifier, escaping embedded quotes.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
