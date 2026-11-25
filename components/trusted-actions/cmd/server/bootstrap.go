package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-trusted-actions/internal/store"
)

// newBootstrapCmd builds the `bootstrap` subcommand: connect to the
// application database with master credentials and apply the idempotent
// bootstrap SQL (create the IAM-auth application user, grant rds_iam and
// CREATEDB, transfer database/schema ownership). Master credentials arrive
// via the environment (ROSA_TA_DB_MASTER_DSN) or the --dsn flag; they are
// used for this one connection and never logged or persisted.
func newBootstrapCmd() *cobra.Command {
	var dsnFlag string

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Prepare the application database for IAM token authentication",
		Long: "Apply the idempotent bootstrap SQL against the application database using " +
			"master credentials: create the trusted_actions_app role, grant it rds_iam and " +
			"CREATEDB, and transfer database and schema ownership to it. Safe to re-run — " +
			"every statement is idempotent.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBootstrap(cmd.Context(), dsnFlag)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&dsnFlag, "dsn", "",
		"master-credentials DSN (postgres://master-user:password@host:port/dbname). "+
			"Defaults to the ROSA_TA_DB_MASTER_DSN environment variable.")

	return cmd
}

// resolveBootstrapDSN picks the master-credentials DSN: the --dsn flag
// wins over the ROSA_TA_DB_MASTER_DSN environment variable; neither set is
// an error.
func resolveBootstrapDSN(dsnFlag, dsnEnv string) (string, error) {
	if dsnFlag != "" {
		return dsnFlag, nil
	}
	if dsnEnv != "" {
		return dsnEnv, nil
	}
	return "", fmt.Errorf("bootstrap needs master credentials: pass --dsn or set ROSA_TA_DB_MASTER_DSN")
}

func runBootstrap(ctx context.Context, dsnFlag string) error {
	dsn, err := resolveBootstrapDSN(dsnFlag, os.Getenv("ROSA_TA_DB_MASTER_DSN"))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02T15:04:05Z07:00"})

	if err := store.BootstrapDatabase(ctx, dsn, logger); err != nil {
		return err
	}
	logger.Info("database bootstrap complete (idempotent — safe to re-run)")
	return nil
}
