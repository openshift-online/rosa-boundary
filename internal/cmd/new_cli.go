package cmd

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	"github.com/openshift-online/rosa-boundary/internal/config"
	ocmcredentials "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// newSelectedProfile is set by the new root's --profile flag. The root auth
// hook must resolve this name (or the saved active profile) before authenticating.
var newSelectedProfile string
var newCommandCancel context.CancelFunc

// newCLI builds the opt-in command surface without registering legacy commands.
func newCLI() *cobra.Command {
	root := &cobra.Command{Use: "rosa-boundary", Short: "Manage internal ROSA investigation workspaces and sessions.", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&newSelectedProfile, "profile", "", "Saved Boundary deployment profile (active if omitted)")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "Show debug diagnostics (never secrets)")
	root.PersistentFlags().Duration("timeout", 0, "Whole-command deadline (default 5m without terminal)")
	root.PersistentFlags().BoolVar(&useDeviceCode, "use-device-code", false, "Use device approval for Boundary and default OCM flow")
	root.PersistentPreRunE = newCLIPreRun
	root.PersistentPostRun = func(*cobra.Command, []string) {
		if newCommandCancel != nil {
			newCommandCancel()
			newCommandCancel = nil
		}
	}
	root.AddCommand(newConfigCommand(), newLoginCommand(), newInvestigationCommand(), newSessionCommand(), &cobra.Command{Use: "version", Short: "Show version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), Version)
		return err
	}})
	return root
}

// newCLIPreRun runs only after Cobra validates arguments and flags. Offline
// config operations never resolve environment values or request credentials.
func newCLIPreRun(cmd *cobra.Command, _ []string) error {
	output.Verbose = verbose
	if cmd.HasAvailableSubCommands() || cmd.Name() == "version" || cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "__complete" || cmd.Name() == "__completeNoDesc" || cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
		return nil
	}
	if _, err := commandOutput(cmd); err != nil {
		return err
	}
	deadline := newDuration(cmd, "timeout")
	if deadline < 0 {
		return fmt.Errorf("--timeout must not be negative")
	}
	if deadline == 0 && !cmd.Flags().Changed("timeout") {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			deadline = 5 * time.Minute
		} else {
			_ = tty.Close()
		}
	} else if deadline == 0 {
		return fmt.Errorf("--timeout must be greater than zero")
	}
	if deadline > 0 {
		ctx, cancel := context.WithTimeout(cmd.Context(), deadline)
		newCommandCancel = cancel
		cmd.SetContext(ctx)
	}
	if cmd.Parent() != nil && cmd.Parent().Name() == "config" || cmd.Name() == "login" {
		return nil
	}
	flags := map[string]string{}
	for flag, key := range map[string]string{"region": "aws_region", "ecs-cluster": "ecs_cluster_name", "efs-filesystem-id": "efs_filesystem_id"} {
		if cmd.Flags().Changed(flag) {
			flags[key] = newString(cmd, flag)
		}
	}
	if cmd.Flags().Changed("use-device-code") {
		flags["oidc_use_device_code"] = strconv.FormatBool(newBool(cmd, "use-device-code"))
	}
	selected, cfg, err := config.ResolveWithFlags(newSelectedProfile, flags)
	if err != nil {
		return err
	}
	newSelectedProfile = selected
	required := []string{"account_id", "aws_region", "keycloak_url"}
	role := cfg.SRERoleARN
	session := "rosa-boundary-session"
	if cmd.Name() == "start" && cmd.Parent().Name() == "session" || cmd.Name() == "create" && cmd.Parent().Name() == "investigation" {
		role, session = cfg.InvokerRoleARN, "rosa-boundary-invoker"
		required = append(required, "invoker_role_arn", "lambda_function_name")
		if cmd.Name() == "start" {
			required = append(required, "ecs_cluster_name")
		}
	} else {
		required = append(required, "sre_role_arn")
		if cmd.Name() == "list" && cmd.Parent().Name() == "investigation" {
			required = append(required, "efs_filesystem_id")
		} else {
			required = append(required, "ecs_cluster_name")
		}
		if cmd.Name() == "close" {
			required = append(required, "efs_filesystem_id")
		}
	}
	if err := config.RequireSettings(cfg, required...); err != nil {
		return err
	}
	if err := newCheckRoleAccounts(cfg.AccountID, map[string]string{"invoker_role_arn": cfg.InvokerRoleARN, "sre_role_arn": cfg.SRERoleARN}); err != nil {
		return err
	}
	reporter, err := authReporter(cmd)
	if err != nil {
		return err
	}
	pkce := auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: cfg.KeycloakRealm, ClientID: cfg.OIDCClientID}
	idToken, creds, err := assumeRoleWithRetryOptions(cmd.Context(), pkce, cfg.AWSRegion, role, session, false, auth.Options{UseDeviceCode: cfg.OIDCUseDeviceCode, Reporter: reporter})
	if err != nil {
		return err
	}
	cachedAuthResult = &AuthResult{Config: cfg, IDToken: idToken, Credentials: creds}
	return nil
}

func newCheckRoleAccounts(accountID string, roles map[string]string) error {
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(accountID) {
		return fmt.Errorf("selected profile account_id must be a 12-digit AWS account ID; verify the deployment account and run 'rosa-boundary config init --help' to replace this profile with --name and --overwrite")
	}
	for name, arn := range roles {
		if arn == "" {
			continue
		}
		match := regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):role/.+$`).FindStringSubmatch(arn)
		if len(match) != 2 || match[1] != accountID {
			return fmt.Errorf("%s does not match selected profile account_id %s; verify both against the intended deployment and run 'rosa-boundary config init --help' to replace this profile with --name and --overwrite", name, accountID)
		}
	}
	return nil
}

func newGroup(use, short string) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
}

func newLeaf(use, short string, args cobra.PositionalArgs, run func(*cobra.Command, []string) error, result bool) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, Args: func(cmd *cobra.Command, values []string) error {
		if err := args(cmd, values); err != nil {
			return err
		}
		_, err := commandOutput(cmd)
		return err
	}, RunE: run}
	addOutputFlag(cmd, result)
	return cmd
}

func newDeploymentFlags(cmd *cobra.Command, ecs, efs bool) {
	cmd.Flags().String("region", "", "Boundary deployment region (configured if omitted)")
	if ecs {
		cmd.Flags().String("ecs-cluster", "", "Boundary ECS cluster (configured if omitted)")
	}
	if efs {
		cmd.Flags().String("efs-filesystem-id", "", "Investigation store (configured if omitted)")
	}
}

func newTerminalRequired() error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("an interactive session requires a controlling terminal; run this command in a terminal (not a pipe or headless job): %w", err)
	}
	defer func() { _ = tty.Close() }()
	if !term.IsTerminal(int(tty.Fd())) {
		return fmt.Errorf("an interactive session requires a controlling terminal; run this command in a terminal (not a pipe or headless job)")
	}
	return nil
}

func newNonEmptyArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(n)(cmd, args); err != nil {
			return err
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return fmt.Errorf("arguments must not be empty; run '%s --help' for usage", cmd.CommandPath())
			}
		}
		return nil
	}
}

func newLoginCommand() *cobra.Command {
	cmd := newLeaf("login", "Sign in for Boundary operations", cobra.NoArgs, func(cmd *cobra.Command, args []string) error {
		// The new root auth hook owns profile selection; login does not assume AWS roles.
		return runNewLogin(cmd)
	}, false)
	cmd.Flags().Bool("force", false, "Sign in again rather than reuse a valid session")
	return cmd
}

func newInvestigationCommand() *cobra.Command {
	group := newGroup("investigation", "Manage investigation workspaces")
	create := newLeaf("create <cluster-id>", "Create an investigation without starting a session", newNonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		createClusterID, createInvestigationID, createOutputFormat = args[0], newString(cmd, "investigation-id"), newString(cmd, "output")
		return runCreateInvestigation(cmd, nil)
	}, true)
	create.Flags().String("investigation-id", "", "Requested investigation ID")
	newDeploymentFlags(create, false, false)
	list := newLeaf("list", "List investigation workspaces, including idle ones", cobra.NoArgs, func(cmd *cobra.Command, args []string) error {
		listInvClusterID, listInvOutputFormat = newString(cmd, "cluster-id"), newString(cmd, "output")
		return runListInvestigations(cmd, args)
	}, true)
	list.Flags().String("cluster-id", "", "Limit results to a ROSA cluster")
	newDeploymentFlags(list, false, true)
	close := newLeaf("close <cluster-id> <investigation-id>", "Close an investigation workspace", newNonEmptyArgs(2), func(cmd *cobra.Command, args []string) error {
		closeClusterID, closeInvestigationID = args[0], args[1]
		closeForce, closeYes, closeDryRun = newBool(cmd, "force"), newBool(cmd, "yes"), newBool(cmd, "dry-run")
		closeOutputFormat = newString(cmd, "output")
		return runCloseInvestigation(cmd, nil)
	}, true)
	close.Args = func(cmd *cobra.Command, args []string) error {
		if err := newNonEmptyArgs(2)(cmd, args); err != nil {
			return err
		}
		if !newBool(cmd, "dry-run") && !newBool(cmd, "yes") {
			if err := newTerminalRequired(); err != nil {
				return fmt.Errorf("--yes is required without a terminal unless --dry-run: %w", err)
			}
		}
		_, err := commandOutput(cmd)
		return err
	}
	close.Flags().Bool("force", false, "Stop active sessions before closing")
	close.Flags().Bool("yes", false, "Skip confirmation")
	close.Flags().Bool("dry-run", false, "Show complete plan without making changes")
	newDeploymentFlags(close, true, true)
	group.AddCommand(create, list, close)
	return group
}

func newSessionCommand() *cobra.Command {
	group := newGroup("session", "Manage investigation sessions and their credentials")
	start := newLeaf("start <cluster-id>", "Start an investigation session", newNonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		startClusterID, startInvestigationID, startOCVersion = args[0], newString(cmd, "investigation-id"), newString(cmd, "oc-version")
		startTaskTimeout = int(newDuration(cmd, "session-timeout") / time.Second)
		startConnect, startNoWait = newBool(cmd, "connect"), newBool(cmd, "no-wait")
		startCredentials = nil
		if provider := newString(cmd, "with-credentials"); provider != "" {
			startCredentials = []string{provider}
		}
		startOCMURL, startOCMFlow, startOutputFormat = newString(cmd, "ocm-url"), newString(cmd, "ocm-auth-flow"), newString(cmd, "output")
		return runStartTask(cmd, nil)
	}, true)
	start.Flags().String("investigation-id", "", "Investigation to use (generated if omitted)")
	start.Flags().String("oc-version", "4.20", "OpenShift CLI version in the session")
	start.Flags().Duration("session-timeout", time.Hour, "Session lifetime (default 1h; policy controls minimum and maximum)")
	start.Flags().Bool("connect", false, "Join the session after it starts")
	start.Flags().Bool("no-wait", false, "Return without waiting for RUNNING")
	start.Flags().String("with-credentials", "", "Configure credentials after startup: ocm")
	start.Flags().String("ocm-url", "", "OCM environment or approved canonical URL")
	start.Flags().String("ocm-auth-flow", "", "OCM-only sign-in override: auth-code or device")
	newDeploymentFlags(start, true, false)
	start.Args = func(cmd *cobra.Command, args []string) error {
		if err := newNonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if d := newDuration(cmd, "session-timeout"); d < 0 || d > 24*time.Hour || d%time.Second != 0 {
			return fmt.Errorf("--session-timeout must be whole seconds between 0 and 24h")
		}
		if newBool(cmd, "no-wait") && (newBool(cmd, "connect") || newString(cmd, "with-credentials") != "") {
			return fmt.Errorf("--no-wait cannot be combined with --connect or --with-credentials")
		}
		if newBool(cmd, "connect") {
			if err := newTerminalRequired(); err != nil {
				return err
			}
		}
		if p := newString(cmd, "with-credentials"); p != "" && p != "ocm" {
			return fmt.Errorf("unsupported credential provider %q; use --with-credentials ocm or omit the flag", p)
		}
		if newString(cmd, "with-credentials") == "" && (cmd.Flags().Changed("ocm-url") || cmd.Flags().Changed("ocm-auth-flow")) {
			return fmt.Errorf("--ocm-url and --ocm-auth-flow require --with-credentials ocm")
		}
		if f := newString(cmd, "ocm-auth-flow"); f != "" && f != "device" && f != "auth-code" {
			return fmt.Errorf("invalid --ocm-auth-flow %q: must be auth-code or device", f)
		}
		if cmd.Flags().Changed("ocm-url") {
			if _, err := ocmcredentials.ResolveEnvironment(newString(cmd, "ocm-url")); err != nil {
				return err
			}
		}
		_, err := commandOutput(cmd)
		return err
	}
	list := newLeaf("list", "List investigation sessions", cobra.NoArgs, func(cmd *cobra.Command, args []string) error {
		listStatus, listOutputFormat = newString(cmd, "status"), newString(cmd, "output")
		return runListTasks(cmd, args)
	}, true)
	list.Flags().String("status", "RUNNING", "RUNNING, STOPPED, or all")
	newDeploymentFlags(list, true, false)
	list.Args = func(cmd *cobra.Command, args []string) error {
		if err := cobra.NoArgs(cmd, args); err != nil {
			return err
		}
		if _, err := validateListTasksStatus(newString(cmd, "status")); err != nil {
			return err
		}
		_, err := commandOutput(cmd)
		return err
	}
	join := newLeaf("join <session-id>", "Open a shell in a running session", newNonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		joinContainer, joinCommand, joinNoWait = newString(cmd, "container"), newString(cmd, "command"), newBool(cmd, "no-wait")
		return runJoinTask(cmd, args)
	}, false)
	join.Args = func(cmd *cobra.Command, args []string) error {
		if err := newNonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if err := newTerminalRequired(); err != nil {
			return err
		}
		_, err := commandOutput(cmd)
		return err
	}
	join.Flags().String("container", "rosa-boundary", "Container to enter")
	join.Flags().String("command", defaultExecCommand, "Command to run")
	join.Flags().Bool("no-wait", false, "Do not wait for RUNNING")
	newDeploymentFlags(join, true, false)
	stop := newLeaf("stop <session-id>", "Stop a session without closing its investigation", newNonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		stopReason, stopWait, stopYes = newString(cmd, "reason"), newBool(cmd, "wait"), newBool(cmd, "yes")
		return runStopTask(cmd, args)
	}, true)
	stop.Args = func(cmd *cobra.Command, args []string) error {
		if err := newNonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if !newBool(cmd, "yes") {
			if err := newTerminalRequired(); err != nil {
				return fmt.Errorf("--yes is required without a terminal: %w", err)
			}
		}
		_, err := commandOutput(cmd)
		return err
	}
	stop.Flags().String("reason", "Investigation complete", "Audit reason")
	stop.Flags().Bool("wait", false, "Wait for STOPPED state")
	stop.Flags().Bool("yes", false, "Skip confirmation")
	newDeploymentFlags(stop, true, false)
	credentials := newGroup("credentials", "Manage credentials in a running session")
	configure := newGroup("configure", "Obtain and configure credentials")
	clear := newGroup("clear", "Remove session credentials")
	configureOCM := newLeaf("ocm <session-id>", "Obtain fresh OCM access for a session", newNonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		credentialsOCMURL, credentialsOCMFlow = newString(cmd, "ocm-url"), newString(cmd, "auth-flow")
		return runCredentialsConfigureOCM(cmd, args)
	}, false)
	configureOCM.Flags().String("ocm-url", "", "OCM environment or approved canonical URL")
	configureOCM.Flags().String("auth-flow", "", "OCM-only override: auth-code or device")
	configureOCM.Args = func(cmd *cobra.Command, args []string) error {
		if err := newNonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if flow := newString(cmd, "auth-flow"); flow != "" && flow != "auth-code" && flow != "device" {
			return fmt.Errorf("invalid --auth-flow %q: use auth-code or device", flow)
		}
		if cmd.Flags().Changed("ocm-url") {
			if _, err := ocmcredentials.ResolveEnvironment(newString(cmd, "ocm-url")); err != nil {
				return err
			}
		}
		_, err := commandOutput(cmd)
		return err
	}
	newDeploymentFlags(configureOCM, true, false)
	clearOCM := newLeaf("ocm <session-id>", "Remove OCM credentials and derived kubeconfig", newNonEmptyArgs(1), runCredentialsClearOCM, false)
	newDeploymentFlags(clearOCM, true, false)
	configure.AddCommand(configureOCM)
	clear.AddCommand(clearOCM)
	credentials.AddCommand(configure, clear)
	group.AddCommand(start, list, join, stop, credentials)
	return group
}

func newString(cmd *cobra.Command, name string) string {
	value, _ := cmd.Flags().GetString(name)
	return value
}
func newBool(cmd *cobra.Command, name string) bool {
	value, _ := cmd.Flags().GetBool(name)
	return value
}
func newDuration(cmd *cobra.Command, name string) time.Duration {
	value, _ := cmd.Flags().GetDuration(name)
	return value
}
