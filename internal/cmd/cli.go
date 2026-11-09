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

// selectedProfile is set by the root --profile flag and resolved before authentication.
var selectedProfile string
var commandCancel context.CancelFunc

// buildRootCommand builds the only supported command tree.
func buildRootCommand() *cobra.Command {
	root := &cobra.Command{Use: "rosa-boundary", Short: "Manage internal ROSA investigation workspaces and sessions.", SilenceUsage: true, SilenceErrors: true}
	root.Args = commandArgs(cobra.NoArgs)
	root.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error { return inputError(cmd, err) })
	root.PersistentFlags().StringVar(&selectedProfile, "profile", "", "Saved Boundary deployment profile (active if omitted)")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "Show debug diagnostics (never secrets)")
	root.PersistentFlags().Duration("timeout", 0, "Whole-command deadline (default 5m without terminal)")
	root.PersistentFlags().Bool("use-device-code", false, "Use device approval for Boundary and default OCM flow")
	// pflag renders boolean flags with [=true|false] in help. Keep explicit
	// =false parsing, but present the ordinary bare-flag form in help text.
	cobra.AddTemplateFunc("normalBoolHelp", func(usage string) string {
		return strings.ReplaceAll(usage, "[=true|false]", strings.Repeat(" ", len("[=true|false]")))
	})
	root.SetHelpTemplate(strings.Replace(root.HelpTemplate(), "{{.UsageString}}", "{{.UsageString | normalBoolHelp}}", 1))
	root.PersistentPreRunE = commandPreRun
	root.PersistentPostRun = func(*cobra.Command, []string) {
		if commandCancel != nil {
			commandCancel()
			commandCancel = nil
		}
	}
	root.AddCommand(buildConfigCommand(), buildLoginCommand(), buildInvestigationCommand(), buildSessionCommand(), &cobra.Command{Use: "version", Short: "Show version", Args: commandArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), Version)
		return err
	}})
	return root
}

// commandPreRun runs only after Cobra validates arguments and flags. Offline
// config operations never resolve environment values or request credentials.
func commandPreRun(cmd *cobra.Command, _ []string) error {
	output.Verbose = verbose
	if cmd.HasAvailableSubCommands() || cmd.Name() == "version" || cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "__complete" || cmd.Name() == "__completeNoDesc" || cmd.Parent() != nil && cmd.Parent().Name() == "completion" {
		return nil
	}
	if _, err := commandOutput(cmd); err != nil {
		return inputError(cmd, err)
	}
	deadline := flagDuration(cmd, "timeout")
	if deadline < 0 {
		return inputError(cmd, fmt.Errorf("--timeout must not be negative"))
	}
	if deadline == 0 && !cmd.Flags().Changed("timeout") {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			deadline = 5 * time.Minute
		} else {
			_ = tty.Close()
		}
	} else if deadline == 0 {
		return inputError(cmd, fmt.Errorf("--timeout must be greater than zero"))
	}
	if deadline > 0 {
		ctx, cancel := context.WithTimeout(cmd.Context(), deadline)
		commandCancel = cancel
		cmd.SetContext(ctx)
	}
	if cmd.Parent() != nil && cmd.Parent().Name() == "config" || cmd.Name() == "login" {
		return nil
	}
	flags := map[string]string{}
	for flag, key := range map[string]string{"region": "aws_region", "ecs-cluster": "ecs_cluster_name", "efs-filesystem-id": "efs_filesystem_id"} {
		if cmd.Flags().Changed(flag) {
			flags[key] = flagString(cmd, flag)
		}
	}
	if cmd.Flags().Changed("use-device-code") {
		flags["oidc_use_device_code"] = strconv.FormatBool(flagBool(cmd, "use-device-code"))
	}
	selected, cfg, err := config.ResolveWithFlags(selectedProfile, flags)
	if err != nil {
		return err
	}
	selectedProfile = selected
	required := []string{"account_id", "aws_region", "keycloak_url"}
	role := cfg.SRERoleARN
	session := "rosa-boundary-session"
	if cmd.Name() == "create" && (cmd.Parent().Name() == "session" || cmd.Parent().Name() == "investigation") {
		role, session = cfg.InvokerRoleARN, "rosa-boundary-invoker"
		required = append(required, "invoker_role_arn", "lambda_function_name")
		if cmd.Parent().Name() == "session" {
			required = append(required, "ecs_cluster_name")
		}
	} else {
		required = append(required, "sre_role_arn")
		if cmd.Name() == "list" && cmd.Parent().Name() == "investigation" {
			required = append(required, "efs_filesystem_id")
		} else {
			required = append(required, "ecs_cluster_name")
		}
		if cmd.Name() == "close" && cmd.Parent().Name() == "investigation" {
			required = append(required, "efs_filesystem_id")
		}
	}
	if err := config.RequireSettings(cfg, required...); err != nil {
		return err
	}
	if err := checkRoleAccounts(cfg.AccountID, map[string]string{"invoker_role_arn": cfg.InvokerRoleARN, "sre_role_arn": cfg.SRERoleARN}); err != nil {
		return err
	}
	if _, err := commandOutput(cmd); err != nil {
		return err
	}
	pkce := auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: cfg.KeycloakRealm, ClientID: cfg.OIDCClientID}
	idToken, creds, err := assumeRoleWithRetryOptions(cmd.Context(), pkce, cfg.AWSRegion, role, session, false, auth.Options{UseDeviceCode: cfg.OIDCUseDeviceCode})
	if err != nil {
		return err
	}
	cachedAuthResult = &AuthResult{Config: cfg, IDToken: idToken, Credentials: creds}
	return nil
}

func checkRoleAccounts(accountID string, roles map[string]string) error {
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

func commandGroup(use, short string) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Args: commandArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() }}
}

func commandLeaf(use, short string, args cobra.PositionalArgs, run func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, Args: commandArgs(func(cmd *cobra.Command, values []string) error {
		if err := args(cmd, values); err != nil {
			return err
		}
		_, err := commandOutput(cmd)
		return err
	}), RunE: run}
	addOutputFlag(cmd)
	return cmd
}

func deploymentFlags(cmd *cobra.Command, ecs, efs bool) {
	cmd.Flags().String("region", "", "Boundary deployment region (configured if omitted)")
	if ecs {
		cmd.Flags().String("ecs-cluster", "", "Boundary ECS cluster (configured if omitted)")
	}
	if efs {
		cmd.Flags().String("efs-filesystem-id", "", "Investigation store (configured if omitted)")
	}
}

// requireTerminal is replaceable by serial tests that exercise headless guards.
var requireTerminal = func() error {
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

func nonEmptyArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < n {
			// Use declares positional placeholders in order, including the second
			// investigation ID in "investigation close".
			placeholders := strings.Fields(cmd.Use)
			if len(placeholders) > len(args)+1 {
				return fmt.Errorf("missing required argument %s", placeholders[len(args)+1])
			}
			return fmt.Errorf("missing required argument (expected %d)", n)
		}
		if len(args) > n {
			return fmt.Errorf("unexpected argument %q (expected %d positional argument(s))", args[n], n)
		}
		for _, arg := range args {
			if strings.TrimSpace(arg) == "" {
				return fmt.Errorf("arguments must not be empty; run '%s --help' for usage", cmd.CommandPath())
			}
		}
		return nil
	}
}

// inputError retains the specific validation failure while giving the exact
// command syntax and a short way to find flag/argument documentation.
func inputError(cmd *cobra.Command, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w\nUsage: %s\nRun '%s --help' for details.", err, cmd.UseLine(), cmd.CommandPath())
}

func commandArgs(validate cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		return inputError(cmd, validate(cmd, args))
	}
}

func buildLoginCommand() *cobra.Command {
	cmd := commandLeaf("login", "Sign in for Boundary operations", cobra.NoArgs, func(cmd *cobra.Command, args []string) error {
		// The root auth hook owns profile selection; login does not assume AWS roles.
		return runLogin(cmd)
	})
	cmd.Flags().Bool("force", false, "Sign in again rather than reuse a valid session")
	return cmd
}

func buildInvestigationCommand() *cobra.Command {
	group := commandGroup("investigation", "Manage investigation workspaces")
	create := commandLeaf("create <cluster-id>", "Create an investigation without starting a session", nonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		createClusterID, createInvestigationID, createOutputFormat = args[0], flagString(cmd, "investigation-id"), flagString(cmd, "output")
		return runCreateInvestigation(cmd, nil)
	})
	create.Flags().String("investigation-id", "", "Requested investigation ID")
	deploymentFlags(create, false, false)
	list := commandLeaf("list", "List investigation workspaces, including idle ones", cobra.NoArgs, func(cmd *cobra.Command, args []string) error {
		listInvClusterID, listInvOutputFormat = flagString(cmd, "cluster-id"), flagString(cmd, "output")
		return runListInvestigations(cmd, args)
	})
	list.Flags().String("cluster-id", "", "Limit results to a ROSA cluster")
	deploymentFlags(list, false, true)
	close := commandLeaf("close <cluster-id> <investigation-id>", "Close an investigation workspace", nonEmptyArgs(2), func(cmd *cobra.Command, args []string) error {
		closeClusterID, closeInvestigationID = args[0], args[1]
		closeForce, closeYes, closeDryRun = flagBool(cmd, "force"), flagBool(cmd, "yes"), flagBool(cmd, "dry-run")
		closeOutputFormat = flagString(cmd, "output")
		return runCloseInvestigation(cmd, nil)
	})
	close.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if err := nonEmptyArgs(2)(cmd, args); err != nil {
			return err
		}
		if !flagBool(cmd, "dry-run") && !flagBool(cmd, "yes") {
			if err := requireTerminal(); err != nil {
				return fmt.Errorf("--yes is required without a terminal unless --dry-run: %w", err)
			}
		}
		_, err := commandOutput(cmd)
		return err
	})
	close.Flags().Bool("force", false, "Stop active sessions before closing")
	close.Flags().Bool("yes", false, "Skip confirmation")
	close.Flags().Bool("dry-run", false, "Show complete plan without making changes")
	deploymentFlags(close, true, true)
	group.AddCommand(create, list, close)
	return group
}

func buildSessionCommand() *cobra.Command {
	group := commandGroup("session", "Manage investigation sessions and their credentials")
	group.Long = "Manage investigation sessions and their credentials.\n\nBoundary sign-in and OCM authorization may require separate human approvals. Credential injection cannot be combined with --no-wait."
	group.Example = `  # Create a session with a new, auto-generated investigation ID
  rosa-boundary session create <cluster-id>

  # Create a session in an existing investigation
  rosa-boundary session create <cluster-id> --investigation-id <investigation-id>

  # Configure fresh OCM credentials in an existing session
  rosa-boundary session credentials configure ocm <session-id>

  # Create a session with a new investigation and OCM credentials
  rosa-boundary session create <cluster-id> --with-credentials ocm`
	group.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			switch args[0] {
			case "start":
				return fmt.Errorf("session start is no longer supported; use 'rosa-boundary session create <cluster-id>' (see 'rosa-boundary session create --help')")
			case "stop":
				return fmt.Errorf("session stop is no longer supported; use 'rosa-boundary session close <session-id>' (see 'rosa-boundary session close --help'); closing the session leaves its investigation open")
			}
		}
		return cobra.NoArgs(cmd, args)
	})
	start := commandLeaf("create <cluster-id>", "Create an investigation session", nonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		startClusterID, startInvestigationID, startOCVersion = args[0], flagString(cmd, "investigation-id"), flagString(cmd, "oc-version")
		sessionTimeoutSeconds = int(flagDuration(cmd, "session-timeout") / time.Second)
		startConnect, startNoWait = flagBool(cmd, "connect"), flagBool(cmd, "no-wait")
		startCredentials = flagString(cmd, "with-credentials")
		startOCMURL, startOCMFlow, startOutputFormat = flagString(cmd, "ocm-url"), flagString(cmd, "ocm-auth-flow"), flagString(cmd, "output")
		return runStartSession(cmd, nil)
	})
	start.Flags().String("investigation-id", "", "Investigation to use (generated if omitted)")
	start.Flags().String("oc-version", "4.20", "OpenShift CLI version in the session")
	start.Flags().Duration("session-timeout", time.Hour, "Session lifetime (default 1h; policy controls minimum and maximum)")
	start.Flags().Bool("connect", false, "Join the session after it starts")
	start.Flags().Bool("no-wait", false, "Return without waiting for RUNNING")
	start.Flags().String("with-credentials", "", "Configure credentials after startup: ocm")
	start.Flags().String("ocm-url", "", "OCM environment or approved canonical URL")
	start.Flags().String("ocm-auth-flow", "", "OCM-only sign-in override: auth-code or device")
	deploymentFlags(start, true, false)
	start.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if err := nonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if d := flagDuration(cmd, "session-timeout"); d < 0 || d > 24*time.Hour || d%time.Second != 0 {
			return fmt.Errorf("--session-timeout must be whole seconds between 0 and 24h")
		}
		if flagBool(cmd, "no-wait") && (flagBool(cmd, "connect") || flagString(cmd, "with-credentials") != "") {
			return fmt.Errorf("--no-wait cannot be combined with --connect or --with-credentials")
		}
		if flagBool(cmd, "connect") {
			if err := requireTerminal(); err != nil {
				return err
			}
		}
		if p := flagString(cmd, "with-credentials"); p != "" && p != "ocm" {
			return fmt.Errorf("unsupported credential provider %q; use --with-credentials ocm or omit the flag", p)
		}
		if flagString(cmd, "with-credentials") == "" && (cmd.Flags().Changed("ocm-url") || cmd.Flags().Changed("ocm-auth-flow")) {
			return fmt.Errorf("--ocm-url and --ocm-auth-flow require --with-credentials ocm")
		}
		if f := flagString(cmd, "ocm-auth-flow"); f != "" && f != "device" && f != "auth-code" {
			return fmt.Errorf("invalid --ocm-auth-flow %q: must be auth-code or device", f)
		}
		if cmd.Flags().Changed("ocm-url") {
			if _, err := ocmcredentials.ResolveEnvironment(flagString(cmd, "ocm-url")); err != nil {
				return err
			}
		}
		_, err := commandOutput(cmd)
		return err
	})
	list := commandLeaf("list", "List investigation sessions", cobra.NoArgs, func(cmd *cobra.Command, args []string) error {
		listStatus, listOutputFormat = flagString(cmd, "status"), flagString(cmd, "output")
		return runListSessions(cmd, args)
	})
	list.Flags().String("status", "RUNNING", "RUNNING, STOPPED, or all")
	deploymentFlags(list, true, false)
	list.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if err := cobra.NoArgs(cmd, args); err != nil {
			return err
		}
		if _, err := validateListSessionsStatus(flagString(cmd, "status")); err != nil {
			return err
		}
		_, err := commandOutput(cmd)
		return err
	})
	join := commandLeaf("join <session-id>", "Open a shell in a running session", nonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		joinContainer, joinCommand, joinNoWait = flagString(cmd, "container"), flagString(cmd, "command"), flagBool(cmd, "no-wait")
		return runJoinSession(cmd, args)
	})
	join.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if err := nonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if _, err := commandOutput(cmd); err != nil {
			return err
		}
		if err := requireTerminal(); err != nil {
			return err
		}
		return nil
	})
	join.Flags().String("container", "rosa-boundary", "Container to enter")
	join.Flags().String("command", defaultExecCommand, "Command to run")
	join.Flags().Bool("no-wait", false, "Do not wait for RUNNING")
	deploymentFlags(join, true, false)
	stop := commandLeaf("close <session-id>", "Close a session without closing its investigation", nonEmptyArgs(1), func(cmd *cobra.Command, args []string) error {
		stopReason, stopWait, stopYes = flagString(cmd, "reason"), flagBool(cmd, "wait"), flagBool(cmd, "yes")
		return runStopSession(cmd, args)
	})
	stop.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if err := nonEmptyArgs(1)(cmd, args); err != nil {
			return err
		}
		if !flagBool(cmd, "yes") {
			if err := requireTerminal(); err != nil {
				return fmt.Errorf("--yes is required without a terminal: %w", err)
			}
		}
		_, err := commandOutput(cmd)
		return err
	})
	stop.Flags().String("reason", "Investigation complete", "Audit reason")
	stop.Flags().Bool("wait", false, "Wait for STOPPED state")
	stop.Flags().Bool("yes", false, "Skip confirmation")
	deploymentFlags(stop, true, false)
	credentials := commandGroup("credentials", "Manage credentials in a running session")
	configure := commandGroup("configure", "Obtain and configure credentials")
	clear := commandGroup("clear", "Remove session credentials")
	configureOCM := commandLeaf("ocm [session-id]", "Obtain fresh OCM access for a session", optionalCredentialSessionID, func(cmd *cobra.Command, args []string) error {
		credentialsOCMURL, credentialsOCMFlow = flagString(cmd, "ocm-url"), flagString(cmd, "auth-flow")
		return runCredentialsConfigureOCM(cmd, args)
	})
	configureOCM.Long = "Obtain fresh OCM access for a session. Without a session ID, discover your RUNNING sessions and suggest a command without changing credentials."
	configureOCM.Flags().String("ocm-url", "", "OCM environment or approved canonical URL")
	configureOCM.Flags().String("auth-flow", "", "OCM-only override: auth-code or device")
	configureOCM.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if err := optionalCredentialSessionID(cmd, args); err != nil {
			return err
		}
		if flow := flagString(cmd, "auth-flow"); cmd.Flags().Changed("auth-flow") && flow != "auth-code" && flow != "device" {
			return fmt.Errorf("invalid --auth-flow %q: use auth-code or device", flow)
		}
		if cmd.Flags().Changed("ocm-url") {
			if _, err := ocmcredentials.ResolveEnvironment(flagString(cmd, "ocm-url")); err != nil {
				return err
			}
		}
		_, err := commandOutput(cmd)
		return err
	})
	deploymentFlags(configureOCM, true, false)
	clearOCM := commandLeaf("ocm [session-id]", "Remove OCM credentials and derived kubeconfig", optionalCredentialSessionID, runCredentialsClearOCM)
	clearOCM.Long = "Remove OCM credentials and derived kubeconfig. Without a session ID, discover your RUNNING sessions and suggest a command without changing credentials."
	deploymentFlags(clearOCM, true, false)
	configure.AddCommand(configureOCM)
	clear.AddCommand(clearOCM)
	credentials.AddCommand(configure, clear)
	group.AddCommand(start, list, join, stop, credentials)
	return group
}

func flagString(cmd *cobra.Command, name string) string {
	value, _ := cmd.Flags().GetString(name)
	return value
}
func flagBool(cmd *cobra.Command, name string) bool {
	value, _ := cmd.Flags().GetBool(name)
	return value
}
func flagDuration(cmd *cobra.Command, name string) time.Duration {
	value, _ := cmd.Flags().GetDuration(name)
	return value
}
