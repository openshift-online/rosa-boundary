package cmd

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
	"github.com/openshift-online/rosa-boundary/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var profileName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func buildConfigCommand() *cobra.Command {
	group := commandGroup("config", "Manage Boundary deployment profiles")
	group.Args = commandArgs(func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			switch args[0] {
			case "list":
				return fmt.Errorf("config list is no longer supported; use 'rosa-boundary config list-profiles' (see 'rosa-boundary config list-profiles --help')")
			case "use":
				return fmt.Errorf("config use is no longer supported; use 'rosa-boundary config use-profile <name>' (see 'rosa-boundary config use-profile --help')")
			}
		}
		return cobra.NoArgs(cmd, args)
	})
	init := commandLeaf("init", "Add a deployment profile", cobra.NoArgs, runConfigInit)
	for _, flag := range []struct{ name, help string }{
		{"name", "Profile name (required without a terminal)"}, {"account-id", "AWS account containing Boundary"}, {"region", "Boundary deployment region"},
		{"project", "Deployment project (default rosa-boundary)"}, {"environment", "Deployment environment (default prod)"},
		{"keycloak-url", "OIDC provider base URL"}, {"realm", "OIDC realm (default EmployeeIDP)"}, {"client-id", "OIDC client ID (default rosa-boundary-sre)"},
		{"lambda-function-name", "Create-investigation Lambda"}, {"invoker-role-arn", "Lambda invoker role ARN"}, {"sre-role-arn", "SRE role ARN"},
		{"ecs-cluster", "Boundary ECS cluster"}, {"efs-filesystem-id", "Investigation EFS filesystem"},
	} {
		init.Flags().String(flag.name, "", flag.help)
	}
	init.Flags().Bool("auto-discover", true, "Discover deployment settings (use --auto-discover=false for manual setup)")
	init.Flags().Bool("use", false, "Make the profile active")
	init.Flags().Bool("overwrite", false, "Allow replacing an existing profile")
	init.Flags().Bool("yes", false, "Skip replacement confirmation (requires --overwrite)")
	list := &cobra.Command{Use: "list-profiles", Short: "List saved profiles and the active profile", Args: commandArgs(cobra.NoArgs), RunE: runConfigList}
	use := &cobra.Command{Use: "use-profile <name>", Short: "Set the active profile", Args: commandArgs(nonEmptyArgs(1)), RunE: runConfigUse}
	get := &cobra.Command{Use: "get [key]", Short: "Read a saved profile or one key", Args: commandArgs(cobra.MaximumNArgs(1)), RunE: runConfigGet}
	group.AddCommand(init, list, use, get)
	return group
}

func promptField(cmd *cobra.Command, flag, label, fallback string) (string, error) {
	value := strings.TrimSpace(flagString(cmd, flag))
	if value != "" {
		return value, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return fallback, nil
	}
	prompt, restore, err := newConfigurePrompt()
	if err != nil {
		return "", err
	}
	defer restore()
	return prompt(label, "", fallback)
}

func runConfigInit(cmd *cobra.Command, _ []string) error {
	if flagBool(cmd, "yes") && !flagBool(cmd, "overwrite") {
		return inputError(cmd, fmt.Errorf("--yes requires --overwrite"))
	}
	if selectedProfile != "" {
		return inputError(cmd, fmt.Errorf("--profile is not used by config init; use --name to name the new profile"))
	}
	name, err := promptField(cmd, "name", "Profile name", "")
	if err != nil {
		return err
	}
	if name != "" && !profileName.MatchString(name) {
		return inputError(cmd, fmt.Errorf("--name must start with a letter or digit and contain only letters, digits, '.', '_' or '-'; choose another name"))
	}
	file, err := config.LoadProfiles()
	if err != nil {
		return err
	}
	if _, exists := file.Profiles[name]; exists {
		if !flagBool(cmd, "overwrite") {
			return fmt.Errorf("profile %q already exists; pass --overwrite to replace it", name)
		}
		if !flagBool(cmd, "yes") {
			if err := requireTerminal(); err != nil {
				return fmt.Errorf("--yes is required to replace a profile without a terminal: %w", err)
			}
			answer, err := promptField(cmd, "", "Replace existing profile? Type yes", "")
			if err != nil {
				return err
			}
			if answer != "yes" {
				return fmt.Errorf("profile replacement canceled; no settings were changed (retry with --overwrite after reviewing the deployment settings)")
			}
		}
	}
	fields := []struct{ flag, label, fallback string }{
		{"account-id", "AWS account ID", ""}, {"region", "Boundary region", ""}, {"project", "Project", "rosa-boundary"}, {"environment", "Environment", "prod"},
		{"keycloak-url", "Keycloak URL", "https://auth.redhat.com/auth"}, {"realm", "Keycloak realm", "EmployeeIDP"}, {"client-id", "OIDC client ID", "rosa-boundary-sre"},
	}
	auto := flagBool(cmd, "auto-discover")
	if !auto {
		fields[4].fallback = ""
	} // Manual setup must supply an issuer; never silently inherit bootstrap defaults.
	values := make(map[string]string)
	for _, field := range fields {
		values[field.flag], err = promptField(cmd, field.flag, field.label, field.fallback)
		if err != nil {
			return err
		}
	}
	if !auto {
		for _, field := range []struct{ flag, label string }{{"lambda-function-name", "Lambda function"}, {"invoker-role-arn", "Invoker role ARN"}, {"sre-role-arn", "SRE role ARN"}, {"ecs-cluster", "ECS cluster"}, {"efs-filesystem-id", "EFS filesystem ID"}} {
			values[field.flag], err = promptField(cmd, field.flag, field.label, "")
			if err != nil {
				return err
			}
		}
	}
	required := []string{"account-id", "region"}
	if !auto {
		required = append(required, "keycloak-url", "lambda-function-name", "invoker-role-arn", "sre-role-arn", "ecs-cluster", "efs-filesystem-id")
	}
	var missing []string
	if name == "" {
		missing = append(missing, "--name")
	}
	for _, key := range required {
		if values[key] == "" {
			missing = append(missing, "--"+key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required settings: %s; supply these flags or run 'rosa-boundary config init --help' for interactive setup", strings.Join(missing, ", "))
	}
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(values["account-id"]) {
		return inputError(cmd, fmt.Errorf("--account-id must be a 12-digit AWS account ID"))
	}
	devicePreference := configureDeviceCode(cmd)
	profile := config.Profile{AccountID: values["account-id"], AWSRegion: values["region"], Project: values["project"], Environment: values["environment"], KeycloakURL: values["keycloak-url"], KeycloakRealm: values["realm"], OIDCClientID: values["client-id"], OIDCUseDeviceCode: &devicePreference, LambdaFunctionName: values["lambda-function-name"], InvokerRoleARN: values["invoker-role-arn"], SRERoleARN: values["sre-role-arn"], ClusterName: values["ecs-cluster"], EFSFilesystemID: values["efs-filesystem-id"]}
	if auto {
		pkce := auth.PKCEConfig{KeycloakURL: profile.KeycloakURL, Realm: profile.KeycloakRealm, ClientID: profile.OIDCClientID}
		if _, err := commandOutput(cmd); err != nil {
			return err
		}
		idToken, err := auth.GetTokenWithOptions(cmd.Context(), pkce, true, auth.Options{UseDeviceCode: devicePreference})
		if err != nil {
			return fmt.Errorf("OIDC discovery authentication failed; check the issuer/client and complete the selected sign-in flow, or use --auto-discover=false with operator-confirmed settings: %w", err)
		}
		role := DeriveInvokerRoleARN(profile.AccountID, profile.Project, profile.Environment)
		creds, err := awsclient.AssumeRoleWithWebIdentity(cmd.Context(), profile.AWSRegion, role, idToken, "rosa-boundary-config-init")
		if err != nil {
			return fmt.Errorf("discovery role assumption failed; verify the account ID, project, environment, and invoker role trust for this deployment: %w", err)
		}
		response, err := lambda.New(DeriveLambdaFunctionName(profile.Project, profile.Environment), profile.AWSRegion, awsclient.StaticCredentialsProvider(creds)).GetConfig(cmd.Context())
		if err != nil {
			return fmt.Errorf("deployment discovery failed; verify the account/region and the derived create-investigation Lambda, or use --auto-discover=false with operator-confirmed settings: %w", err)
		}
		if err := checkDiscoveryIdentity(profile, response); err != nil {
			return err
		}
		profile.LambdaFunctionName, profile.InvokerRoleARN, profile.SRERoleARN = response.LambdaFunctionName, response.InvokerRoleARN, response.SRERoleARN
		profile.ClusterName, profile.EFSFilesystemID = response.ECSClusterName, response.EFSFilesystemID
		if profile.LambdaFunctionName == "" {
			profile.LambdaFunctionName = DeriveLambdaFunctionName(profile.Project, profile.Environment)
		}
		if profile.InvokerRoleARN == "" {
			profile.InvokerRoleARN = role
		}
		if response.AWSRegion != "" {
			profile.AWSRegion = response.AWSRegion
		}
		if response.KeycloakURL != "" {
			profile.KeycloakURL = response.KeycloakURL
		}
		if response.KeycloakRealm != "" {
			profile.KeycloakRealm = response.KeycloakRealm
		}
		if response.OIDCClientID != "" {
			profile.OIDCClientID = response.OIDCClientID
		}
		var absent []string
		if profile.SRERoleARN == "" {
			absent = append(absent, "sre_role_arn")
		}
		if profile.ClusterName == "" {
			absent = append(absent, "ecs_cluster_name")
		}
		if profile.EFSFilesystemID == "" {
			absent = append(absent, "efs_filesystem_id")
		}
		if len(absent) != 0 {
			return fmt.Errorf("discovery response missing required settings: %s; verify the selected deployment and its Lambda configuration, or use --auto-discover=false with operator-confirmed settings", strings.Join(absent, ", "))
		}
	}
	if err := checkRoleAccounts(profile.AccountID, map[string]string{"invoker_role_arn": profile.InvokerRoleARN, "sre_role_arn": profile.SRERoleARN}); err != nil {
		return err
	}
	if err := file.AddProfile(name, profile, flagBool(cmd, "overwrite"), flagBool(cmd, "use")); err != nil {
		return err
	}
	if err := config.SaveProfiles(file); err != nil {
		return err
	}
	if format, _ := commandOutput(cmd); format == "json" {
		output.Status("Saved profile %s", name)
		return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": name, "active": file.ActiveProfile == name, "discovered": auto})
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Saved profile %s\n", name)
	return err
}

func checkDiscoveryIdentity(seed config.Profile, response *lambda.ConfigResponse) error {
	for _, setting := range []struct{ key, bootstrap, discovered string }{
		{"aws_region", seed.AWSRegion, response.AWSRegion},
		{"keycloak_url", seed.KeycloakURL, response.KeycloakURL},
		{"keycloak_realm", seed.KeycloakRealm, response.KeycloakRealm},
		{"oidc_client_id", seed.OIDCClientID, response.OIDCClientID},
	} {
		if setting.discovered != "" && setting.bootstrap != setting.discovered {
			return fmt.Errorf("discovered %s differs from bootstrap value; verify the target deployment and retry with the correct bootstrap flags", setting.key)
		}
	}
	return nil
}

func runConfigList(cmd *cobra.Command, _ []string) error {
	file, err := config.LoadProfiles()
	if err != nil {
		return err
	}
	if len(file.Profiles) == 0 {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "No profiles found. Run 'rosa-boundary config init --help' to create one.")
		return err
	}
	names := make([]string, 0, len(file.Profiles))
	for name := range file.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	tbl := output.NewTableTo(cmd.OutOrStdout(), "ACTIVE", "PROFILE", "ACCOUNT ID", "ENVIRONMENT", "REGION")
	tbl.PrintHeader()
	for _, name := range names {
		profile := file.Profiles[name]
		mark := ""
		if name == file.ActiveProfile {
			mark = "*"
		}
		tbl.PrintRow(mark, name, profile.AccountID, profile.Environment, profile.AWSRegion)
	}
	tbl.Flush()
	return nil
}

func runConfigUse(cmd *cobra.Command, args []string) error {
	if selectedProfile != "" {
		return fmt.Errorf("--profile is not used by config use-profile; pass the profile name as an argument: rosa-boundary config use-profile <name>")
	}
	file, err := config.LoadProfiles()
	if err != nil {
		return err
	}
	profile, ok := file.Profiles[args[0]]
	if !ok {
		return fmt.Errorf("unknown profile %q; run 'rosa-boundary config list-profiles' and pass a saved name to 'rosa-boundary config use-profile'", args[0])
	}
	if err := file.UseProfile(args[0]); err != nil {
		return err
	}
	if err := config.SaveProfiles(file); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Active profile: %s\nAWS account ID: %s\nAWS region: %s\n", args[0], profile.AccountID, profile.AWSRegion)
	return err
}

func runConfigGet(cmd *cobra.Command, args []string) error {
	_, profile, err := config.ReadSavedProfile(selectedProfile)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(profile)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		_, err = cmd.OutOrStdout().Write(data)
		return err
	}
	file, err := config.LoadProfiles()
	if err != nil {
		return err
	}
	value, err := file.SavedValue(selectedProfile, args[0])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), value)
	return err
}

func runLogin(cmd *cobra.Command) error {
	flags := map[string]string{}
	if flag := cmd.Flag("use-device-code"); flag != nil && flag.Changed {
		flags["oidc_use_device_code"] = strconv.FormatBool(flagBool(cmd, "use-device-code"))
	}
	selected, cfg, err := config.ResolveWithFlags(selectedProfile, flags)
	if err != nil {
		return err
	}
	selectedProfile = selected
	if err := config.RequireSettings(cfg, "keycloak_url"); err != nil {
		return err
	}
	if _, err := commandOutput(cmd); err != nil {
		return err
	}
	_, err = auth.GetTokenWithOptions(cmd.Context(), auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: cfg.KeycloakRealm, ClientID: cfg.OIDCClientID}, flagBool(cmd, "force"), auth.Options{UseDeviceCode: cfg.OIDCUseDeviceCode})
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	if format, _ := commandOutput(cmd); format == "json" {
		return output.JSONTo(cmd.OutOrStdout(), map[string]any{"profile": selectedProfile, "authenticated": true})
	}
	return nil
}
