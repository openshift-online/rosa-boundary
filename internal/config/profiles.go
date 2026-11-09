package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Profile contains only saved deployment settings, never tokens or credentials.
// Optional fields remain absent in YAML rather than being filled from the environment.
type Profile struct {
	AccountID          string `yaml:"account_id,omitempty"`
	Environment        string `yaml:"environment,omitempty"`
	Project            string `yaml:"project,omitempty"`
	AWSRegion          string `yaml:"aws_region,omitempty"`
	KeycloakURL        string `yaml:"keycloak_url,omitempty"`
	KeycloakRealm      string `yaml:"keycloak_realm,omitempty"`
	OIDCClientID       string `yaml:"oidc_client_id,omitempty"`
	OIDCUseDeviceCode  *bool  `yaml:"oidc_use_device_code,omitempty"`
	LambdaFunctionName string `yaml:"lambda_function_name,omitempty"`
	InvokerRoleARN     string `yaml:"invoker_role_arn,omitempty"`
	SRERoleARN         string `yaml:"sre_role_arn,omitempty"`
	ClusterName        string `yaml:"ecs_cluster_name,omitempty"`
	EFSFilesystemID    string `yaml:"efs_filesystem_id,omitempty"`
}

// ProfilesFile is the named-profile YAML document.
type ProfilesFile struct {
	ActiveProfile string             `yaml:"active_profile,omitempty"`
	Profiles      map[string]Profile `yaml:"profiles"`
}

var profileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func profilePath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// LoadProfiles reads saved YAML without resolving environment settings or defaults.
// A missing file is an empty document; invalid files fail normal schema validation.
func LoadProfiles() (*ProfilesFile, error) {
	path, err := profilePath()
	if err != nil {
		return nil, err
	}
	return ReadProfiles(path)
}

// ReadProfiles reads an explicit path (useful for callers with a custom config location).
func ReadProfiles(path string) (*ProfilesFile, error) {
	file, err := readProfiles(path)
	if err != nil {
		return nil, fmt.Errorf("could not read Boundary configuration file %s\nHelp: Check that the file is accessible and uses the named-profile format (active_profile and profiles). If this is an old flat config, back it up or move it aside, then run 'rosa-boundary config init' to create a new profile.\nDetails: %w", path, err)
	}
	return file, nil
}

func readProfiles(path string) (*ProfilesFile, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return &ProfilesFile{Profiles: make(map[string]Profile)}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect config %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("config %s must be a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decode config %s: %w", path, err)
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config %s must contain a mapping", path)
	}
	fields := root.Content[0].Content
	for i := 0; i < len(fields); i += 2 {
		if fields[i].Value != "profiles" {
			continue
		}
		if fields[i+1].Kind != yaml.MappingNode {
			return nil, fmt.Errorf("config %s: profiles must be a mapping", path)
		}
		for j := 0; j < len(fields[i+1].Content); j += 2 {
			profile := fields[i+1].Content[j+1]
			if profile.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("config %s: profile %q must be a mapping", path, fields[i+1].Content[j].Value)
			}
			for k := 0; k < len(profile.Content); k += 2 {
				if profile.Content[k].Value == "oidc_use_device_code" && profile.Content[k+1].Tag != "!!bool" {
					return nil, fmt.Errorf("config %s: oidc_use_device_code must be a YAML boolean (true or false)", path)
				}
			}
		}
	}
	var file ProfilesFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true) // Never silently drop unknown (possibly sensitive) fields on save.
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode named profiles %s: %w", path, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config %s must contain exactly one YAML document", path)
	}
	if file.Profiles == nil {
		return nil, fmt.Errorf("config %s: profiles must be a mapping", path)
	}
	if err := file.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &file, nil
}

func (f *ProfilesFile) validate() error {
	if f == nil || f.Profiles == nil {
		return fmt.Errorf("profiles must be a mapping")
	}
	for name := range f.Profiles {
		if !profileNamePattern.MatchString(name) {
			return fmt.Errorf("invalid profile name %q (use letters, digits, dots, underscores or hyphens)", name)
		}
	}
	if f.ActiveProfile != "" {
		if _, ok := f.Profiles[f.ActiveProfile]; !ok {
			return fmt.Errorf("active_profile %q does not exist in profiles", f.ActiveProfile)
		}
	}
	return nil
}

// SelectProfile selects an explicitly named saved profile or the saved active profile.
// Environment variables cannot change the selection.
func (f *ProfilesFile) SelectProfile(name string) (string, Profile, error) {
	if f == nil {
		return "", Profile{}, fmt.Errorf("no profiles loaded")
	}
	if name == "" {
		name = f.ActiveProfile
	}
	if name == "" {
		return "", Profile{}, fmt.Errorf("no active profile; run 'rosa-boundary config list-profiles' to see saved profiles, select one with 'rosa-boundary config use-profile <name>' or --profile, or create one with 'rosa-boundary config init --name <name>'")
	}
	p, ok := f.Profiles[name]
	if !ok {
		return "", Profile{}, fmt.Errorf("unknown profile %q; run 'rosa-boundary config list-profiles' to see saved profiles, then select one with --profile or 'rosa-boundary config use-profile <name>'", name)
	}
	return name, p, nil
}

// AddProfile refuses replacement unless overwrite was explicitly requested.
// The first profile becomes active; later additions keep the current selection.
func (f *ProfilesFile) AddProfile(name string, p Profile, overwrite, use bool) error {
	if f == nil || f.Profiles == nil {
		return fmt.Errorf("profiles must be initialized")
	}
	if !profileNamePattern.MatchString(name) {
		return fmt.Errorf("invalid profile name %q", name)
	}
	if _, exists := f.Profiles[name]; exists && !overwrite {
		return fmt.Errorf("profile %q already exists; use --overwrite to replace it", name)
	}
	f.Profiles[name] = p
	if f.ActiveProfile == "" || use {
		f.ActiveProfile = name
	}
	return nil
}

// UseProfile changes only the in-memory active selection; call SaveProfiles to persist.
func (f *ProfilesFile) UseProfile(name string) error {
	if _, _, err := f.SelectProfile(name); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("profile name is required")
	}
	f.ActiveProfile = name
	return nil
}

// SavedValue returns a supported saved key without environment or default values.
// A key omitted from the YAML is an error, even if a runtime default exists.
func (f *ProfilesFile) SavedValue(name, key string) (any, error) {
	_, p, err := f.SelectProfile(name)
	if err != nil {
		return nil, err
	}
	values := map[string]string{
		"account_id": p.AccountID, "environment": p.Environment, "project": p.Project,
		"aws_region": p.AWSRegion, "keycloak_url": p.KeycloakURL, "keycloak_realm": p.KeycloakRealm,
		"oidc_client_id": p.OIDCClientID, "lambda_function_name": p.LambdaFunctionName,
		"invoker_role_arn": p.InvokerRoleARN, "sre_role_arn": p.SRERoleARN,
		"ecs_cluster_name": p.ClusterName, "efs_filesystem_id": p.EFSFilesystemID,
	}
	if key == "oidc_use_device_code" {
		if p.OIDCUseDeviceCode == nil {
			return nil, fmt.Errorf("key %q is not saved in the selected profile; run 'rosa-boundary config get' to inspect saved settings and reinitialize the profile if this setting is needed", key)
		}
		return *p.OIDCUseDeviceCode, nil
	}
	v, ok := values[key]
	if !ok {
		return nil, fmt.Errorf("unsupported config key %q; run 'rosa-boundary config get' to see the saved settings and their key names", key)
	}
	if v == "" {
		return nil, fmt.Errorf("key %q is not saved in the selected profile; run 'rosa-boundary config get' to inspect saved settings and reinitialize the profile if this setting is needed", key)
	}
	return v, nil
}

// SaveProfiles validates the current file before atomic replacement so invalid
// configurations are never overwritten. Confirmation for --overwrite belongs to the caller.
func SaveProfiles(f *ProfilesFile) error {
	path, err := profilePath()
	if err != nil {
		return err
	}
	return WriteProfiles(path, f)
}

// WriteProfiles atomically writes a named-profile document with mode 0600.
func WriteProfiles(path string, f *ProfilesFile) error {
	if err := f.validate(); err != nil {
		return err
	}
	if _, err := ReadProfiles(path); err != nil { // Refuse invalid and symlink targets.
		return err
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode profiles: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // Best-effort cleanup after close or rename.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// ResolveProfile applies explicit flag values, then ROSA_BOUNDARY_* environment
// variables, saved values, and finally non-deployment defaults. Pass only flags
// that were explicitly set; an absent flag must not mask an environment value.
// lookupEnv may be nil to use os.LookupEnv. The selected profile is always saved.
func (f *ProfilesFile) ResolveProfile(name string, flags map[string]string, lookupEnv func(string) (string, bool)) (string, *Config, error) {
	selected, p, err := f.SelectProfile(name)
	if err != nil {
		return "", nil, err
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	resolve := func(key, saved, fallback string) string {
		if value, ok := flags[key]; ok {
			return value
		}
		if value, ok := lookupEnv("ROSA_BOUNDARY_" + strings.ToUpper(key)); ok {
			return value
		}
		if saved != "" {
			return saved
		}
		return fallback
	}
	for key := range flags {
		if key != "oidc_use_device_code" && !supportedKey(key) {
			return "", nil, fmt.Errorf("unsupported config key %q", key)
		}
	}
	device := false
	if p.OIDCUseDeviceCode != nil {
		device = *p.OIDCUseDeviceCode
	}
	if raw, ok := flags["oidc_use_device_code"]; ok {
		device, err = strconv.ParseBool(raw)
		if err != nil {
			return "", nil, fmt.Errorf("--use-device-code must be a boolean (true or false): %w", err)
		}
	} else if raw, ok := lookupEnv("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE"); ok {
		device, err = strconv.ParseBool(raw)
		if err != nil {
			return "", nil, fmt.Errorf("ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE must be a boolean (true or false): %w", err)
		}
	}
	cfg := &Config{
		AccountID:          resolve("account_id", p.AccountID, ""),
		Environment:        resolve("environment", p.Environment, "prod"),
		Project:            resolve("project", p.Project, "rosa-boundary"),
		AWSRegion:          resolve("aws_region", p.AWSRegion, ""),
		KeycloakURL:        resolve("keycloak_url", p.KeycloakURL, ""),
		KeycloakRealm:      resolve("keycloak_realm", p.KeycloakRealm, "EmployeeIDP"),
		OIDCClientID:       resolve("oidc_client_id", p.OIDCClientID, "rosa-boundary-sre"),
		OIDCUseDeviceCode:  device,
		LambdaFunctionName: resolve("lambda_function_name", p.LambdaFunctionName, ""),
		InvokerRoleARN:     resolve("invoker_role_arn", p.InvokerRoleARN, ""),
		SRERoleARN:         resolve("sre_role_arn", p.SRERoleARN, ""),
		ClusterName:        resolve("ecs_cluster_name", p.ClusterName, ""),
		EFSFilesystemID:    resolve("efs_filesystem_id", p.EFSFilesystemID, ""),
	}
	return selected, cfg, nil
}

func supportedKey(key string) bool {
	switch key {
	case "account_id", "environment", "project", "aws_region", "keycloak_url", "keycloak_realm", "oidc_client_id", "lambda_function_name", "invoker_role_arn", "sre_role_arn", "ecs_cluster_name", "efs_filesystem_id":
		return true
	}
	return false
}

// ReadSavedProfile reads the explicit or active profile without runtime resolution.
func ReadSavedProfile(name string) (string, Profile, error) {
	f, err := LoadProfiles()
	if err != nil {
		return "", Profile{}, err
	}
	return f.SelectProfile(name)
}

// ResolveWithFlags resolves the selected saved profile using explicitly supplied
// flag keys (the snake_case YAML keys). It never uses environment to select a profile.
func ResolveWithFlags(name string, flags map[string]string) (string, *Config, error) {
	f, err := LoadProfiles()
	if err != nil {
		return "", nil, err
	}
	return f.ResolveProfile(name, flags, nil)
}

// RequireSettings reports missing settings for a particular command. Callers
// choose the keys that operation actually needs; resolution does not invent an
// account, region, ECS cluster, or filesystem ID.
func RequireSettings(cfg *Config, keys ...string) error {
	if cfg == nil {
		return fmt.Errorf("no resolved profile")
	}
	values := map[string]string{
		"account_id": cfg.AccountID, "environment": cfg.Environment,
		"project": cfg.Project, "aws_region": cfg.AWSRegion,
		"keycloak_url": cfg.KeycloakURL, "keycloak_realm": cfg.KeycloakRealm,
		"oidc_client_id": cfg.OIDCClientID, "lambda_function_name": cfg.LambdaFunctionName,
		"invoker_role_arn": cfg.InvokerRoleARN, "sre_role_arn": cfg.SRERoleARN,
		"ecs_cluster_name": cfg.ClusterName, "efs_filesystem_id": cfg.EFSFilesystemID,
	}
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			return fmt.Errorf("unsupported config key %q", key)
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing Boundary deployment setting %q in selected profile (set it with config init or an explicit flag/environment override)", key)
		}
	}
	return nil
}
