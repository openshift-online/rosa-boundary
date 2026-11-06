package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// saveTestProfile builds a minimal saved profile without adding test-only
// convenience APIs to production configuration code.
func saveTestProfile(name string, cfg Config, use, overwrite bool) error {
	f, err := LoadProfiles()
	if err != nil {
		return err
	}
	device := cfg.OIDCUseDeviceCode
	p := Profile{AccountID: cfg.AccountID, Environment: cfg.Environment, Project: cfg.Project,
		AWSRegion: cfg.AWSRegion, KeycloakURL: cfg.KeycloakURL, KeycloakRealm: cfg.KeycloakRealm,
		OIDCClientID: cfg.OIDCClientID, OIDCUseDeviceCode: &device,
		LambdaFunctionName: cfg.LambdaFunctionName, InvokerRoleARN: cfg.InvokerRoleARN,
		SRERoleARN: cfg.SRERoleARN, ClusterName: cfg.ClusterName, EFSFilesystemID: cfg.EFSFilesystemID}
	if err := f.AddProfile(name, p, overwrite, use); err != nil {
		return err
	}
	return SaveProfiles(f)
}

func TestProfilesSaveSelectAndSavedValues(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := saveTestProfile("stage", Config{AccountID: "111111111111", AWSRegion: "us-east-1"}, false, false); err != nil {
		t.Fatal(err)
	}
	if err := saveTestProfile("prod", Config{AccountID: "222222222222", AWSRegion: "us-west-1", OIDCUseDeviceCode: true}, false, false); err != nil {
		t.Fatal(err)
	}
	file, err := LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if file.ActiveProfile != "stage" || len(file.Profiles) != 2 {
		t.Fatalf("unexpected profiles: %+v", file)
	}
	if _, err := file.SavedValue("stage", "environment"); err == nil {
		t.Fatal("saved value must not contain runtime defaults")
	}
	if v, err := file.SavedValue("stage", "oidc_use_device_code"); err != nil || v != false {
		t.Fatalf("saved boolean = %v, %v", v, err)
	}
	if err := saveTestProfile("stage", Config{}, false, false); err == nil {
		t.Fatal("replacement without overwrite succeeded")
	}
	file, err = LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.UseProfile("prod"); err != nil {
		t.Fatal(err)
	}
	if err := SaveProfiles(file); err != nil {
		t.Fatal(err)
	}
	if _, err := file.SavedValue("stage", "unknown"); err == nil {
		t.Fatal("unknown key accepted")
	}
	selected, cfg, err := ResolveWithFlags("", nil)
	if err != nil || selected != "prod" || cfg.AWSRegion != "us-west-1" || cfg.AccountID != "222222222222" {
		t.Fatalf("resolved = %q, %+v, %v", selected, cfg, err)
	}
	if err := saveTestProfile("prod", Config{AWSRegion: "eu-west-1"}, false, true); err != nil {
		t.Fatal(err)
	}
	file, err = LoadProfiles()
	if err != nil || file.ActiveProfile != "prod" || file.Profiles["stage"].AccountID != "111111111111" {
		t.Fatalf("replacement changed other profiles: %+v %v", file, err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "rosa-boundary", "config.yaml")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, %v", info, err)
	}
}

func TestInvalidConfigRejectedAndUnchanged(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "rosa-boundary", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	invalid := []byte("keycloak_url: https://example.test\n")
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfiles(); err == nil || !strings.Contains(err.Error(), "field keycloak_url not found") {
		t.Fatalf("LoadProfiles invalid config = %v", err)
	}
	if err := saveTestProfile("stage", Config{}, false, false); err == nil || !strings.Contains(err.Error(), "field keycloak_url not found") {
		t.Fatalf("SaveProfile invalid config = %v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != string(invalid) {
		t.Fatal("invalid config overwritten")
	}
}

func TestProfileResolvePrecedenceAndNoDeploymentGuess(t *testing.T) {
	f := &ProfilesFile{ActiveProfile: "stage", Profiles: map[string]Profile{
		"stage": {AWSRegion: "us-east-1", ClusterName: "stage-ecs"},
		"prod":  {AWSRegion: "us-west-1"},
	}}
	env := func(key string) (string, bool) {
		v, ok := map[string]string{"ROSA_BOUNDARY_AWS_REGION": "eu-central-1", "ROSA_BOUNDARY_PROFILE": "prod", "ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE": "invalid"}[key]
		return v, ok
	}
	selected, cfg, err := f.ResolveProfile("", map[string]string{"aws_region": "ap-south-1", "oidc_use_device_code": "false"}, env)
	if err != nil || selected != "stage" || cfg.AWSRegion != "ap-south-1" || cfg.ClusterName != "stage-ecs" || cfg.AccountID != "" {
		t.Fatalf("resolution = %q %+v %v", selected, cfg, err)
	}
	if _, _, err := f.ResolveProfile("prod", nil, env); err == nil || !strings.Contains(err.Error(), "ROSA_BOUNDARY_OIDC_USE_DEVICE_CODE") {
		t.Fatalf("invalid env accepted: %v", err)
	}
	selected, cfg, err = f.ResolveProfile("prod", nil, func(string) (string, bool) { return "", false })
	if err != nil || selected != "prod" || cfg.ClusterName != "" || cfg.AWSRegion != "us-west-1" {
		t.Fatalf("prod resolution = %q %+v %v", selected, cfg, err)
	}
}

func TestProfilesRejectMalformedAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	for _, data := range []string{
		"profiles: null\n", "profiles:\n  stage:\n    token: secret\n",
		"profiles:\n  stage:\n    oidc_use_device_code: null\n",
		"profiles:\n  stage:\n    oidc_use_device_code: 'true'\n",
		"active_profile: missing\nprofiles: {}\n",
		"profiles: {}\nprofiles: {}\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadProfiles(path); err == nil {
			t.Fatalf("accepted malformed YAML: %q", data)
		}
	}
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteProfiles(link, &ProfilesFile{Profiles: map[string]Profile{}}); err == nil {
		t.Fatal("wrote through symlink")
	}
}
