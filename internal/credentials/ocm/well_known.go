package ocm

// These values match ocm-cli and ocm-sdk-go. They remain local because importing
// either complete module solely for constants materially increases the CLI size.
const (
	ClientID      = "ocm-cli"
	ssoBaseURL    = "https://sso.redhat.com"
	oidcBaseURL   = ssoBaseURL + "/auth/realms/redhat-external/protocol/openid-connect"
	AuthURL       = oidcBaseURL + "/auth"
	DeviceAuthURL = AuthURL + "/device"
	TokenURL      = oidcBaseURL + "/token"
	RedirectURL   = "http://127.0.0.1:9998/oauth/callback"

	ProductionURL  = "https://api.openshift.com"
	StagingURL     = "https://api.stage.openshift.com"
	IntegrationURL = "https://api.integration.openshift.com"
)
