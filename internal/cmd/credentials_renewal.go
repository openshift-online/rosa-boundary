package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/config"
	ocm "github.com/openshift-online/rosa-boundary/internal/credentials/ocm"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

type attachmentOCMAuth interface {
	AcquireForAttachment(context.Context, ocm.Flow) (ocm.Token, *ocm.AttachmentGrant, error)
	Refresh(context.Context, *ocm.AttachmentGrant) (ocm.Token, error)
}

var newAttachmentOCMAuth = func() attachmentOCMAuth {
	a := ocm.NewAuthenticator(output.Status)
	a.Debug = credentialDebugf
	return a
}

const (
	renewalUploadTimeout = 100 * time.Second
	renewalLoginTimeout  = 3 * time.Minute
	// Budget the OAuth exchange, helper upload, and a small scheduling margin.
	renewalLead = ocm.RefreshTimeout + renewalUploadTimeout + 10*time.Second
)

type ocmSetup struct {
	environment ocm.Environment
	flow        ocm.Flow
}

type ocmRenewal struct {
	grant         *ocm.AttachmentGrant
	expiry        time.Time
	generation    string
	fallback      string
	refresh       func(context.Context, *ocm.AttachmentGrant) (ocm.Token, error)
	authorization *renewalAWS
	install       func(context.Context, *awsclient.TemporaryCredentials, ocm.Token, string, string) error
}

func credentialGeneration() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(random[:]), nil
}

func (r *ocmRenewal) delay(expiry, now time.Time) (time.Duration, bool) {
	remaining := expiry.Sub(now)
	lead := max(renewalLead, min(remaining/4, 5*time.Minute))
	if r.authorization != nil && r.authorization.needsRefresh(now.Add(remaining-lead)) {
		lead = max(lead, renewalLead+renewalLoginTimeout)
	}
	if remaining <= lead {
		return 0, false
	}
	return remaining - lead, true
}

func waitRenewal(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

// run stops permanently on an unconfirmed commit, including a generation
// conflict. Retrying could obscure an intentional clear or newer configure.
func (r *ocmRenewal) run(ctx context.Context, now func() time.Time, wait func(context.Context, time.Duration) bool) {
	if err := r.runUntilStopped(ctx, now, wait); err != nil {
		r.warn(ctx, err.Error())
	}
}

// runUntilStopped returns failures to the standalone configure command. An
// attached shell instead reports them as warnings and remains open.
func (r *ocmRenewal) runUntilStopped(ctx context.Context, now func() time.Time, wait func(context.Context, time.Duration) bool) error {
	defer r.grant.Release()
	for {
		delay, ok := r.delay(r.expiry, now())
		if !ok {
			return errors.New("expiry is missing or too near")
		}
		if !wait(ctx, delay) || ctx.Err() != nil {
			return ctx.Err()
		}
		var creds *awsclient.TemporaryCredentials
		if r.authorization != nil {
			var err error
			creds, err = r.authorization.credentials(ctx, now)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				return errors.New("could not refresh Boundary authorization")
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		token, err := r.refresh(ctx, r.grant)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return errors.New("online refresh failed; fresh OCM approval may be required")
		}
		if token.Expiry.IsZero() || ocmTokenNearExpiry(token, now()) {
			return errors.New("refreshed token expiry is missing or too near")
		}
		generation, err := credentialGeneration()
		if err == nil && ctx.Err() == nil {
			err = r.install(ctx, creds, token, generation, r.generation)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return errors.New("replacement was not confirmed (Boundary authorization, transfer failure, or credentials changed)")
		}
		r.expiry = token.Expiry
		r.generation = generation
		_ = output.Debug("Renewed OCM access; expires at %s", r.expiry.Format(time.RFC3339))
	}
}

func (r *ocmRenewal) warn(ctx context.Context, reason string) {
	if ctx.Err() == nil {
		output.Warning("OCM renewal stopped: %s. To configure fresh credentials manually, run: %s", reason, r.fallback)
	}
}

func installAttachmentOCM(ctx context.Context, ecs *awsclient.ECSClient, region string, creds *awsclient.TemporaryCredentials, clusterName, sessionID string, setup ocmSetup, token ocm.Token, grant *ocm.AttachmentGrant, a attachmentOCMAuth, authorization *renewalAWS) (*ocmRenewal, error) {
	r := &ocmRenewal{grant: grant, expiry: token.Expiry, authorization: authorization}
	var err error
	_, schedulable := r.delay(token.Expiry, time.Now())
	if grant.Available() && schedulable {
		r.generation, err = credentialGeneration()
	}
	installedGeneration := false
	if err == nil {
		installedGeneration, err = transferOCMToken(ctx, ecs, region, creds, sessionID, setup.environment, token, r.generation, "")
	}
	_, schedulable = r.delay(token.Expiry, time.Now())
	if err != nil || !installedGeneration || !schedulable {
		grant.Release()
		if err == nil && a != nil {
			if r.generation != "" && !installedGeneration {
				output.Status("OCM renewal not scheduled: this task image supports one-shot configuration only")
			} else {
				output.Status("OCM renewal not scheduled: no online grant or no usable expiry")
			}
		}
		return nil, err
	}
	r.refresh = a.Refresh
	r.fallback = setup.configureCommand(region, clusterName, sessionID)
	r.install = func(ctx context.Context, fresh *awsclient.TemporaryCredentials, token ocm.Token, generation, expected string) error {
		ctx, cancel := context.WithTimeout(ctx, renewalUploadTimeout)
		defer cancel()
		ecs := awsclient.NewECSClient(region, clusterName, awsclient.StaticCredentialsProvider(fresh))
		if err := prepareCredentialSession(ctx, ecs, sessionID); err != nil {
			return err
		}
		_, err := transferOCMToken(ctx, ecs, region, fresh, sessionID, setup.environment, token, generation, expected)
		return err
	}
	return r, nil
}

func (s ocmSetup) configureCommand(region, clusterName, sessionID string) string {
	command := fmt.Sprintf("rosa-boundary --profile %s session credentials configure ocm %s --region %s --ecs-cluster %s",
		shellArgument(selectedProfile), shellArgument(sessionID), shellArgument(region), shellArgument(clusterName))
	if s.environment.URL != "" {
		command += " --ocm-url " + shellArgument(s.environment.URL)
	}
	if s.flow != "" {
		command += " --auth-flow " + shellArgument(string(s.flow))
	}
	return command
}

// renewalAWS refreshes only the credentials for new helper connections. Its
// caller supplies the original SRE role and identity, never the invoker role.
type renewalAWS struct {
	creds    *awsclient.TemporaryCredentials
	reassume func(context.Context) (*awsclient.TemporaryCredentials, error)
}

func (a *renewalAWS) needsRefresh(now time.Time) bool {
	return a.creds == nil || a.creds.Expiry.Sub(now) <= ocm.RefreshTimeout+renewalUploadTimeout
}

func (a *renewalAWS) credentials(ctx context.Context, now func() time.Time) (*awsclient.TemporaryCredentials, error) {
	if !a.needsRefresh(now()) {
		return a.creds, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	creds, err := a.reassume(ctx)
	if err != nil {
		return nil, err
	}
	if creds == nil || creds.Expiry.Sub(now()) <= ocm.RefreshTimeout+renewalUploadTimeout {
		return nil, errors.New("new Boundary authorization has insufficient lifetime")
	}
	a.creds = creds
	return creds, nil
}

func newRenewalAWS(cfg *config.Config, creds *awsclient.TemporaryCredentials, role, sessionName, originalIDToken string, options auth.Options) *renewalAWS {
	originalSubject, subjectErr := authenticatedSubject(originalIDToken)
	return &renewalAWS{creds: creds, reassume: func(ctx context.Context) (*awsclient.TemporaryCredentials, error) {
		if subjectErr != nil || !validOwnerSubject(originalSubject) {
			return nil, errors.New("cannot verify original Boundary identity")
		}
		_ = output.Debug("Refreshing Boundary authorization for the OCM helper; this is separate from OCM approval")
		ctx, cancel := context.WithTimeout(ctx, renewalLoginTimeout)
		defer cancel()
		pkce := auth.PKCEConfig{KeycloakURL: cfg.KeycloakURL, Realm: cfg.KeycloakRealm, ClientID: cfg.OIDCClientID}
		idToken, fresh, err := assumeRoleWithRetryOptions(ctx, pkce, cfg.AWSRegion, role, sessionName, false, options)
		if err != nil {
			return nil, err
		}
		subject, err := authenticatedSubject(idToken)
		if err != nil || subject != originalSubject {
			return nil, errors.New("authenticated Boundary identity changed")
		}
		return fresh, nil
	}}
}
