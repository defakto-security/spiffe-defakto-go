// Package azuremsi attests an Azure workload using an Azure AD Managed
// Identity token. Works on any Azure compute resource with a managed
// identity assigned: App Service, Container Apps, AKS, VM, etc.
package azuremsi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
)

const (
	pluginName    = "azure_msi"
	pluginVersion = "1.0"

	defaultAudience = "api://AzureADTokenExchange"
)

// tokenCredential is the subset of *azidentity.ManagedIdentityCredential
// this attestor needs, narrowed so tests can fake it without reaching IMDS.
type tokenCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// Options configures Attestor. At most one of ClientID, PrincipalID, and
// ResourceID may be set — they select between multiple user-assigned
// identities on the same resource. When none is set, the system-assigned
// identity is used.
type Options struct {
	// Audience is the token's intended audience. Defaults to
	// "api://AzureADTokenExchange".
	Audience    string
	ClientID    string
	PrincipalID string
	ResourceID  string
}

// Attestor attests via an Azure Managed Identity access token. It satisfies
// attestation.Attestor.
type Attestor struct {
	audience   string
	credential tokenCredential
}

// New builds an Attestor backed by azidentity.ManagedIdentityCredential.
// Pass nil for default options (system-assigned identity, default audience).
func New(opts *Options) (*Attestor, error) {
	if opts == nil {
		opts = &Options{}
	}
	selectors := 0
	for _, v := range []string{opts.ClientID, opts.PrincipalID, opts.ResourceID} {
		if v != "" {
			selectors++
		}
	}
	if selectors > 1 {
		return nil, fmt.Errorf("azuremsi: at most one of ClientID, PrincipalID, ResourceID may be set")
	}

	audience := opts.Audience
	if audience == "" {
		audience = defaultAudience
	}

	miOpts := &azidentity.ManagedIdentityCredentialOptions{}
	switch {
	case opts.ClientID != "":
		miOpts.ID = azidentity.ClientID(opts.ClientID)
	case opts.PrincipalID != "":
		miOpts.ID = azidentity.ObjectID(opts.PrincipalID)
	case opts.ResourceID != "":
		miOpts.ID = azidentity.ResourceID(opts.ResourceID)
	}
	cred, err := azidentity.NewManagedIdentityCredential(miOpts)
	if err != nil {
		return nil, fmt.Errorf("azuremsi: build managed identity credential: %w", err)
	}

	return &Attestor{audience: audience, credential: cred}, nil
}

func (a *Attestor) PluginName() string    { return pluginName }
func (a *Attestor) PluginVersion() string { return pluginVersion }

// CollectEvidence fetches a fresh managed identity access token.
func (a *Attestor) CollectEvidence(ctx context.Context) (attestation.Evidence, error) {
	tok, err := a.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{a.scope()}})
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("azuremsi: get token: %w", err)
	}
	if tok.Token == "" {
		return attestation.Evidence{}, fmt.Errorf("azuremsi: managed identity returned no token")
	}
	payload, err := json.Marshal(map[string]string{"token": tok.Token})
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("azuremsi: marshal evidence: %w", err)
	}
	return attestation.Evidence{Payload: payload}, nil
}

// scope derives the OAuth2 scope from the configured audience: the default
// audience is used as-is, anything else gets "/.default" appended per Azure
// AD's v2 token convention (unless already present).
func (a *Attestor) scope() string {
	if a.audience == defaultAudience || strings.HasSuffix(a.audience, "/.default") {
		return a.audience
	}
	return a.audience + "/.default"
}

var _ attestation.Attestor = (*Attestor)(nil)
