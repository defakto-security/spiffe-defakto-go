// Package gcpiit attests a GCP workload by fetching a signed Instance
// Identity Token from the metadata service — no GCP SDK required, it's a
// plain HTTP endpoint.
package gcpiit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
)

const (
	pluginName    = "gcp_iit"
	pluginVersion = "1.0"

	defaultMetadataHost   = "metadata.google.internal"
	defaultServiceAccount = "default"
	defaultAudience       = "urn:defakto:security:server"
)

// Options configures Attestor. A zero-value Options applies documented
// defaults.
type Options struct {
	// MetadataHost is the GCP metadata service host:port. Defaults to
	// "metadata.google.internal". Override for testing.
	MetadataHost string
	// ServiceAccount selects which instance service account to request the
	// identity token for. Defaults to "default".
	ServiceAccount string
	// Audience is the token's intended audience. Defaults to
	// "urn:defakto:security:server".
	Audience string
	// HTTPClient overrides the client used to reach the metadata service.
	// Defaults to http.DefaultClient.
	HTTPClient *http.Client
}

// Attestor attests via the GCP Instance Identity Token. It satisfies
// attestation.Attestor.
type Attestor struct {
	metadataHost   string
	serviceAccount string
	audience       string
	httpClient     *http.Client
}

// New builds an Attestor. Pass nil for default options.
func New(opts *Options) *Attestor {
	if opts == nil {
		opts = &Options{}
	}
	a := &Attestor{
		metadataHost:   opts.MetadataHost,
		serviceAccount: opts.ServiceAccount,
		audience:       opts.Audience,
		httpClient:     opts.HTTPClient,
	}
	if a.metadataHost == "" {
		a.metadataHost = defaultMetadataHost
	}
	if a.serviceAccount == "" {
		a.serviceAccount = defaultServiceAccount
	}
	if a.audience == "" {
		a.audience = defaultAudience
	}
	if a.httpClient == nil {
		a.httpClient = http.DefaultClient
	}
	return a
}

func (a *Attestor) PluginName() string    { return pluginName }
func (a *Attestor) PluginVersion() string { return pluginVersion }

// CollectEvidence fetches a fresh Instance Identity Token from the metadata
// service and wraps it as {"token": "<jwt>"}.
func (a *Attestor) CollectEvidence(ctx context.Context) (attestation.Evidence, error) {
	reqURL := fmt.Sprintf(
		"http://%s/computeMetadata/v1/instance/service-accounts/%s/identity?audience=%s&format=full",
		a.metadataHost, url.PathEscape(a.serviceAccount), url.QueryEscape(a.audience),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("gcpiit: build metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("gcpiit: cannot obtain GCP instance identity token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("gcpiit: read metadata response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return attestation.Evidence{}, fmt.Errorf("gcpiit: metadata service returned unexpected status %d", resp.StatusCode)
	}

	payload, err := json.Marshal(map[string]string{"token": string(body)})
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("gcpiit: marshal evidence: %w", err)
	}
	return attestation.Evidence{Payload: payload}, nil
}

var _ attestation.Attestor = (*Attestor)(nil)
