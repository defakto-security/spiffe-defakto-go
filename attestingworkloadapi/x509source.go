package attestingworkloadapi

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

const (
	minRefreshDelay = time.Second
	refreshRatio    = 0.85
)

// X509Source is a source of X509-SVIDs and X.509 bundles maintained by
// re-attesting on a schedule. It satisfies go-spiffe's x509svid.Source and
// x509bundle.Source, so it's usable anywhere a consumer is typed against
// those — e.g. in place of workloadapi.X509Source.
type X509Source struct {
	client *Client

	mu      sync.RWMutex
	svid    *x509svid.SVID
	bundles map[string]*x509bundle.Bundle

	closeOnce sync.Once
	closeCh   chan struct{}
}

var (
	_ x509svid.Source   = (*X509Source)(nil)
	_ x509bundle.Source = (*X509Source)(nil)
)

// X509Source performs an initial attestation (blocking, like
// workloadapi.NewX509Source) and then refreshes in the background at 85% of
// the current SVID's remaining lifetime, floored at 1 second.
func (c *Client) X509Source(ctx context.Context) (*X509Source, error) {
	svid, bundles, err := c.fetchX509(ctx)
	if err != nil {
		return nil, err
	}
	src := &X509Source{
		client:  c,
		svid:    svid,
		bundles: bundles,
		closeCh: make(chan struct{}),
	}
	go src.refreshLoop()
	return src, nil
}

// GetX509SVID returns the most recently fetched X509-SVID.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.svid, nil
}

// GetX509BundleForTrustDomain returns the bundle for trustDomain from the
// most recent attestation response.
func (s *X509Source) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bundle, ok := s.bundles[trustDomain.Name()]
	if !ok {
		return nil, newError(CodeBundleNotFound, fmt.Sprintf("no X.509 bundle found for trust domain %q", trustDomain.Name()), nil)
	}
	return bundle, nil
}

// Close stops the background refresh loop. Safe to call more than once.
func (s *X509Source) Close() error {
	s.closeOnce.Do(func() { close(s.closeCh) })
	return nil
}

func (s *X509Source) refreshLoop() {
	for {
		delay := refreshDelay(s.currentExpiry())
		select {
		case <-s.closeCh:
			return
		case <-time.After(delay):
		}

		svid, bundles, err := s.client.fetchX509(context.Background())
		if err != nil {
			// Best-effort retry, floored so a persistent failure doesn't spin.
			select {
			case <-s.closeCh:
				return
			case <-time.After(minRefreshDelay):
			}
			continue
		}

		s.mu.Lock()
		s.svid = svid
		s.bundles = bundles
		s.mu.Unlock()
	}
}

func (s *X509Source) currentExpiry() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.svid.Certificates[0].NotAfter
}

func refreshDelay(expiresAt time.Time) time.Duration {
	remaining := time.Duration(float64(time.Until(expiresAt)) * refreshRatio)
	if remaining < minRefreshDelay {
		return minRefreshDelay
	}
	return remaining
}

// fetchX509 runs one attestation handshake and returns the default (first)
// SVID plus the combined own+federated bundle map.
func (c *Client) fetchX509(ctx context.Context) (*x509svid.SVID, map[string]*x509bundle.Bundle, error) {
	attestations, err := collectAttestations(ctx, c.attestors)
	if err != nil {
		return nil, nil, err
	}

	resp, err := c.stub.FetchX509SVID(ctx, &serverlessapi.FetchX509SVIDRequest{
		Attestations: attestations,
		ClusterId:    c.clusterID,
	})
	if err != nil {
		return nil, nil, newError(CodeAttestationFailed, "FetchX509SVID request failed", err)
	}

	result := resp.GetX509Svids()
	if result == nil {
		return nil, nil, newError(CodeAttestationFailed, "endpoint did not return X.509 SVIDs — attestation likely incomplete", nil)
	}

	svids, bundles, err := parseX509Response(result.GetSvids(), result.GetFederatedBundles())
	if err != nil {
		return nil, nil, err
	}
	if len(svids) == 0 {
		return nil, nil, newError(CodeAttestationFailed, "no X.509-SVIDs in response", nil)
	}
	return svids[0], bundles, nil
}
