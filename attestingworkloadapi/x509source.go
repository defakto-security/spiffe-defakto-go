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

	// maxRefreshBackoff caps the exponential backoff applied after
	// consecutive refresh failures, so a persistently unreachable attestation
	// server doesn't mean an evidence-collection round (a live STS/IMDS call
	// per attestor) every couple of seconds forever.
	maxRefreshBackoff = time.Minute

	// refreshFetchTimeout bounds a single background refresh attempt so a
	// hung attestation-server or attestor call can't block refreshLoop (and
	// thus delay Close) indefinitely.
	refreshFetchTimeout = 30 * time.Second
)

// X509Source is a source of X509-SVIDs and X.509 bundles maintained by
// re-attesting on a schedule. It satisfies go-spiffe's x509svid.Source and
// x509bundle.Source, so it's usable anywhere a consumer is typed against
// those — e.g. in place of workloadapi.X509Source.
type X509Source struct {
	client *Client

	mu             sync.RWMutex
	svid           *x509svid.SVID
	bundles        map[string]*x509bundle.Bundle
	lastRefreshErr error

	closeOnce sync.Once
	closeCh   chan struct{}

	// refreshCtx/refreshCancel bound background refresh attempts and let
	// Close interrupt one that's in flight, rather than only stopping the
	// loop between attempts. Deliberately rooted in context.Background(),
	// not the ctx passed to X509Source — that ctx only bounds the initial
	// blocking fetch, not the source's whole lifetime.
	refreshCtx    context.Context
	refreshCancel context.CancelFunc
}

var (
	_ x509svid.Source   = (*X509Source)(nil)
	_ x509bundle.Source = (*X509Source)(nil)
)

// X509Source performs an initial attestation (blocking, like
// workloadapi.NewX509Source) and then refreshes in the background at 85% of
// the current SVID's remaining lifetime, floored at 1 second. Consecutive
// refresh failures back off exponentially up to maxRefreshBackoff and are
// reported by LastRefreshError.
func (c *Client) X509Source(ctx context.Context) (*X509Source, error) {
	svid, bundles, err := c.fetchX509(ctx)
	if err != nil {
		return nil, err
	}
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	src := &X509Source{
		client:        c,
		svid:          svid,
		bundles:       bundles,
		closeCh:       make(chan struct{}),
		refreshCtx:    refreshCtx,
		refreshCancel: refreshCancel,
	}
	go src.refreshLoop()
	return src, nil
}

// GetX509SVID returns the most recently fetched X509-SVID. It never fails
// over to an error: if background refresh has been failing, this keeps
// returning the last SVID obtained, which may be past its NotAfter — call
// LastRefreshError to tell a healthy SVID from a stale one.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.svid, nil
}

// LastRefreshError returns the error from the most recent background refresh
// attempt, or nil if it succeeded (or none has run yet). Non-nil means the
// SVID from GetX509SVID is not being renewed and may be expired.
func (s *X509Source) LastRefreshError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRefreshErr
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

// Close stops the background refresh loop, cancelling any refresh attempt
// currently in flight. Safe to call more than once.
func (s *X509Source) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.refreshCancel()
	})
	return nil
}

func (s *X509Source) refreshLoop() {
	failures := 0
	for {
		select {
		case <-s.closeCh:
			return
		case <-time.After(refreshDelay(s.currentExpiry())):
		}

		svid, bundles, err := s.fetchRefresh()
		if err != nil {
			select {
			case <-s.closeCh:
				// Close cancelled this attempt; that's not a refresh failure
				// worth reporting from LastRefreshError.
				return
			default:
			}
			failures++
			s.mu.Lock()
			s.lastRefreshErr = err
			s.mu.Unlock()
			// Past NotAfter refreshDelay floors at minRefreshDelay, so without
			// a growing backoff here a down server would be re-attested
			// against every couple of seconds indefinitely.
			select {
			case <-s.closeCh:
				return
			case <-time.After(failureBackoff(failures)):
			}
			continue
		}

		failures = 0
		s.mu.Lock()
		s.svid = svid
		s.bundles = bundles
		s.lastRefreshErr = nil
		s.mu.Unlock()
	}
}

// failureBackoff doubles minRefreshDelay per consecutive failure, capped at
// maxRefreshBackoff.
func failureBackoff(failures int) time.Duration {
	backoff := minRefreshDelay
	for i := 1; i < failures && backoff < maxRefreshBackoff; i++ {
		backoff *= 2
	}
	return min(backoff, maxRefreshBackoff)
}

// fetchRefresh runs one background refresh attempt bounded by
// refreshFetchTimeout, and cancellable early via s.refreshCtx (closed by
// Close) so a hung server/attestor call can't block refreshLoop forever.
func (s *X509Source) fetchRefresh() (*x509svid.SVID, map[string]*x509bundle.Bundle, error) {
	ctx, cancel := context.WithTimeout(s.refreshCtx, refreshFetchTimeout)
	defer cancel()
	return s.client.fetchX509(ctx)
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
