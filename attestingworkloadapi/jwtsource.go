package attestingworkloadapi

import (
	"context"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

// jwtBundleCacheTTL bounds how long GetJWTBundleForTrustDomain reuses a
// previously fetched bundle map. jwtsvid.ParseAndValidate calls that method
// once per token validation, before signature verification, so without a
// cache an attacker could drive one full attestation per inbound token. A
// var, not a const, so tests can shorten it.
var jwtBundleCacheTTL = time.Minute

// JWTSource fetches JWT-SVIDs and bundles via serverless attestation.
// FetchJWTSVID re-attests on every call: there is no cached SVID (the
// audience varies per call, same as go-spiffe's own
// workloadapi.JWTSource.FetchJWTSVID). Bundles are cached for
// jwtBundleCacheTTL (60s) — go-spiffe's jwtbundle.Source interface takes no
// context to hang a background refresh off, and the per-validation call rate
// makes an uncached fetch an attestation-amplification risk.
type JWTSource struct {
	client *Client

	mu            sync.Mutex
	cachedBundles map[string]*jwtbundle.Bundle
	cachedAt      time.Time
}

var (
	_ jwtbundle.Source = (*JWTSource)(nil)
	_ jwtsvid.Source   = (*JWTSource)(nil)
)

// JWTSource returns a JWTSource bound to this Client's attestors and
// transport.
func (c *Client) JWTSource() *JWTSource {
	return &JWTSource{client: c}
}

// FetchJWTSVID attests and requests a JWT-SVID for the given audiences.
// Matches workloadapi.JWTSource's exported method of the same name. A
// non-zero params.Subject requests that specific SPIFFE ID; the zero value
// stringifies to "" and lets the server pick.
func (s *JWTSource) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	audiences := append([]string{params.Audience}, params.ExtraAudiences...)

	attestations, err := collectAttestations(ctx, s.client.attestors)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.stub.FetchJWTSVID(ctx, &serverlessapi.FetchJWTSVIDRequest{
		Attestations: attestations,
		Audience:     audiences,
		SpiffeId:     params.Subject.String(),
		ClusterId:    s.client.clusterID,
	})
	if err != nil {
		return nil, newError(CodeAttestationFailed, "FetchJWTSVID request failed", err)
	}

	result := resp.GetJwtSvids()
	if result == nil || len(result.GetSvids()) == 0 {
		return nil, newError(CodeAttestationFailed, "endpoint did not return a JWT-SVID — attestation likely incomplete", nil)
	}
	return parseJWTSVIDFromProto(result.GetSvids()[0], audiences)
}

// GetJWTBundleForTrustDomain satisfies go-spiffe's jwtbundle.Source. The
// whole bundle map is cached for jwtBundleCacheTTL and answers both hits and
// ErrBundleNotFound misses, so an unknown trust domain can't be used to drive
// repeated attestations either. On an expired cache it re-attests under a
// refreshFetchTimeout-bounded context (the interface gives no context to
// cancel with).
func (s *JWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bundles := s.cachedBundles
	if bundles == nil || time.Since(s.cachedAt) >= jwtBundleCacheTTL {
		fresh, err := s.fetchBundles()
		if err != nil {
			// Leave any still-valid cache in place: a transient failure must
			// not force a cache miss (and a fresh attestation) for every
			// later caller.
			return nil, err
		}
		s.cachedBundles = fresh
		s.cachedAt = time.Now()
		bundles = fresh
	}

	bundle, ok := bundles[trustDomain.Name()]
	if !ok {
		return nil, newError(CodeBundleNotFound, "no JWT bundle found for trust domain \""+trustDomain.Name()+"\"", nil)
	}
	return bundle, nil
}

func (s *JWTSource) fetchBundles() (map[string]*jwtbundle.Bundle, error) {
	ctx, cancel := context.WithTimeout(context.Background(), refreshFetchTimeout)
	defer cancel()

	attestations, err := collectAttestations(ctx, s.client.attestors)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.stub.FetchJWTBundles(ctx, &serverlessapi.FetchJWTBundlesRequest{
		Attestations: attestations,
		ClusterId:    s.client.clusterID,
	})
	if err != nil {
		return nil, newError(CodeAttestationFailed, "FetchJWTBundles request failed", err)
	}

	result := resp.GetBundles()
	if result == nil {
		return nil, newError(CodeAttestationFailed, "endpoint did not return JWT bundles — attestation likely incomplete", nil)
	}
	return parseJWTBundlesMap(result.GetBundles()), nil
}
