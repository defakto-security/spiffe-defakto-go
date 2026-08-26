package attestingworkloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

// JWTSource fetches JWT-SVIDs and bundles via serverless attestation. Every
// call re-attests: there is no cached SVID (the audience varies per call,
// same as go-spiffe's own workloadapi.JWTSource.FetchJWTSVID). Bundles are
// likewise fetched live, since go-spiffe's jwtbundle.Source interface takes
// no context to attach a background-refresh cache to.
type JWTSource struct {
	client *Client
}

// JWTSource returns a JWTSource bound to this Client's attestors and
// transport.
func (c *Client) JWTSource() *JWTSource {
	return &JWTSource{client: c}
}

// FetchJWTSVID attests and requests a JWT-SVID for the given audiences.
// Matches workloadapi.JWTSource's exported method of the same name.
func (s *JWTSource) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	audiences := append([]string{params.Audience}, params.ExtraAudiences...)

	attestations, err := collectAttestations(ctx, s.client.attestors)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.stub.FetchJWTSVID(ctx, &serverlessapi.FetchJWTSVIDRequest{
		Attestations: attestations,
		Audience:     audiences,
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

// GetJWTBundleForTrustDomain satisfies go-spiffe's jwtbundle.Source. It
// re-attests on every call (the interface takes no context to cache
// against).
func (s *JWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	ctx := context.Background()

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

	bundles := parseJWTBundlesMap(result.GetBundles())
	bundle, ok := bundles[trustDomain.Name()]
	if !ok {
		return nil, newError(CodeBundleNotFound, "no JWT bundle found for trust domain \""+trustDomain.Name()+"\"", nil)
	}
	return bundle, nil
}
