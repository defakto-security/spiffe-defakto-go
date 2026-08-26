package attestingworkloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

// collectAttestations runs every attestor concurrently and converts their
// evidence to the wire format. Order is preserved to match the input slice.
func collectAttestations(ctx context.Context, attestors []attestation.Attestor) ([]*serverlessapi.MethodAttestation, error) {
	type result struct {
		idx      int
		evidence attestation.Evidence
		err      error
	}

	results := make(chan result, len(attestors))
	for i, a := range attestors {
		go func(i int, a attestation.Attestor) {
			ev, err := a.CollectEvidence(ctx)
			results <- result{idx: i, evidence: ev, err: err}
		}(i, a)
	}

	out := make([]*serverlessapi.MethodAttestation, len(attestors))
	var firstErr error
	for range attestors {
		r := <-results
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		out[r.idx] = &serverlessapi.MethodAttestation{
			MethodType:    attestors[r.idx].PluginName(),
			MethodVersion: attestors[r.idx].PluginVersion(),
			Evidence:      r.evidence.Payload,
		}
	}
	if firstErr != nil {
		return nil, newError(CodeAttestorCollectionFailed, "one or more attestors failed to collect evidence", firstErr)
	}
	return out, nil
}

// parseX509Response extracts SVIDs and the combined own+federated bundle map
// from a FetchX509SVID response's result fields. A malformed federated
// bundle entry is skipped rather than failing the whole response (matching
// the Python/TS SDKs).
func parseX509Response(svids []*serverlessapi.X509SVID, federated map[string][]byte) ([]*x509svid.SVID, map[string]*x509bundle.Bundle, error) {
	parsed := make([]*x509svid.SVID, 0, len(svids))
	bundles := map[string]*x509bundle.Bundle{}

	for _, s := range svids {
		svid, err := x509svid.ParseRaw(s.GetX509Svid(), s.GetX509SvidKey())
		if err != nil {
			return nil, nil, newError(CodeAttestationFailed, "attestingworkloadapi: parse x509-svid", err)
		}
		svid.Hint = s.GetHint()
		parsed = append(parsed, svid)

		if bundleDER := s.GetBundle(); len(bundleDER) > 0 {
			td := svid.ID.TrustDomain()
			if bundle, err := x509bundle.ParseRaw(td, bundleDER); err == nil {
				bundles[td.Name()] = bundle
			}
		}
	}

	for name, bundle := range parseX509BundlesMap(federated) {
		bundles[name] = bundle
	}

	return parsed, bundles, nil
}

// parseX509BundlesMap turns a {trust_domain_name: bundle_der} proto map into
// a name-keyed bundle map, skipping malformed entries.
func parseX509BundlesMap(bundlesMap map[string][]byte) map[string]*x509bundle.Bundle {
	out := map[string]*x509bundle.Bundle{}
	for name, der := range bundlesMap {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			continue
		}
		bundle, err := x509bundle.ParseRaw(td, der)
		if err != nil {
			continue
		}
		out[td.Name()] = bundle
	}
	return out
}

// parseJWTSVIDFromProto parses the token in a proto JWTSVID message. The
// signature is not re-verified here — the Trust Domain Server already
// validated the attestation and signed the token over a TLS connection this
// client dialed directly, unlike the local Workload API case where the
// token traverses an untrusted-by-default UDS peer.
func parseJWTSVIDFromProto(proto *serverlessapi.JWTSVID, audiences []string) (*jwtsvid.SVID, error) {
	svid, err := jwtsvid.ParseInsecure(proto.GetSvid(), audiences)
	if err != nil {
		return nil, newError(CodeAttestationFailed, "attestingworkloadapi: parse jwt-svid", err)
	}
	svid.Hint = proto.GetHint()
	return svid, nil
}

// parseJWTBundlesMap turns a {trust_domain_name: jwks_bytes} proto map into
// a name-keyed bundle map, skipping malformed entries.
func parseJWTBundlesMap(bundlesMap map[string][]byte) map[string]*jwtbundle.Bundle {
	out := map[string]*jwtbundle.Bundle{}
	for name, jwks := range bundlesMap {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			continue
		}
		bundle, err := jwtbundle.Parse(td, jwks)
		if err != nil {
			continue
		}
		out[td.Name()] = bundle
	}
	return out
}
