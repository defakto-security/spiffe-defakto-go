package attestingworkloadapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"

	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

func TestJWTSource_FetchJWTSVID(t *testing.T) {
	token := buildJWTFixture(t, map[string]any{
		"sub": "spiffe://example.org/workload",
		"aud": []string{"https://api.example.org"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	srv := &fakeServer{jwtSVIDResp: &serverlessapi.FetchJWTSVIDResponse{
		JwtSvids: &serverlessapi.JWTSVIDResult{
			Svids: []*serverlessapi.JWTSVID{{SpiffeId: "spiffe://example.org/workload", Svid: token}},
		},
	}}
	client := newTestClient(t, srv)

	svid, err := client.JWTSource().FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: "https://api.example.org"})
	if err != nil {
		t.Fatalf("FetchJWTSVID() error = %v", err)
	}
	if svid.ID.String() != "spiffe://example.org/workload" {
		t.Errorf("ID = %q, want spiffe://example.org/workload", svid.ID.String())
	}
	if srv.lastJWTSVID.Audience[0] != "https://api.example.org" {
		t.Errorf("request audience = %v, want [https://api.example.org]", srv.lastJWTSVID.Audience)
	}
}

func TestJWTSource_FetchJWTSVID_ExtraAudiences(t *testing.T) {
	token := buildJWTFixture(t, map[string]any{"sub": "spiffe://example.org/workload", "aud": []string{"a", "b"}, "exp": time.Now().Add(time.Hour).Unix()})
	srv := &fakeServer{jwtSVIDResp: &serverlessapi.FetchJWTSVIDResponse{
		JwtSvids: &serverlessapi.JWTSVIDResult{Svids: []*serverlessapi.JWTSVID{{SpiffeId: "spiffe://example.org/workload", Svid: token}}},
	}}
	client := newTestClient(t, srv)

	_, err := client.JWTSource().FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: "a", ExtraAudiences: []string{"b"}})
	if err != nil {
		t.Fatalf("FetchJWTSVID() error = %v", err)
	}
	if len(srv.lastJWTSVID.Audience) != 2 || srv.lastJWTSVID.Audience[0] != "a" || srv.lastJWTSVID.Audience[1] != "b" {
		t.Errorf("request audience = %v, want [a b]", srv.lastJWTSVID.Audience)
	}
}

func TestJWTSource_FetchJWTSVID_SendsSubject(t *testing.T) {
	const id = "spiffe://example.org/workload"
	token := buildJWTFixture(t, map[string]any{"sub": id, "aud": []string{"a"}, "exp": time.Now().Add(time.Hour).Unix()})
	srv := &fakeServer{jwtSVIDResp: &serverlessapi.FetchJWTSVIDResponse{
		JwtSvids: &serverlessapi.JWTSVIDResult{Svids: []*serverlessapi.JWTSVID{{SpiffeId: id, Svid: token}}},
	}}
	client := newTestClient(t, srv)
	source := client.JWTSource()

	if _, err := source.FetchJWTSVID(context.Background(), jwtsvid.Params{
		Audience: "a",
		Subject:  spiffeid.RequireFromString(id),
	}); err != nil {
		t.Fatalf("FetchJWTSVID() error = %v", err)
	}
	if got := srv.lastJWTSVID.GetSpiffeId(); got != id {
		t.Errorf("request spiffe_id = %q, want %q", got, id)
	}

	// An unset Subject must send the empty string, not panic or invent an ID.
	if _, err := source.FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: "a"}); err != nil {
		t.Fatalf("FetchJWTSVID() without Subject error = %v", err)
	}
	if got := srv.lastJWTSVID.GetSpiffeId(); got != "" {
		t.Errorf("request spiffe_id = %q with no Subject, want empty", got)
	}
}

func TestJWTSource_FetchJWTSVID_NoSVIDsInResponse(t *testing.T) {
	srv := &fakeServer{jwtSVIDResp: &serverlessapi.FetchJWTSVIDResponse{JwtSvids: &serverlessapi.JWTSVIDResult{}}}
	client := newTestClient(t, srv)

	_, err := client.JWTSource().FetchJWTSVID(context.Background(), jwtsvid.Params{Audience: "a"})
	if err == nil {
		t.Error("FetchJWTSVID() error = nil, want error for empty svids")
	}
}

func TestJWTSource_GetJWTBundleForTrustDomain(t *testing.T) {
	jwks := []byte(`{"keys":[]}`)
	srv := &fakeServer{jwtBundlesResp: &serverlessapi.FetchJWTBundlesResponse{
		Bundles: &serverlessapi.JWTBundlesResult{Bundles: map[string][]byte{"example.org": jwks}},
	}}
	client := newTestClient(t, srv)

	td := spiffeid.RequireTrustDomainFromString("example.org")
	if _, err := client.JWTSource().GetJWTBundleForTrustDomain(td); err != nil {
		t.Errorf("GetJWTBundleForTrustDomain(example.org) error = %v", err)
	}

	other := spiffeid.RequireTrustDomainFromString("other.org")
	if _, err := client.JWTSource().GetJWTBundleForTrustDomain(other); !errors.Is(err, ErrBundleNotFound) {
		t.Errorf("GetJWTBundleForTrustDomain(other.org) err = %v, want ErrBundleNotFound", err)
	}
}

func TestJWTSource_GetJWTBundleForTrustDomain_Caches(t *testing.T) {
	srv := &fakeServer{jwtBundlesResp: &serverlessapi.FetchJWTBundlesResponse{
		Bundles: &serverlessapi.JWTBundlesResult{Bundles: map[string][]byte{"example.org": []byte(`{"keys":[]}`)}},
	}}
	source := newTestClient(t, srv).JWTSource()
	td := spiffeid.RequireTrustDomainFromString("example.org")

	for i := range 3 {
		if _, err := source.GetJWTBundleForTrustDomain(td); err != nil {
			t.Fatalf("call %d error = %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&srv.jwtBundlesFetchCount); got != 1 {
		t.Errorf("FetchJWTBundles calls = %d within the TTL, want 1", got)
	}

	// An unknown trust domain must also be answered from the fresh cache,
	// otherwise it stays an attestation-amplification vector.
	other := spiffeid.RequireTrustDomainFromString("other.org")
	if _, err := source.GetJWTBundleForTrustDomain(other); !errors.Is(err, ErrBundleNotFound) {
		t.Errorf("GetJWTBundleForTrustDomain(other.org) err = %v, want ErrBundleNotFound", err)
	}
	if got := atomic.LoadInt32(&srv.jwtBundlesFetchCount); got != 1 {
		t.Errorf("FetchJWTBundles calls = %d after a cached miss, want 1", got)
	}
}

func TestJWTSource_GetJWTBundleForTrustDomain_RefetchesAfterTTL(t *testing.T) {
	srv := &fakeServer{jwtBundlesResp: &serverlessapi.FetchJWTBundlesResponse{
		Bundles: &serverlessapi.JWTBundlesResult{Bundles: map[string][]byte{"example.org": []byte(`{"keys":[]}`)}},
	}}
	source := newTestClient(t, srv).JWTSource()
	td := spiffeid.RequireTrustDomainFromString("example.org")

	original := jwtBundleCacheTTL
	jwtBundleCacheTTL = 10 * time.Millisecond
	t.Cleanup(func() { jwtBundleCacheTTL = original })

	if _, err := source.GetJWTBundleForTrustDomain(td); err != nil {
		t.Fatalf("first call error = %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := source.GetJWTBundleForTrustDomain(td); err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if got := atomic.LoadInt32(&srv.jwtBundlesFetchCount); got != 2 {
		t.Errorf("FetchJWTBundles calls = %d across an expired TTL, want 2", got)
	}
}

func TestJWTSource_GetJWTBundleForTrustDomain_FetchErrorKeepsCache(t *testing.T) {
	srv := &fakeServer{jwtBundlesResp: &serverlessapi.FetchJWTBundlesResponse{
		Bundles: &serverlessapi.JWTBundlesResult{Bundles: map[string][]byte{"example.org": []byte(`{"keys":[]}`)}},
	}}
	source := newTestClient(t, srv).JWTSource()
	td := spiffeid.RequireTrustDomainFromString("example.org")

	if _, err := source.GetJWTBundleForTrustDomain(td); err != nil {
		t.Fatalf("warm-up call error = %v", err)
	}

	original := jwtBundleCacheTTL
	jwtBundleCacheTTL = 10 * time.Millisecond
	t.Cleanup(func() { jwtBundleCacheTTL = original })
	time.Sleep(20 * time.Millisecond)

	srv.jwtBundlesErr = errors.New("server down")
	if _, err := source.GetJWTBundleForTrustDomain(td); err == nil {
		t.Fatal("GetJWTBundleForTrustDomain() error = nil, want the server's error")
	}

	// The failed fetch must not have poisoned the cache: restore the TTL and
	// the previously cached bundle is still served.
	jwtBundleCacheTTL = time.Minute
	if _, err := source.GetJWTBundleForTrustDomain(td); err != nil {
		t.Errorf("post-failure call error = %v, want the retained cached bundle", err)
	}
}
