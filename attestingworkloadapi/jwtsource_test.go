package attestingworkloadapi

import (
	"context"
	"errors"
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
