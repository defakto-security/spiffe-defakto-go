package attestingworkloadapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

func newTestClient(t *testing.T, srv serverlessapi.SpiffeWorkloadAPIServer) *Client {
	t.Helper()
	conn := dialFakeServer(t, srv)
	return &Client{
		conn:      conn,
		stub:      serverlessapi.NewSpiffeWorkloadAPIClient(conn),
		attestors: []attestation.Attestor{&fixedAttestor{name: "fake", version: "1.0"}},
	}
}

func TestX509Source_GetX509SVID(t *testing.T) {
	certDER, keyDER := buildX509Fixture(t, "spiffe://example.org/workload")
	srv := &fakeServer{x509Resp: &serverlessapi.FetchX509SVIDResponse{
		X509Svids: &serverlessapi.X509SVIDResult{
			Svids: []*serverlessapi.X509SVID{{
				SpiffeId: "spiffe://example.org/workload", X509Svid: certDER, X509SvidKey: keyDER, Bundle: certDER,
			}},
		},
	}}
	client := newTestClient(t, srv)

	src, err := client.X509Source(context.Background())
	if err != nil {
		t.Fatalf("X509Source() error = %v", err)
	}
	defer func() { _ = src.Close() }()

	svid, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID() error = %v", err)
	}
	if svid.ID.String() != "spiffe://example.org/workload" {
		t.Errorf("ID = %q, want spiffe://example.org/workload", svid.ID.String())
	}
}

func TestX509Source_GetX509BundleForTrustDomain(t *testing.T) {
	certDER, keyDER := buildX509Fixture(t, "spiffe://example.org/workload")
	srv := &fakeServer{x509Resp: &serverlessapi.FetchX509SVIDResponse{
		X509Svids: &serverlessapi.X509SVIDResult{
			Svids: []*serverlessapi.X509SVID{{
				SpiffeId: "spiffe://example.org/workload", X509Svid: certDER, X509SvidKey: keyDER, Bundle: certDER,
			}},
		},
	}}
	client := newTestClient(t, srv)

	src, err := client.X509Source(context.Background())
	if err != nil {
		t.Fatalf("X509Source() error = %v", err)
	}
	defer func() { _ = src.Close() }()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	if _, err := src.GetX509BundleForTrustDomain(td); err != nil {
		t.Errorf("GetX509BundleForTrustDomain(example.org) error = %v", err)
	}

	other := spiffeid.RequireTrustDomainFromString("other.org")
	if _, err := src.GetX509BundleForTrustDomain(other); !errors.Is(err, ErrBundleNotFound) {
		t.Errorf("GetX509BundleForTrustDomain(other.org) err = %v, want ErrBundleNotFound", err)
	}
}

func TestX509Source_ConstructionFailsOnAttestationFailure(t *testing.T) {
	srv := &fakeServer{x509Err: errors.New("denied")}
	client := newTestClient(t, srv)

	if _, err := client.X509Source(context.Background()); err == nil {
		t.Error("X509Source() error = nil, want error when the server rejects attestation")
	}
}

func TestX509Source_Close_StopsBackgroundRefresh(t *testing.T) {
	certDER, keyDER := buildX509Fixture(t, "spiffe://example.org/workload")
	srv := &fakeServer{x509Resp: &serverlessapi.FetchX509SVIDResponse{
		X509Svids: &serverlessapi.X509SVIDResult{
			Svids: []*serverlessapi.X509SVID{{SpiffeId: "spiffe://example.org/workload", X509Svid: certDER, X509SvidKey: keyDER}},
		},
	}}
	client := newTestClient(t, srv)

	src, err := client.X509Source(context.Background())
	if err != nil {
		t.Fatalf("X509Source() error = %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// Closing twice must not panic.
	if err := src.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	// Give any leaked goroutine a moment; nothing to assert beyond "no panic,
	// no hang" — the race detector (mise run test uses -race) catches
	// unsynchronized access if refreshLoop kept running against a closed source.
	time.Sleep(10 * time.Millisecond)
}
