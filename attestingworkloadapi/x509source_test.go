package attestingworkloadapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

// buildX509FixtureWithExpiry is buildX509Fixture with a caller-chosen
// NotAfter, for tests that need to observe the background refresh loop
// actually fire rather than wait out the standard 1-hour fixture.
func buildX509FixtureWithExpiry(t *testing.T, spiffeID string, notAfter time.Time) (certDER, keyDER []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("parse spiffe id: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		URIs:                  []*url.URL{uri},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return certDER, keyDER
}

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

func TestRefreshDelay(t *testing.T) {
	tests := []struct {
		name       string
		expiresIn  time.Duration
		wantAtLeat time.Duration
		wantAtMost time.Duration
	}{
		{name: "already expired floors at minRefreshDelay", expiresIn: -time.Minute, wantAtLeat: minRefreshDelay, wantAtMost: minRefreshDelay},
		{name: "1 hour out is ~0.85 of remaining", expiresIn: time.Hour, wantAtLeat: 50 * time.Minute, wantAtMost: 52 * time.Minute},
		{name: "a few hundred ms out floors at minRefreshDelay", expiresIn: 300 * time.Millisecond, wantAtLeat: minRefreshDelay, wantAtMost: minRefreshDelay},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refreshDelay(time.Now().Add(tt.expiresIn))
			if got < tt.wantAtLeat || got > tt.wantAtMost {
				t.Errorf("refreshDelay(now+%v) = %v, want between %v and %v", tt.expiresIn, got, tt.wantAtLeat, tt.wantAtMost)
			}
		})
	}
}

func TestX509Source_BackgroundRefresh_FiresThenStopsOnClose(t *testing.T) {
	certDER, keyDER := buildX509FixtureWithExpiry(t, "spiffe://example.org/workload", time.Now().Add(1500*time.Millisecond))
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

	// refreshDelay(now+1.5s) ~= 1.275s (0.85 * remaining), comfortably above
	// the 1s floor and within this sleep's patience.
	time.Sleep(2 * time.Second)
	countAfterRunning := atomic.LoadInt32(&srv.x509FetchCount)
	if countAfterRunning < 2 {
		t.Fatalf("x509FetchCount = %d after 2s running, want >= 2 (initial fetch + at least one refresh)", countAfterRunning)
	}

	if err := src.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	time.Sleep(2 * time.Second)
	countAfterClose := atomic.LoadInt32(&srv.x509FetchCount)
	if countAfterClose != countAfterRunning {
		t.Errorf("x509FetchCount grew from %d to %d after Close(); background refresh did not stop", countAfterRunning, countAfterClose)
	}
}
