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
	"strings"
	"sync"
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

func TestFailureBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: minRefreshDelay},
		{failures: 2, want: 2 * minRefreshDelay},
		{failures: 3, want: 4 * minRefreshDelay},
		{failures: 4, want: 8 * minRefreshDelay},
		{failures: 20, want: maxRefreshBackoff},
		{failures: 1000, want: maxRefreshBackoff},
	}
	for _, tt := range tests {
		if got := failureBackoff(tt.failures); got != tt.want {
			t.Errorf("failureBackoff(%d) = %v, want %v", tt.failures, got, tt.want)
		}
	}
}

// flakyX509Server fails FetchX509SVID for calls 2..failThrough (the first
// call, X509Source's blocking initial fetch, always succeeds) and records
// when each call arrived, so a test can watch the retry cadence grow.
type flakyX509Server struct {
	serverlessapi.UnimplementedSpiffeWorkloadAPIServer

	resp        *serverlessapi.FetchX509SVIDResponse
	failThrough int

	mu    sync.Mutex
	calls []time.Time
}

func (f *flakyX509Server) FetchX509SVID(_ context.Context, _ *serverlessapi.FetchX509SVIDRequest) (*serverlessapi.FetchX509SVIDResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, time.Now())
	n := len(f.calls)
	f.mu.Unlock()

	if n > 1 && n <= f.failThrough {
		return nil, errors.New("attestation denied")
	}
	return f.resp, nil
}

func (f *flakyX509Server) callTimes() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.calls...)
}

func TestX509Source_RefreshFailures_BackOffAndSurfaceLastError(t *testing.T) {
	// Expiry is deliberately short so the first refresh fires at ~1.02s
	// (0.85 * 1.2s); after that the SVID is expired, refreshDelay floors at
	// minRefreshDelay, and only failureBackoff separates the attempts.
	certDER, keyDER := buildX509FixtureWithExpiry(t, "spiffe://example.org/workload", time.Now().Add(1200*time.Millisecond))
	srv := &flakyX509Server{
		failThrough: 3, // calls 2 and 3 fail, call 4 succeeds
		resp: &serverlessapi.FetchX509SVIDResponse{
			X509Svids: &serverlessapi.X509SVIDResult{
				Svids: []*serverlessapi.X509SVID{{SpiffeId: "spiffe://example.org/workload", X509Svid: certDER, X509SvidKey: keyDER}},
			},
		},
	}
	client := newTestClient(t, srv)

	src, err := client.X509Source(context.Background())
	if err != nil {
		t.Fatalf("X509Source() error = %v", err)
	}
	defer func() { _ = src.Close() }()

	if err := src.LastRefreshError(); err != nil {
		t.Errorf("LastRefreshError() = %v before any refresh, want nil", err)
	}

	// Both failures have landed by now (~1.0s and ~3.0s) but the successful
	// retry (~6.0s) has not.
	time.Sleep(4 * time.Second)
	refreshErr := src.LastRefreshError()
	if refreshErr == nil {
		t.Fatal("LastRefreshError() = nil while refresh is failing, want the server's error")
	}
	if !errors.Is(refreshErr, ErrAttestationFailed) {
		t.Errorf("LastRefreshError() = %v, want an ErrAttestationFailed", refreshErr)
	}
	if !strings.Contains(refreshErr.Error(), "attestation denied") {
		t.Errorf("LastRefreshError() = %v, want it to carry the server's %q", refreshErr, "attestation denied")
	}
	// A 1s-floor hot loop would have burned through far more than this.
	if got := len(srv.callTimes()); got > 4 {
		t.Errorf("FetchX509SVID calls = %d in 4s, want <= 4 (backoff is not spacing retries out)", got)
	}

	// Wait out the 2s backoff after the second failure plus the 1s floor.
	time.Sleep(4 * time.Second)
	if err := src.LastRefreshError(); err != nil {
		t.Errorf("LastRefreshError() = %v after a successful refresh, want nil", err)
	}

	calls := srv.callTimes()
	if len(calls) < 4 {
		t.Fatalf("FetchX509SVID calls = %d, want >= 4 (initial + 2 failures + 1 success)", len(calls))
	}
	firstGap := calls[2].Sub(calls[1])  // after 1 failure: 1s backoff + 1s floor
	secondGap := calls[3].Sub(calls[2]) // after 2 failures: 2s backoff + 1s floor
	if secondGap <= firstGap {
		t.Errorf("retry gaps = %v then %v, want the second to be longer (exponential backoff)", firstGap, secondGap)
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

	// Poll for the first background refresh instead of sleeping a fixed
	// window: the fixture's fixed NotAfter means every refresh after the
	// first floors at minRefreshDelay (1s), so a fixed-sleep-then-snapshot
	// check races the next scheduled refresh under host scheduling jitter.
	// Polling only needs "at least one refresh happened", not "happened by
	// this exact deadline".
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt32(&srv.x509FetchCount) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	countAfterRunning := atomic.LoadInt32(&srv.x509FetchCount)
	if countAfterRunning < 2 {
		t.Fatalf("x509FetchCount = %d after 10s, want >= 2 (initial fetch + at least one refresh)", countAfterRunning)
	}

	if err := src.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	countAtClose := atomic.LoadInt32(&srv.x509FetchCount)
	// Wait several multiples of the 1s retry floor: any refresh in flight
	// when Close() landed settles well within this window, so a persistent
	// increase past countAtClose means the background loop genuinely didn't
	// stop, not that we sampled too early.
	time.Sleep(5 * time.Second)
	countAfterClose := atomic.LoadInt32(&srv.x509FetchCount)
	if countAfterClose > countAtClose+1 {
		t.Errorf("x509FetchCount grew from %d to %d well after Close(); background refresh did not stop", countAtClose, countAfterClose)
	}
}
