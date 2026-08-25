package attestingworkloadapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

// buildX509Fixture returns DER-encoded (cert, PKCS#8 key) for a self-signed
// leaf whose SAN is the given SPIFFE ID — mirroring what a Trust Domain
// Server would actually issue.
func buildX509Fixture(t *testing.T, spiffeID string) (certDER, keyDER []byte) {
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
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "test"},
		NotBefore:          time.Now().Add(-time.Minute),
		NotAfter:           time.Now().Add(time.Hour),
		URIs:               []*url.URL{uri},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// buildJWTFixture returns a syntactically valid JWT-SVID token carrying
// the given claims, signed with RS256 for syntactic validity.
// The signature is still generated fresh; jwtsvid.ParseInsecure does not
// verify it but requires the structure to be well-formed.
func buildJWTFixture(t *testing.T, claims map[string]any) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	message := enc(headerJSON) + "." + enc(claimsJSON)

	h := sha256.New()
	h.Write([]byte(message))
	digest := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return message + "." + enc(sig)
}

func TestCollectAttestations(t *testing.T) {
	a1 := &fixedAttestor{name: "aws_token", version: "1.0", evidence: attestation.Evidence{Payload: []byte("aws-evidence")}}
	a2 := &fixedAttestor{name: "gcp_iit", version: "1.0", evidence: attestation.Evidence{Payload: []byte("gcp-evidence")}}

	got, err := collectAttestations(context.Background(), []attestation.Attestor{a1, a2})
	if err != nil {
		t.Fatalf("collectAttestations() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].MethodType != "aws_token" || string(got[0].Evidence) != "aws-evidence" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].MethodType != "gcp_iit" || string(got[1].Evidence) != "gcp-evidence" {
		t.Errorf("got[1] = %+v", got[1])
	}
}

func TestCollectAttestations_OneFails(t *testing.T) {
	wantErr := errors.New("boom")
	a1 := &fixedAttestor{name: "ok", version: "1.0"}
	a2 := &fixedAttestor{name: "bad", version: "1.0", err: wantErr}

	_, err := collectAttestations(context.Background(), []attestation.Attestor{a1, a2})
	if !errors.Is(err, ErrAttestorCollectionFailed) {
		t.Errorf("err = %v, want ErrAttestorCollectionFailed", err)
	}
}

func TestParseX509Response(t *testing.T) {
	certDER, keyDER := buildX509Fixture(t, "spiffe://example.org/workload")
	proto := &serverlessapi.X509SVID{
		SpiffeId:    "spiffe://example.org/workload",
		X509Svid:    certDER,
		X509SvidKey: keyDER,
		Bundle:      certDER, // reuse the leaf as a stand-in trust bundle DER
		Hint:        "internal",
	}

	svids, bundles, err := parseX509Response([]*serverlessapi.X509SVID{proto}, nil)
	if err != nil {
		t.Fatalf("parseX509Response() error = %v", err)
	}
	if len(svids) != 1 {
		t.Fatalf("len(svids) = %d, want 1", len(svids))
	}
	if svids[0].ID.String() != "spiffe://example.org/workload" {
		t.Errorf("ID = %q, want spiffe://example.org/workload", svids[0].ID.String())
	}
	if svids[0].Hint != "internal" {
		t.Errorf("Hint = %q, want internal", svids[0].Hint)
	}
	if _, ok := bundles["example.org"]; !ok {
		t.Errorf("bundles missing own trust domain example.org: %+v", bundles)
	}
}

func TestParseJWTSVIDFromProto(t *testing.T) {
	now := time.Now()
	token := buildJWTFixture(t, map[string]any{
		"sub": "spiffe://example.org/workload",
		"aud": []string{"https://api.example.org"},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	proto := &serverlessapi.JWTSVID{SpiffeId: "spiffe://example.org/workload", Svid: token, Hint: "external"}

	svid, err := parseJWTSVIDFromProto(proto, []string{"https://api.example.org"})
	if err != nil {
		t.Fatalf("parseJWTSVIDFromProto() error = %v", err)
	}
	if svid.ID.String() != "spiffe://example.org/workload" {
		t.Errorf("ID = %q, want spiffe://example.org/workload", svid.ID.String())
	}
	if svid.Hint != "external" {
		t.Errorf("Hint = %q, want external", svid.Hint)
	}
}

type fixedAttestor struct {
	name, version string
	evidence      attestation.Evidence
	err           error
}

func (f *fixedAttestor) PluginName() string    { return f.name }
func (f *fixedAttestor) PluginVersion() string { return f.version }
func (f *fixedAttestor) CollectEvidence(context.Context) (attestation.Evidence, error) {
	return f.evidence, f.err
}
