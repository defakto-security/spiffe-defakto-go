package attestingworkloadapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
)

type noopAttestor struct{}

func (noopAttestor) PluginName() string    { return "noop" }
func (noopAttestor) PluginVersion() string { return "1.0" }
func (noopAttestor) CollectEvidence(context.Context) (attestation.Evidence, error) {
	return attestation.Evidence{}, nil
}

func TestParseServerAddress(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "host and port", value: "my-server.internal:8443", wantHost: "my-server.internal", wantPort: 8443},
		{name: "host only defaults to 443", value: "my-server.internal", wantHost: "my-server.internal", wantPort: 443},
		{name: "bracketed IPv6 with port", value: "[::1]:443", wantHost: "::1", wantPort: 443},
		{name: "empty value is invalid", value: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseServerAddress(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseServerAddress(%q) error = nil, want error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseServerAddress(%q) error = %v", tt.value, err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("parseServerAddress(%q) = (%q, %d), want (%q, %d)", tt.value, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestResolveTarget_ExplicitServerAddress(t *testing.T) {
	cfg := &config{serverAddress: "my-server.internal:8443"}
	target, err := resolveTarget(cfg)
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if target != "my-server.internal:8443" {
		t.Errorf("target = %q, want %q", target, "my-server.internal:8443")
	}
}

func TestResolveTarget_TrustDomainID(t *testing.T) {
	cfg := &config{trustDomainID: "td-m36ckrte4e"}
	target, err := resolveTarget(cfg)
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if target != "td-m36ckrte4e.agent.spirl.com:443" {
		t.Errorf("target = %q, want %q", target, "td-m36ckrte4e.agent.spirl.com:443")
	}
}

func TestResolveTarget_InvalidTrustDomainID(t *testing.T) {
	cfg := &config{trustDomainID: "Not_Valid!"}
	if _, err := resolveTarget(cfg); !errors.Is(err, ErrInvalidTrustDomain) {
		t.Errorf("err = %v, want ErrInvalidTrustDomain", err)
	}
}

func TestResolveTarget_NothingConfigured(t *testing.T) {
	cfg := &config{}
	if _, err := resolveTarget(cfg); !errors.Is(err, ErrServerAddressNotConfigured) {
		t.Errorf("err = %v, want ErrServerAddressNotConfigured", err)
	}
}

func TestNew_NoAttestorsConfigured(t *testing.T) {
	_, err := New(context.Background(), WithTarget("passthrough:///bufnet"))
	if !errors.Is(err, ErrNoAttestorsConfigured) {
		t.Errorf("err = %v, want ErrNoAttestorsConfigured", err)
	}
}

func TestNew_UsesExplicitTarget(t *testing.T) {
	c, err := New(context.Background(),
		WithAttestors(noopAttestor{}),
		WithTarget("passthrough:///bufnet"),
		WithDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = c.Close() }()
	if len(c.attestors) != 1 {
		t.Errorf("len(attestors) = %d, want 1", len(c.attestors))
	}
}
