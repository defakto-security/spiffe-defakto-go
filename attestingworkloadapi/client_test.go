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

// ptrAttestor has pointer receivers, so a nil *ptrAttestor is a typed-nil
// value wrapped in a non-nil attestation.Attestor interface — the case
// isNilAttestor must catch that a plain `== nil` check on the interface
// would miss.
type ptrAttestor struct{}

func (*ptrAttestor) PluginName() string    { return "ptr" }
func (*ptrAttestor) PluginVersion() string { return "1.0" }
func (*ptrAttestor) CollectEvidence(context.Context) (attestation.Evidence, error) {
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
	t.Setenv(envServerAddress, "")
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
	t.Setenv(envServerAddress, "")
	cfg := &config{trustDomainID: "Not_Valid!"}
	if _, err := resolveTarget(cfg); !errors.Is(err, ErrInvalidTrustDomain) {
		t.Errorf("err = %v, want ErrInvalidTrustDomain", err)
	}
}

func TestResolveTarget_NothingConfigured(t *testing.T) {
	// Cleared explicitly: resolveTarget falls back to these, so an ambient
	// value in the developer's or CI's environment would break the test.
	t.Setenv(envServerAddress, "")
	t.Setenv(envTrustDomainID, "")

	cfg := &config{}
	if _, err := resolveTarget(cfg); !errors.Is(err, ErrServerAddressNotConfigured) {
		t.Errorf("err = %v, want ErrServerAddressNotConfigured", err)
	}
}

func TestResolveTarget_ServerAddressFromEnv(t *testing.T) {
	t.Setenv(envServerAddress, "env-server.internal:9443")
	t.Setenv(envTrustDomainID, "")

	target, err := resolveTarget(&config{})
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if target != "env-server.internal:9443" {
		t.Errorf("target = %q, want %q", target, "env-server.internal:9443")
	}
}

func TestResolveTarget_TrustDomainIDFromEnv(t *testing.T) {
	t.Setenv(envServerAddress, "")
	t.Setenv(envTrustDomainID, "td-m36ckrte4e")

	target, err := resolveTarget(&config{})
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if target != "td-m36ckrte4e.agent.spirl.com:443" {
		t.Errorf("target = %q, want %q", target, "td-m36ckrte4e.agent.spirl.com:443")
	}
}

func TestResolveTarget_ExplicitServerAddressBeatsEnv(t *testing.T) {
	t.Setenv(envServerAddress, "env-server.internal:9443")

	target, err := resolveTarget(&config{serverAddress: "explicit.internal:8443"})
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if target != "explicit.internal:8443" {
		t.Errorf("target = %q, want the explicit address to win over the env var", target)
	}
}

func TestNew_ClusterIDFromEnv(t *testing.T) {
	t.Setenv(envClusterID, "cluster-from-env")

	c, err := New(context.Background(),
		WithAttestors(noopAttestor{}),
		WithTarget("passthrough:///bufnet"),
		WithDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.clusterID != "cluster-from-env" {
		t.Errorf("clusterID = %q, want %q", c.clusterID, "cluster-from-env")
	}
}

func TestNew_ExplicitClusterIDBeatsEnv(t *testing.T) {
	t.Setenv(envClusterID, "cluster-from-env")

	c, err := New(context.Background(),
		WithAttestors(noopAttestor{}),
		WithClusterID("explicit-cluster"),
		WithTarget("passthrough:///bufnet"),
		WithDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.clusterID != "explicit-cluster" {
		t.Errorf("clusterID = %q, want %q", c.clusterID, "explicit-cluster")
	}
}

func TestNew_ExplicitEmptyClusterIDBeatsEnv(t *testing.T) {
	t.Setenv(envClusterID, "cluster-from-env")

	c, err := New(context.Background(),
		WithAttestors(noopAttestor{}),
		WithClusterID(""),
		WithTarget("passthrough:///bufnet"),
		WithDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.clusterID != "" {
		t.Errorf("clusterID = %q, want empty: explicit empty must not fall back to %s", c.clusterID, envClusterID)
	}
}

func TestNew_NoAttestorsConfigured(t *testing.T) {
	_, err := New(context.Background(), WithTarget("passthrough:///bufnet"))
	if !errors.Is(err, ErrNoAttestorsConfigured) {
		t.Errorf("err = %v, want ErrNoAttestorsConfigured", err)
	}
}

func TestNew_RejectsNilAttestor(t *testing.T) {
	_, err := New(context.Background(), WithAttestors(nil), WithTarget("passthrough:///bufnet"))
	if !errors.Is(err, ErrNoAttestorsConfigured) {
		t.Errorf("err = %v, want ErrNoAttestorsConfigured", err)
	}
}

func TestNew_RejectsTypedNilAttestor(t *testing.T) {
	var a *ptrAttestor
	_, err := New(context.Background(), WithAttestors(a), WithTarget("passthrough:///bufnet"))
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
