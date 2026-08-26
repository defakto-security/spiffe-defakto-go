// Package attestingworkloadapi is the Defakto attesting Workload API
// client: it obtains SVIDs via serverless attestation instead of the local
// SPIFFE Workload API socket, for environments where a persistent Defakto
// agent isn't practical (Lambda, Cloud Run, restricted Kubernetes, etc.).
package attestingworkloadapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

const (
	envServerAddress = "DEFAKTO_SERVER_ADDRESS"
	envTrustDomainID = "DEFAKTO_TRUST_DOMAIN_ID"
	envClusterID     = "DEFAKTO_CLUSTER_ID"

	defaultPort = 443
)

var trustDomainIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type config struct {
	attestors     []attestation.Attestor
	serverAddress string
	trustDomainID string
	clusterID     string
	target        string
	dialOptions   []grpc.DialOption
}

// Option configures a Client.
type Option func(*config)

// WithAttestors sets the evidence sources used for every attestation
// handshake. Required — New returns ErrNoAttestorsConfigured without it.
func WithAttestors(attestors ...attestation.Attestor) Option {
	return func(c *config) { c.attestors = attestors }
}

// WithServerAddress overrides DEFAKTO_SERVER_ADDRESS: a self-hosted Trust
// Domain Server's "host" or "host:port" (default port 443).
func WithServerAddress(addr string) Option {
	return func(c *config) { c.serverAddress = addr }
}

// WithTrustDomainID overrides DEFAKTO_TRUST_DOMAIN_ID: a Defakto-hosted
// trust domain ID, resolved to "<id>.agent.spirl.com:443".
func WithTrustDomainID(id string) Option {
	return func(c *config) { c.trustDomainID = id }
}

// WithClusterID overrides DEFAKTO_CLUSTER_ID, scoping issuance to a
// specific serverless cluster's policy set. Empty selects the
// trust-domain-scoped policy set.
func WithClusterID(id string) Option {
	return func(c *config) { c.clusterID = id }
}

// WithDialOptions overrides the gRPC dial options used to connect. Defaults
// to TLS with the system root CA pool.
func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(c *config) { c.dialOptions = opts }
}

// WithTarget sets the gRPC dial target directly, bypassing
// WithServerAddress/WithTrustDomainID resolution entirely. Intended for
// tests and custom gRPC resolver schemes.
func WithTarget(target string) Option {
	return func(c *config) { c.target = target }
}

// Client is the Defakto attesting Workload API client.
type Client struct {
	conn      *grpc.ClientConn
	stub      serverlessapi.SpiffeWorkloadAPIClient
	attestors []attestation.Attestor
	clusterID string
}

// New builds a Client. The gRPC channel is lazily connected on first use.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	if len(cfg.attestors) == 0 {
		return nil, ErrNoAttestorsConfigured
	}
	for _, a := range cfg.attestors {
		if isNilAttestor(a) {
			return nil, ErrNoAttestorsConfigured
		}
	}

	target := cfg.target
	if target == "" {
		var err error
		target, err = resolveTarget(cfg)
		if err != nil {
			return nil, err
		}
	}

	dialOptions := cfg.dialOptions
	if dialOptions == nil {
		dialOptions = []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))}
	}

	conn, err := grpc.NewClient(target, dialOptions...)
	if err != nil {
		return nil, newError(CodeDialFailed, fmt.Sprintf("attestingworkloadapi: dial %s", target), err)
	}

	clusterID := strings.TrimSpace(cfg.clusterID)
	if clusterID == "" {
		clusterID = strings.TrimSpace(os.Getenv(envClusterID))
	}

	_ = ctx // reserved: no blocking initial RPC, unlike workloadapi.NewX509Source; each fetch is on-demand.

	return &Client{
		conn:      conn,
		stub:      serverlessapi.NewSpiffeWorkloadAPIClient(conn),
		attestors: cfg.attestors,
		clusterID: clusterID,
	}, nil
}

// Close releases the underlying gRPC channel.
func (c *Client) Close() error {
	return c.conn.Close()
}

// isNilAttestor reports whether a is nil: either the plain interface nil
// from an empty WithAttestors entry, or a typed nil pointer (e.g.
// (*awstoken.Attestor)(nil)) wrapped in a non-nil interface, which would
// otherwise panic the first time collectAttestations calls CollectEvidence
// on it.
func isNilAttestor(a attestation.Attestor) bool {
	if a == nil {
		return true
	}
	v := reflect.ValueOf(a)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// resolveTarget picks the gRPC dial target: an explicit/env server address
// wins, then an explicit/env trust domain ID, else ErrServerAddressNotConfigured.
func resolveTarget(cfg *config) (string, error) {
	addr := cfg.serverAddress
	if addr == "" {
		addr = os.Getenv(envServerAddress)
	}
	if addr != "" {
		host, port, err := parseServerAddress(addr)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	}

	trustDomainID := cfg.trustDomainID
	if trustDomainID == "" {
		trustDomainID = os.Getenv(envTrustDomainID)
	}
	if trustDomainID != "" {
		if !trustDomainIDPattern.MatchString(trustDomainID) {
			return "", newError(CodeInvalidTrustDomain, fmt.Sprintf("invalid %s=%q: must match ^[a-z0-9][a-z0-9-]*$", envTrustDomainID, trustDomainID), nil)
		}
		return fmt.Sprintf("%s.agent.spirl.com:443", trustDomainID), nil
	}

	return "", newError(CodeServerAddressNotConfigured,
		fmt.Sprintf("no server address configured: set %s (self-hosted) or %s (Defakto-hosted), or pass WithTarget", envServerAddress, envTrustDomainID), nil)
}

// parseServerAddress parses "host:port" or a bare "host" (default port 443),
// accepting bracketed IPv6 literals like "[::1]:443".
func parseServerAddress(value string) (host string, port int, err error) {
	if value == "" {
		return "", 0, newError(CodeInvalidServerAddress, fmt.Sprintf("invalid %s: empty value", envServerAddress), nil)
	}
	u, err := url.Parse("//" + value)
	if err != nil {
		return "", 0, newError(CodeInvalidServerAddress, fmt.Sprintf("invalid %s=%q: %v", envServerAddress, value, err), err)
	}
	host = u.Hostname()
	if host == "" {
		return "", 0, newError(CodeInvalidServerAddress, fmt.Sprintf("invalid %s=%q: host is empty", envServerAddress, value), nil)
	}
	port = defaultPort
	if p := u.Port(); p != "" {
		parsedPort, convErr := strconv.Atoi(p)
		if convErr != nil {
			return "", 0, newError(CodeInvalidServerAddress, fmt.Sprintf("invalid port in %s=%q", envServerAddress, value), convErr)
		}
		port = parsedPort
	}
	return host, port, nil
}
