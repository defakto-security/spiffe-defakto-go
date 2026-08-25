// Package awstoken attests an AWS workload via STS GetWebIdentityToken.
// Works in any environment with an attached IAM role: Lambda, ECS, EC2, EKS
// pods with IRSA.
package awstoken

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
)

const (
	pluginName    = "aws_token"
	pluginVersion = "1.0"

	defaultAudience         = "urn:defakto:security:server"
	defaultSigningAlgorithm = "RS256"
	defaultDurationSeconds  = int32(60)
)

// tokenGetter is the subset of *sts.Client this attestor needs, narrowed so
// tests can fake STS without a network call.
type tokenGetter interface {
	GetWebIdentityToken(ctx context.Context, params *sts.GetWebIdentityTokenInput, optFns ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// Options configures Attestor. A zero-value Options applies documented
// defaults.
type Options struct {
	// Audience is the intended recipient of the STS web identity token (the
	// aud claim). Defaults to "urn:defakto:security:server".
	Audience []string
	// SigningAlgorithm is "RS256" or "ES384". Defaults to "RS256".
	SigningAlgorithm string
	// DurationSeconds is the token's validity window, 60-3600. Defaults to 60.
	DurationSeconds int32
	// Tags are attached to the token as STS session tags.
	Tags map[string]string
}

// Attestor attests via AWS STS GetWebIdentityToken. It satisfies
// attestation.Attestor.
type Attestor struct {
	audience  []string
	algorithm string
	duration  int32
	tags      map[string]string
	client    tokenGetter
}

// New builds an Attestor, loading an STS client from the ambient AWS
// configuration (environment variables, IRSA, EC2/ECS instance metadata).
// Pass nil for default options.
func New(ctx context.Context, opts *Options) (*Attestor, error) {
	if opts == nil {
		opts = &Options{}
	}
	a := &Attestor{
		audience:  opts.Audience,
		algorithm: opts.SigningAlgorithm,
		duration:  opts.DurationSeconds,
		tags:      opts.Tags,
	}
	if len(a.audience) == 0 {
		a.audience = []string{defaultAudience}
	}
	if a.algorithm == "" {
		a.algorithm = defaultSigningAlgorithm
	}
	if a.duration == 0 {
		a.duration = defaultDurationSeconds
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("awstoken: load AWS config: %w", err)
	}
	a.client = sts.NewFromConfig(cfg)
	return a, nil
}

func (a *Attestor) PluginName() string    { return pluginName }
func (a *Attestor) PluginVersion() string { return pluginVersion }

// CollectEvidence fetches a fresh web-identity token from STS.
func (a *Attestor) CollectEvidence(ctx context.Context) (attestation.Evidence, error) {
	input := &sts.GetWebIdentityTokenInput{
		Audience:         a.audience,
		SigningAlgorithm: aws.String(a.algorithm),
		DurationSeconds:  aws.Int32(a.duration),
	}
	for k, v := range a.tags {
		input.Tags = append(input.Tags, ststypes.Tag{Key: aws.String(k), Value: aws.String(v)})
	}

	out, err := a.client.GetWebIdentityToken(ctx, input)
	if err != nil {
		return attestation.Evidence{}, fmt.Errorf("awstoken: get web identity token: %w", err)
	}
	if out.WebIdentityToken == nil || *out.WebIdentityToken == "" {
		return attestation.Evidence{}, fmt.Errorf("awstoken: STS returned an empty web identity token")
	}
	return attestation.Evidence{Payload: []byte(*out.WebIdentityToken)}, nil
}

var _ attestation.Attestor = (*Attestor)(nil)
