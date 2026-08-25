package awstoken

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeTokenGetter struct {
	gotInput *sts.GetWebIdentityTokenInput
	output   *sts.GetWebIdentityTokenOutput
	err      error
}

func (f *fakeTokenGetter) GetWebIdentityToken(_ context.Context, params *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.gotInput = params
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

func TestAttestor_CollectEvidence_Defaults(t *testing.T) {
	fake := &fakeTokenGetter{output: &sts.GetWebIdentityTokenOutput{WebIdentityToken: strPtr("the-jwt")}}
	a := &Attestor{
		audience:  []string{defaultAudience},
		algorithm: defaultSigningAlgorithm,
		duration:  defaultDurationSeconds,
		client:    fake,
	}

	ev, err := a.CollectEvidence(context.Background())
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	if string(ev.Payload) != "the-jwt" {
		t.Errorf("Payload = %q, want %q", ev.Payload, "the-jwt")
	}
	if fake.gotInput.Audience[0] != defaultAudience {
		t.Errorf("Audience = %v, want %v", fake.gotInput.Audience, []string{defaultAudience})
	}
	if *fake.gotInput.SigningAlgorithm != defaultSigningAlgorithm {
		t.Errorf("SigningAlgorithm = %q, want %q", *fake.gotInput.SigningAlgorithm, defaultSigningAlgorithm)
	}
	if *fake.gotInput.DurationSeconds != defaultDurationSeconds {
		t.Errorf("DurationSeconds = %d, want %d", *fake.gotInput.DurationSeconds, defaultDurationSeconds)
	}
	if a.PluginName() != "aws_token" || a.PluginVersion() != "1.0" {
		t.Errorf("PluginName/PluginVersion = %q/%q", a.PluginName(), a.PluginVersion())
	}
}

func TestAttestor_CollectEvidence_Tags(t *testing.T) {
	fake := &fakeTokenGetter{output: &sts.GetWebIdentityTokenOutput{WebIdentityToken: strPtr("tok")}}
	a := &Attestor{
		audience:  []string{defaultAudience},
		algorithm: defaultSigningAlgorithm,
		duration:  defaultDurationSeconds,
		tags:      map[string]string{"environment": "production"},
		client:    fake,
	}

	if _, err := a.CollectEvidence(context.Background()); err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	if len(fake.gotInput.Tags) != 1 || *fake.gotInput.Tags[0].Key != "environment" || *fake.gotInput.Tags[0].Value != "production" {
		t.Errorf("Tags = %+v, want [{environment production}]", fake.gotInput.Tags)
	}
}

func TestAttestor_CollectEvidence_STSError(t *testing.T) {
	wantErr := errors.New("sts unavailable")
	fake := &fakeTokenGetter{err: wantErr}
	a := &Attestor{audience: []string{defaultAudience}, algorithm: defaultSigningAlgorithm, duration: defaultDurationSeconds, client: fake}

	_, err := a.CollectEvidence(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrapping %v", err, wantErr)
	}
}

func TestAttestor_CollectEvidence_EmptyToken(t *testing.T) {
	fake := &fakeTokenGetter{output: &sts.GetWebIdentityTokenOutput{WebIdentityToken: strPtr("")}}
	a := &Attestor{audience: []string{defaultAudience}, algorithm: defaultSigningAlgorithm, duration: defaultDurationSeconds, client: fake}

	if _, err := a.CollectEvidence(context.Background()); err == nil {
		t.Error("CollectEvidence() error = nil, want error for empty token")
	}
}

func strPtr(s string) *string { return &s }

func TestNew_WithFakeClient(t *testing.T) {
	fake := &fakeTokenGetter{output: &sts.GetWebIdentityTokenOutput{WebIdentityToken: strPtr("new-token")}}
	opts := &Options{Client: fake}

	a, err := New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify defaults were applied
	if len(a.audience) != 1 || a.audience[0] != defaultAudience {
		t.Errorf("audience = %v, want [%s]", a.audience, defaultAudience)
	}
	if a.algorithm != defaultSigningAlgorithm {
		t.Errorf("algorithm = %q, want %q", a.algorithm, defaultSigningAlgorithm)
	}
	if a.duration != defaultDurationSeconds {
		t.Errorf("duration = %d, want %d", a.duration, defaultDurationSeconds)
	}

	// Verify the fake client was wired in and works
	ev, err := a.CollectEvidence(context.Background())
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	if string(ev.Payload) != "new-token" {
		t.Errorf("Payload = %q, want %q", ev.Payload, "new-token")
	}
}

func TestNew_WithCustomOptions(t *testing.T) {
	fake := &fakeTokenGetter{output: &sts.GetWebIdentityTokenOutput{WebIdentityToken: strPtr("custom-token")}}
	opts := &Options{
		Audience:         []string{"custom-aud"},
		SigningAlgorithm: "ES384",
		DurationSeconds:  300,
		Tags:             map[string]string{"env": "test"},
		Client:           fake,
	}

	a, err := New(context.Background(), opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Verify custom options were applied
	if len(a.audience) != 1 || a.audience[0] != "custom-aud" {
		t.Errorf("audience = %v, want [custom-aud]", a.audience)
	}
	if a.algorithm != "ES384" {
		t.Errorf("algorithm = %q, want %q", a.algorithm, "ES384")
	}
	if a.duration != 300 {
		t.Errorf("duration = %d, want %d", a.duration, 300)
	}

	// Verify CollectEvidence uses the custom options
	if _, err := a.CollectEvidence(context.Background()); err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	if fake.gotInput.Audience[0] != "custom-aud" {
		t.Errorf("Audience sent to STS = %v, want [custom-aud]", fake.gotInput.Audience)
	}
	if *fake.gotInput.SigningAlgorithm != "ES384" {
		t.Errorf("SigningAlgorithm sent to STS = %q, want %q", *fake.gotInput.SigningAlgorithm, "ES384")
	}
	if *fake.gotInput.DurationSeconds != 300 {
		t.Errorf("DurationSeconds sent to STS = %d, want %d", *fake.gotInput.DurationSeconds, 300)
	}
}
