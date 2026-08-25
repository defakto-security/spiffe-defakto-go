package attestation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/defakto-security/spiffe-defakto-go/attestation"
)

type fakeAttestor struct {
	name, version string
	evidence      attestation.Evidence
	err           error
}

func (f *fakeAttestor) PluginName() string    { return f.name }
func (f *fakeAttestor) PluginVersion() string { return f.version }
func (f *fakeAttestor) CollectEvidence(context.Context) (attestation.Evidence, error) {
	return f.evidence, f.err
}

var _ attestation.Attestor = (*fakeAttestor)(nil)

func TestAttestor_CollectEvidence(t *testing.T) {
	want := attestation.Evidence{Payload: []byte("token-bytes")}
	a := &fakeAttestor{name: "fake", version: "1.0", evidence: want}

	got, err := a.CollectEvidence(context.Background())
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v, want nil", err)
	}
	if string(got.Payload) != string(want.Payload) {
		t.Errorf("Payload = %q, want %q", got.Payload, want.Payload)
	}
	if a.PluginName() != "fake" || a.PluginVersion() != "1.0" {
		t.Errorf("PluginName/PluginVersion = %q/%q, want fake/1.0", a.PluginName(), a.PluginVersion())
	}
}

func TestAttestor_CollectEvidence_Error(t *testing.T) {
	wantErr := errors.New("boom")
	a := &fakeAttestor{name: "fake", version: "1.0", err: wantErr}

	_, err := a.CollectEvidence(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
}
