package azuremsi

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type fakeCredential struct {
	gotScopes []string
	token     azcore.AccessToken
	err       error
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.gotScopes = opts.Scopes
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return f.token, nil
}

func TestAttestor_CollectEvidence_DefaultAudience(t *testing.T) {
	fake := &fakeCredential{token: azcore.AccessToken{Token: "the-token", ExpiresOn: time.Now().Add(time.Hour)}}
	a := &Attestor{audience: defaultAudience, credential: fake}

	ev, err := a.CollectEvidence(context.Background())
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if payload["token"] != "the-token" {
		t.Errorf("payload[token] = %q, want %q", payload["token"], "the-token")
	}
	if len(fake.gotScopes) != 1 || fake.gotScopes[0] != defaultAudience {
		t.Errorf("scopes = %v, want [%s]", fake.gotScopes, defaultAudience)
	}
}

func TestAttestor_CollectEvidence_CustomAudienceAppendsDefaultScope(t *testing.T) {
	fake := &fakeCredential{token: azcore.AccessToken{Token: "tok"}}
	a := &Attestor{audience: "api://my-app", credential: fake}

	if _, err := a.CollectEvidence(context.Background()); err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}
	want := "api://my-app/.default"
	if len(fake.gotScopes) != 1 || fake.gotScopes[0] != want {
		t.Errorf("scopes = %v, want [%s]", fake.gotScopes, want)
	}
}

func TestAttestor_CollectEvidence_CredentialError(t *testing.T) {
	wantErr := errors.New("imds unreachable")
	a := &Attestor{audience: defaultAudience, credential: &fakeCredential{err: wantErr}}

	_, err := a.CollectEvidence(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrapping %v", err, wantErr)
	}
}

func TestNew_RejectsMultipleIdentitySelectors(t *testing.T) {
	_, err := New(&Options{ClientID: "a", PrincipalID: "b"})
	if err == nil {
		t.Error("New() error = nil, want error for multiple identity selectors")
	}
}

func TestAttestor_PluginNameAndVersion(t *testing.T) {
	a := &Attestor{audience: defaultAudience, credential: &fakeCredential{}}
	if a.PluginName() != "azure_msi" || a.PluginVersion() != "1.0" {
		t.Errorf("PluginName/PluginVersion = %q/%q", a.PluginName(), a.PluginVersion())
	}
}
