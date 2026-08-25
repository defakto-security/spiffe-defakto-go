package gcpiit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAttestor_CollectEvidence(t *testing.T) {
	var gotPath, gotHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		gotHeader = r.Header.Get("Metadata-Flavor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("the-iit-jwt"))
	}))
	defer server.Close()

	a := New(&Options{MetadataHost: server.Listener.Addr().String(), HTTPClient: server.Client()})
	// New() prefixes with "http://", but httptest already gives a bare
	// host:port — CollectEvidence must build the URL the same way
	// regardless, so point MetadataHost at the test server's host:port.

	ev, err := a.CollectEvidence(context.Background())
	if err != nil {
		t.Fatalf("CollectEvidence() error = %v", err)
	}

	var payload map[string]string
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if payload["token"] != "the-iit-jwt" {
		t.Errorf("payload[token] = %q, want %q", payload["token"], "the-iit-jwt")
	}
	if gotHeader != "Google" {
		t.Errorf("Metadata-Flavor header = %q, want %q", gotHeader, "Google")
	}
	wantPath := "/computeMetadata/v1/instance/service-accounts/default/identity?audience=urn%3Adefakto%3Asecurity%3Aserver&format=full"
	if gotPath != wantPath {
		t.Errorf("request path = %q, want %q", gotPath, wantPath)
	}
}

func TestAttestor_CollectEvidence_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	a := New(&Options{MetadataHost: server.Listener.Addr().String(), HTTPClient: server.Client()})
	if _, err := a.CollectEvidence(context.Background()); err == nil {
		t.Error("CollectEvidence() error = nil, want error for 403 status")
	}
}

func TestAttestor_PluginNameAndVersion(t *testing.T) {
	a := New(nil)
	if a.PluginName() != "gcp_iit" || a.PluginVersion() != "1.0" {
		t.Errorf("PluginName/PluginVersion = %q/%q", a.PluginName(), a.PluginVersion())
	}
}
