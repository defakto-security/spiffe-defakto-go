package attestingworkloadapi

import (
	"errors"
	"io"
	"testing"
)

func TestError_Is_MatchesSameCode(t *testing.T) {
	err := newError(CodeNoAttestorsConfigured, "custom message", nil)
	if !errors.Is(err, ErrNoAttestorsConfigured) {
		t.Errorf("errors.Is(err, ErrNoAttestorsConfigured) = false, want true")
	}
}

func TestError_Is_DoesNotMatchDifferentCode(t *testing.T) {
	err := newError(CodeNoAttestorsConfigured, "custom message", nil)
	if errors.Is(err, ErrBundleNotFound) {
		t.Errorf("errors.Is(err, ErrBundleNotFound) = true, want false")
	}
}

func TestError_Unwrap_SurfacesCause(t *testing.T) {
	err := newError(CodeAttestationFailed, "wrapped", io.EOF)
	if !errors.Is(err, io.EOF) {
		t.Errorf("errors.Is(err, io.EOF) = false, want true")
	}
}

func TestError_Error_IncludesCause(t *testing.T) {
	err := newError(CodeAttestationFailed, "wrapped", io.EOF)
	got := err.Error()
	want := "wrapped: EOF"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
