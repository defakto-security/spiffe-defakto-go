package attestingworkloadapi

// Code is a stable identifier for an error condition raised by this
// package, so callers can branch on kind (via errors.Is against the
// sentinel Err* variables) rather than string matching.
type Code string

const (
	CodeServerAddressNotConfigured Code = "SERVER_ADDRESS_NOT_CONFIGURED"
	CodeInvalidServerAddress       Code = "INVALID_SERVER_ADDRESS"
	CodeInvalidTrustDomain         Code = "INVALID_TRUST_DOMAIN"
	CodeNoAttestorsConfigured      Code = "NO_ATTESTORS_CONFIGURED"
	CodeAttestorCollectionFailed   Code = "ATTESTOR_COLLECTION_FAILED"
	CodeAttestationFailed          Code = "ATTESTATION_FAILED"
	CodeBundleNotFound             Code = "BUNDLE_NOT_FOUND"
	CodeDialFailed                 Code = "DIAL_FAILED"
)

// Error is the error type returned by this package's public API.
type Error struct {
	Code    Code
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap makes errors.Is/errors.As see through to Cause.
func (e *Error) Unwrap() error { return e.Cause }

// Is reports whether target is a sentinel *Error with the same Code, so
// callers can write errors.Is(err, attestingworkloadapi.ErrBundleNotFound)
// regardless of the specific message or wrapped cause.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func newError(code Code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: cause}
}

var (
	ErrServerAddressNotConfigured = &Error{Code: CodeServerAddressNotConfigured, Message: "no server address configured"}
	ErrInvalidServerAddress       = &Error{Code: CodeInvalidServerAddress, Message: "invalid server address"}
	ErrInvalidTrustDomain         = &Error{Code: CodeInvalidTrustDomain, Message: "invalid trust domain id"}
	ErrNoAttestorsConfigured      = &Error{Code: CodeNoAttestorsConfigured, Message: "no attestors configured"}
	ErrAttestorCollectionFailed   = &Error{Code: CodeAttestorCollectionFailed, Message: "one or more attestors failed to collect evidence"}
	ErrAttestationFailed          = &Error{Code: CodeAttestationFailed, Message: "attestation failed"}
	ErrBundleNotFound             = &Error{Code: CodeBundleNotFound, Message: "bundle not found"}
	ErrDialFailed                 = &Error{Code: CodeDialFailed, Message: "failed to dial the attestation server"}
)
