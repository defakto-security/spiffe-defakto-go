# spiffe-defakto-go

Go SDK for SPIFFE workload identity and Defakto attestation.

This SDK covers what `go-spiffe/v2` does not: Defakto's serverless
attestation API, for workloads with no SPIFFE Workload API Unix domain
socket (AWS Lambda, GCP Cloud Run, Azure Functions, restricted Kubernetes,
etc.). For the standard local Workload API (a socket is available), use
[`go-spiffe/v2`](https://github.com/spiffe/go-spiffe) directly — this SDK
does not duplicate it.

## Install

```bash
go get github.com/defakto-security/spiffe-defakto-go
```

## Usage

```go
package main

import (
	"context"
	"log"

	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi"
	"github.com/defakto-security/spiffe-defakto-go/attestors/awstoken"
)

func main() {
	ctx := context.Background()

	attestor, err := awstoken.New(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	client, err := attestingworkloadapi.New(ctx,
		attestingworkloadapi.WithAttestors(attestor),
		attestingworkloadapi.WithTrustDomainID("td-m36ckrte4e"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	src, err := client.X509Source(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = src.Close() }()

	svid, err := src.GetX509SVID()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("SPIFFE ID:", svid.ID)
}
```

`*attestingworkloadapi.X509Source` satisfies `go-spiffe/v2`'s
`x509svid.Source` and `x509bundle.Source` interfaces, so it's usable
anywhere a consumer is typed against those — e.g. in place of
`workloadapi.X509Source` — with no adapter code. Call `client.X509Source(ctx)`
once and hold onto the result; it refreshes itself in the background and
must be `Close()`d when you're done with it (independently of `client.Close()`
— closing the `Client` does not stop a source's background refresh loop, it
just makes its next refresh attempt fail against a dead connection, which the
source's own retry/backoff will keep retrying until you call `src.Close()`).
If a background refresh is failing, `GetX509SVID()` keeps returning the last
SVID it has — which may be past its expiry — with a `nil` error; call
`LastRefreshError()` to check whether the source is actually still healthy.
`GetX509BundleForTrustDomain` only returns bundles present in the most recent
`FetchX509SVID` response (your own trust domain plus any federated bundles
the server included there) — it does not make a separate live call, so a
federated trust domain the server doesn't include in that response returns
`ErrBundleNotFound` regardless of whether that bundle exists server-side.

`client.JWTSource()` returns a `*JWTSource` satisfying `jwtsvid.Source` and
`jwtbundle.Source`. **Call it once and hold the result** — each call to
`client.JWTSource()` constructs a new `*JWTSource` with its own, empty bundle
cache, so calling it per-request (e.g. inside an HTTP handler) defeats the
caching described below and re-attests on every single call. Every
`FetchJWTSVID` call re-attests live (the audience varies per call, so there
is nothing to cache); `GetJWTBundleForTrustDomain` caches the bundle map for
60 seconds *on that `*JWTSource` instance*, since `jwtsvid.ParseAndValidate`
calls it once per token validation and an uncached live call there would let
a flood of inbound tokens trigger a matching flood of attestation calls.

## Attestors

| Package                | Constructor | `PluginName()` | `PluginVersion()` | Cloud | Defaults |
|------------------------|-------------|----------------|--------------------|-------|----------|
| `attestors/awstoken`   | `New(ctx context.Context, opts *Options) (*Attestor, error)` | `aws_token`    | `1.0`              | AWS (STS `GetWebIdentityToken`) | audience `urn:defakto:security:server`, algorithm `RS256`, duration `60s` |
| `attestors/gcpiit`     | `New(opts *Options) *Attestor` (no `ctx`, no error) | `gcp_iit`      | `1.0`              | GCP (Instance Identity Token, metadata service) | host `metadata.google.internal`, service account `default`, audience `urn:defakto:security:server` |
| `attestors/azuremsi`   | `New(opts *Options) (*Attestor, error)` (no `ctx`) | `azure_msi`    | `1.0`              | Azure (Managed Identity) | audience `api://AzureADTokenExchange`, system-assigned identity |

The three constructors are intentionally not uniform: `awstoken.New` takes a
`ctx` because it calls `config.LoadDefaultConfig` (which can make network
calls to resolve credentials); `gcpiit.New` never fails, since it just builds
an HTTP request template; `azuremsi.New` can fail (multiple identity
selectors set) but doesn't need a `ctx`, since `azidentity.NewManagedIdentityCredential`
doesn't call out to IMDS until a token is actually requested. Pass `nil` for
`opts` on any of them to accept all documented defaults.

For the `custom_jwt` or `extension` serverless attestation methods, there is
no built-in attestor in any Defakto SDK — implement the `attestation.Attestor`
interface directly:

```go
type myAttestor struct{}

func (myAttestor) PluginName() string    { return "custom_jwt" }
func (myAttestor) PluginVersion() string { return "1.0" }
func (myAttestor) CollectEvidence(ctx context.Context) (attestation.Evidence, error) {
	token, err := os.ReadFile("/var/run/secrets/tokens/workload-jwt")
	if err != nil {
		return attestation.Evidence{}, err
	}
	return attestation.Evidence{Payload: token}, nil
}
```

## Configuration

`attestingworkloadapi.New` resolves its gRPC target in this order:

1. `WithTarget` — bypasses everything below entirely; mainly for tests and
   custom gRPC resolver schemes.
2. `WithServerAddress` / `DEFAKTO_SERVER_ADDRESS` — a self-hosted Trust
   Domain Server (`host` or `host:port`, default port 443).
3. `WithTrustDomainID` / `DEFAKTO_TRUST_DOMAIN_ID` — a Defakto-hosted trust
   domain ID, resolved to `<id>.agent.spirl.com:443`.

If none of the above is set, `New` returns `ErrServerAddressNotConfigured`.
An explicit `With*` option always wins over its environment variable.

`WithAttestors` is required — `New` returns `ErrNoAttestorsConfigured`
without it. Unlike the Python/TS SDKs, this SDK does not auto-select
attestors from a `DEFAKTO_ATTESTORS` env var by name: Go's static import
model would force every consumer's binary to compile in the AWS, Azure, and
GCP dependency graphs regardless of which cloud it actually targets, so
attestors are always wired explicitly by the caller.

## Errors

`attestingworkloadapi` returns errors as `*attestingworkloadapi.Error`
(`Code`, `Message`, and a wrapped `Cause`), matched by `Code` rather than by
message text or pointer identity — so `errors.Is(err, SentinelErr)` works
regardless of the specific message or wrapped cause:

```go
client, err := attestingworkloadapi.New(ctx, attestingworkloadapi.WithAttestors(attestor))
if errors.Is(err, attestingworkloadapi.ErrServerAddressNotConfigured) {
	// neither WithServerAddress/DEFAKTO_SERVER_ADDRESS nor
	// WithTrustDomainID/DEFAKTO_TRUST_DOMAIN_ID nor WithTarget was set
}
```

The sentinels: `ErrServerAddressNotConfigured`, `ErrInvalidServerAddress`,
`ErrInvalidTrustDomain`, `ErrNoAttestorsConfigured` (also returned for a nil
attestor passed to `WithAttestors`), `ErrAttestorCollectionFailed`,
`ErrAttestationFailed`, `ErrBundleNotFound`, `ErrDialFailed`. `errors.Is`
also unwraps to the underlying cause (e.g. the gRPC status or attestor
error), so `errors.As` against a more specific error type still works
through an `attestingworkloadapi.Error`.

## Development

- `mise run build` — `go build ./...`
- `mise run test` — `go test ./... -race -cover`
- `mise run lint` — `golangci-lint run ./...`
- `mise run check` — all three
- `mise run gen-protos` — regenerate gRPC stubs after editing
  `protos/alpha/serverlessapi/api.proto` (see `CLAUDE.md` for the vendoring
  process)
