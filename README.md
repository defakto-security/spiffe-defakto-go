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
`workloadapi.X509Source` — with no adapter code. `client.JWTSource()`
similarly returns a `*JWTSource` satisfying `jwtbundle.Source`, plus its own
`FetchJWTSVID` method; every JWT call re-attests live, there is no cache.

## Attestors

| Package                | `PluginName()` | `PluginVersion()` | Cloud | Defaults |
|------------------------|----------------|--------------------|-------|----------|
| `attestors/awstoken`   | `aws_token`    | `1.0`              | AWS (STS `GetWebIdentityToken`) | audience `urn:defakto:security:server`, algorithm `RS256`, duration `60s` |
| `attestors/gcpiit`     | `gcp_iit`      | `1.0`              | GCP (Instance Identity Token, metadata service) | host `metadata.google.internal`, service account `default`, audience `urn:defakto:security:server` |
| `attestors/azuremsi`   | `azure_msi`    | `1.0`              | Azure (Managed Identity) | audience `api://AzureADTokenExchange`, system-assigned identity |

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

## Development

- `mise run build` — `go build ./...`
- `mise run test` — `go test ./... -race -cover`
- `mise run lint` — `golangci-lint run ./...`
- `mise run check` — all three
- `mise run gen-protos` — regenerate gRPC stubs after editing
  `protos/alpha/serverlessapi/api.proto` (see `CLAUDE.md` for the vendoring
  process)
