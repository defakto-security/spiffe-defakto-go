# CLAUDE.md

This repo is the Go SDK for SPIFFE workload identity and Defakto attestation
— the Go sibling of `spiffe-defakto-python` and `spiffe-defakto-ts`.

## What belongs here vs. upstream

Go is in a different position than Python and TS: **`go-spiffe/v2` already
exists**, and is already a dependency throughout the Defakto/SPIRL Go
codebase. Python and TS had to build their own SVID types, SPIFFE ID
parsing, and local Workload API client because no equivalent library existed
in those ecosystems. That gap doesn't exist in Go, so this SDK's job is
narrower — and staying narrow is the point, not an accident.

Concrete rules:

1. **Reuse `go-spiffe/v2` types directly.** `x509svid.SVID`, `jwtsvid.SVID`,
   `spiffeid.ID`, `spiffeid.TrustDomain`, `x509bundle.Bundle`,
   `jwtbundle.Bundle`. Never define parallel structs for these.
2. **Satisfy `go-spiffe`'s interfaces, don't wrap them.** Anything that acts
   as a source of SVIDs or bundles must implement `x509svid.Source`,
   `x509bundle.Source`, or `jwtbundle.Source` directly, so it's a drop-in
   wherever a consumer is typed against those interfaces — no adapter shim.
   `attestingworkloadapi.X509Source` does exactly this; a consumer typed
   against `x509svid.Source`/`x509bundle.Source` (e.g. `workloadapi.X509Source`'s
   own interface) can take either one with no code change.
3. **The local Workload API (UDS, the standard `FetchX509SVID`/
   `FetchJWTSVID` over the spec socket) is out of scope here, permanently.**
   `go-spiffe/v2/workloadapi` already implements it, fully spec-conformant.
   Do not add a competing implementation.
4. **What belongs in this repo:** Defakto's proprietary serverless
   attestation gRPC protocol (`attestingworkloadapi`, vendoring
   `alpha.serverlessapi` — not part of the SPIFFE Workload API spec), and
   the cloud-metadata attestors that produce evidence for it (`attestors/*`
   — AWS STS web-identity tokens, GCP IIT, Azure MSI). These are
   Defakto-proprietary transport and cloud-vendor integrations; no SPIFFE
   upstream would take them.
5. **The upstream-worthiness test for any new feature considered for this
   repo:** would the SPIFFE community accept a PR for this in `go-spiffe`?
   Standard Workload API behavior → it belongs upstream, use it from there.
   Anything tied to Defakto's control plane, a proprietary protocol, or a
   cloud-vendor-specific credential mechanism → belongs here.

This also means: no wiring of this SDK into any downstream consumer (e.g.
`security-domain-proxy`) happens in this repo. This is a library only —
adopting it elsewhere is a separate task in that consumer's own repo.

## Package layout

- `attestation/` — the `Attestor` plugin contract (interface + `Evidence`
  type). No built-in implementation of `custom_jwt` or `extension` — every
  SDK (Python, TS, Go) leaves those to the caller, since the proof format is
  issuer/webhook-defined, not Defakto-defined.
- `attestors/{awstoken,gcpiit,azuremsi}/` — one attestor per cloud, each its
  own subpackage (like `go-spiffe`'s own `svid/x509svid`,
  `bundle/x509bundle` split) so importing one doesn't pull in another
  cloud's SDK dependency graph.
- `attestingworkloadapi/` — the serverless attestation gRPC client:
  `Client`, `X509Source` (satisfies `x509svid.Source` + `x509bundle.Source`,
  background-refreshes like `workloadapi.X509Source` does), `JWTSource`
  (satisfies `jwtsvid.Source` + `jwtbundle.Source`; `FetchJWTSVID`
  re-attests per call — same as `workloadapi.JWTSource.FetchJWTSVID` — while
  `GetJWTBundleForTrustDomain` caches the bundle map for 60s).
  - `attestingworkloadapi/internal/serverlessapi/` — generated gRPC stubs,
    regenerate with `mise run gen-protos` after updating
    `protos/alpha/serverlessapi/api.proto`.

Note: `attestingworkloadapi.New` requires attestors via `WithAttestors` —
there is deliberately no env-var auto-selection of attestors by name (unlike
Python/TS's `DEFAKTO_ATTESTORS`). Go's static import model means naming an
attestor by string would still require every consumer binary to compile in
the AWS, GCP, and Azure SDKs regardless of which cloud it targets, so the
caller wires attestors explicitly instead. This is a deliberate Go-idiom
difference from the Python/TS SDKs, not a gap to close.

## Updating the vendored proto

`protos/alpha/serverlessapi/api.proto` is a vendored copy of
`spirl/spirl:protos/agent/alpha/serverlessapi/api.proto`. There is no
automated sync (same as the Python and TS SDKs, which vendor the same file
the same way) — when the upstream proto changes:

1. Copy the updated `api.proto` from `spirl/spirl` over
   `protos/alpha/serverlessapi/api.proto`.
2. Keep the `go_package` option pointed at
   `github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi`
   (the upstream file points at `spirl/spirl`'s own Go module — don't copy
   that line verbatim).
3. Run `mise run gen-protos`.
4. Update any code in `attestingworkloadapi/` that depended on removed or
   renamed fields, and run `mise run check`.
