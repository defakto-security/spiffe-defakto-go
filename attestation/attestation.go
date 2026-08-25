// Package attestation defines the plugin contract every Defakto serverless
// attestation method implements: a proof payload, and the interface that
// collects it from the workload's environment.
//
// Built-in attestors for AWS, GCP, and Azure live in the attestors/*
// subpackages. There is no built-in attestor for the custom_jwt or extension
// serverless attestation methods — implement Attestor directly, since the
// proof format for those is defined by your issuer or webhook, not by
// Defakto.
package attestation

import "context"

// Evidence is the proof payload produced by a single Attestor. When more
// than one Attestor is configured, their evidence is combined and sent
// together in a single attestation request.
type Evidence struct {
	// Payload is the raw proof bytes — e.g. a signed JWT or an instance
	// identity document.
	Payload []byte
}

// Attestor collects attestation evidence from the current workload's
// environment.
type Attestor interface {
	// PluginName identifies the attestation method (e.g. "aws_token"),
	// matched against the "type" configured in the server's attestation
	// policy.
	PluginName() string
	// PluginVersion is the attestor's proof-format version. The server
	// rejects evidence from an unsupported version.
	PluginVersion() string
	// CollectEvidence produces evidence for a single attestation handshake.
	// May be called multiple times: once per request, and again on every
	// SVID rotation.
	CollectEvidence(ctx context.Context) (Evidence, error)
}
