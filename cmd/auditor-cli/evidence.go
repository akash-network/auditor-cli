package main

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"
)

type EvidenceDocument struct {
	SchemaVersion         string              `json:"schema_version"`
	ChainID               string              `json:"chain_id"`
	Provider              string              `json:"provider"`
	Auditor               string              `json:"auditor"`
	AuditEscrowID         string              `json:"audit_escrow_id"`
	TargetTier            string              `json:"target_tier"`
	AttestedTier          string              `json:"attested_tier"`
	AttestedCapabilities  []string            `json:"attested_capabilities"`
	CollectedAt           string              `json:"collected_at"`
	BlockHeight           string              `json:"block_height"`
	SnapshotHash          string              `json:"snapshot_hash"`
	ChallengeSnapshotHash string              `json:"challenge_snapshot_hash"`
	InventoryNonce        string              `json:"inventory_nonce"`
	Software              SoftwareEvidence    `json:"software"`
	NetworkBaseline       NetworkBaseline     `json:"network_baseline"`
	SustainedValidation   SustainedValidation `json:"sustained_validation"`
	Checks                []EvidenceCheck     `json:"checks"`
	FaultContext          FaultContext        `json:"fault_context"`
}

type SoftwareEvidence struct {
	Version            string `json:"version"`
	BinaryHash         string `json:"binary_hash"`
	ArtifactRef        string `json:"artifact_ref,omitempty"`
	Signature          string `json:"signature,omitempty"`
	SignatureRef       string `json:"signature_ref,omitempty"`
	SignatureType      string `json:"signature_type,omitempty"`
	PublicKeyRef       string `json:"public_key_ref,omitempty"`
	VerificationStatus string `json:"verification_status"`
}

type NetworkBaseline struct {
	MBPSDown     int     `json:"mbps_down"`
	MBPSUp       int     `json:"mbps_up"`
	LatencyMSP95 float64 `json:"latency_ms_p95"`
	ProofRef     string  `json:"proof_ref"`
}

type SustainedValidation struct {
	BaselineID    string `json:"baseline_id"`
	Window        string `json:"window"`
	LastCheckedAt string `json:"last_checked_at"`
	Status        string `json:"status"`
	ProofRef      string `json:"proof_ref"`
}

type EvidenceCheck struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	ProofRef   string         `json:"proof_ref"`
	ObservedAt string         `json:"observed_at,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type FaultContext struct {
	FaultAttribution string `json:"fault_attribution"`
	Reason           string `json:"reason"`
}

func buildEvidence(cfg collectConfig, committed *verifiedSnapshot, challenge *verifiedSnapshot, chainFacts *chainFactsResult, collectedAt time.Time, checks []EvidenceCheck) EvidenceDocument {
	snapshotRef := sha256Ref(committed.PayloadHash)
	challengeRef := sha256Ref(challenge.PayloadHash)
	resourceSummary := committed.Payload.GetResourceSummary()
	softwareHash := cfg.softwareBinaryHash
	softwareStatus := "observed_only"
	if softwareHash == "" {
		softwareStatus = "unsigned_binary"
	}
	softwareSignature := resourceSummary.GetSoftwareSignature()
	softwareSignatureType := ""
	if len(softwareSignature) != 0 {
		softwareSignatureType = "raw_detached"
	}

	return EvidenceDocument{
		SchemaVersion:         evidenceSchema,
		ChainID:               committed.Payload.GetChainID(),
		Provider:              committed.Provider,
		Auditor:               cfg.auditor,
		AuditEscrowID:         cfg.auditEscrowID,
		TargetTier:            cfg.targetTier,
		AttestedTier:          cfg.attestedTier,
		AttestedCapabilities:  append([]string(nil), cfg.attestedCapabilities...),
		CollectedAt:           collectedAt.Format(time.RFC3339Nano),
		BlockHeight:           chainFacts.BlockHeight,
		SnapshotHash:          snapshotRef,
		ChallengeSnapshotHash: challengeRef,
		InventoryNonce:        base64.StdEncoding.EncodeToString(challenge.Payload.GetNonce()),
		Software: SoftwareEvidence{
			Version:            resourceSummary.GetSoftwareVersion(),
			BinaryHash:         softwareHash,
			Signature:          base64.StdEncoding.EncodeToString(softwareSignature),
			SignatureType:      softwareSignatureType,
			VerificationStatus: softwareStatus,
		},
		NetworkBaseline: NetworkBaseline{
			ProofRef: snapshotRef,
		},
		SustainedValidation: SustainedValidation{
			BaselineID:    snapshotRef,
			Window:        "attestation_ttl",
			LastCheckedAt: collectedAt.Format(time.RFC3339Nano),
			Status:        "not_evaluated",
			ProofRef:      snapshotRef,
		},
		Checks: checks,
		FaultContext: FaultContext{
			FaultAttribution: "unspecified",
			Reason:           "unspecified",
		},
	}
}

func evidenceChecks(committed *verifiedSnapshot, challenge *verifiedSnapshot, chainFacts *chainFactsResult) []EvidenceCheck {
	if chainFacts == nil {
		chainFacts = &chainFactsResult{}
	}

	observedAt := challenge.Payload.GetTimestamp().UTC().Format(time.RFC3339Nano)
	snapshotRef := sha256Ref(committed.PayloadHash)
	challengeRef := sha256Ref(challenge.PayloadHash)
	resourceSummary := committed.Payload.GetResourceSummary()
	signatureStatus := "pass"
	if !committed.SignatureVerified || !challenge.SignatureVerified {
		signatureStatus = "not_evaluated"
	}

	checks := []EvidenceCheck{
		{
			Name:       "provider_registered_on_chain",
			Status:     statusFromObserved(chainFacts.ProviderRegistered),
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
		},
		{
			Name:       "provider_bond_sufficient",
			Status:     statusFromOptionalPass(chainFacts.ProviderBondObserved, chainFacts.ProviderBondSufficient),
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
		},
		{
			Name:       "provider_age_sufficient",
			Status:     "not_evaluated",
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
		},
		{
			Name:       "lease_completion_sufficient",
			Status:     "not_evaluated",
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
			Details:    leaseStatsDetails(chainFacts),
		},
		{
			Name:       "no_recent_slashing",
			Status:     "not_evaluated",
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
		},
		{
			Name:       "snapshot_not_suspended",
			Status:     statusFromOptionalPass(chainFacts.SnapshotObserved, !chainFacts.SnapshotSuspended),
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
		},
		{
			Name:       "snapshot_hash_matches_chain",
			Status:     statusFromOptionalPass(chainFacts.SnapshotObserved, chainSnapshotMatchesPayload(chainFacts, committed.PayloadHash)),
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
		},
		{
			Name:       "inventory_nonce_matches",
			Status:     "pass",
			ProofRef:   challengeRef,
			ObservedAt: observedAt,
			Details: map[string]any{
				"nonce_length": len(challenge.Payload.GetNonce()),
			},
		},
		{
			Name:       "inventory_signature_valid",
			Status:     signatureStatus,
			ProofRef:   challengeRef,
			ObservedAt: observedAt,
			Details: map[string]any{
				"provider_pubkey_address":      chainFacts.ProviderPubKeyAddress,
				"committed_signature_verified": committed.SignatureVerified,
				"challenge_signature_verified": challenge.SignatureVerified,
			},
		},
		{
			Name:       "software_identity_recorded",
			Status:     "pass",
			ProofRef:   snapshotRef,
			ObservedAt: observedAt,
			Details: map[string]any{
				"software_version": resourceSummary.GetSoftwareVersion(),
			},
		},
	}

	return checks
}

func leaseStatsDetails(chainFacts *chainFactsResult) map[string]any {
	if chainFacts == nil || !chainFacts.LeaseStatsObserved {
		return nil
	}

	return map[string]any{
		"total_leases":            chainFacts.TotalLeases,
		"completed_leases":        chainFacts.CompletedLeases,
		"provider_faulted_leases": chainFacts.ProviderFaultedLeases,
	}
}

func statusFromObserved(ok bool) string {
	if ok {
		return "pass"
	}

	return "fail"
}

func statusFromOptionalPass(observed, ok bool) string {
	if !observed {
		return "not_evaluated"
	}
	if ok {
		return "pass"
	}

	return "fail"
}

func marshalEvidenceCanonical(evidence EvidenceDocument) ([]byte, string, error) {
	if evidence.AttestedCapabilities == nil {
		evidence.AttestedCapabilities = []string{}
	} else {
		evidence.AttestedCapabilities = append([]string(nil), evidence.AttestedCapabilities...)
		sort.Strings(evidence.AttestedCapabilities)
	}

	raw, err := json.Marshal(evidence)
	if err != nil {
		return nil, "", err
	}
	if err := validateEvidenceBytes(raw); err != nil {
		return nil, "", err
	}

	return raw, sha256Ref(sha256Bytes(raw)), nil
}
