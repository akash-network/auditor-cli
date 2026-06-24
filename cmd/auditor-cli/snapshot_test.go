package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/resource"

	inventoryv1 "pkg.akt.dev/go/inventory/v1"
)

func TestVerifySnapshotEnvelopeAndSignature(t *testing.T) {
	priv := secp256k1.GenPrivKey()
	provider := sdk.AccAddress(priv.PubKey().Address()).String()
	nonce := []byte("12345678901234567890123456789012")

	payloadBytes := mustSnapshotPayload(t, provider, nonce)
	signature, err := priv.Sign(payloadBytes)
	require.NoError(t, err)

	resp := &inventoryv1.GetInventorySnapshotResponse{
		SnapshotPayload: payloadBytes,
		Signature:       signature,
		Provider:        provider,
	}

	verified, err := verifySnapshotEnvelope(resp, nonce)
	require.NoError(t, err)
	require.Equal(t, provider, verified.Provider)
	require.Equal(t, nonce, verified.Payload.GetNonce())

	err = verifyProviderSignature(verified.PayloadBytes, resp.GetSignature(), priv.PubKey(), provider)
	require.NoError(t, err)
}

func TestSnapshotPayloadHashIncludesChallengeFields(t *testing.T) {
	first, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		Nonce:         []byte("12345678901234567890123456789012"),
		Timestamp:     time.Unix(1, 0).UTC(),
		ResourceSummary: inventoryv1.SnapshotResourceSummary{
			TotalVCPUs: 32,
		},
	})
	require.NoError(t, err)

	second, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		Nonce:         []byte("21098765432109876543210987654321"),
		Timestamp:     time.Unix(2, 0).UTC(),
		ResourceSummary: inventoryv1.SnapshotResourceSummary{
			TotalVCPUs: 32,
		},
	})
	require.NoError(t, err)

	require.NotEqual(t, snapshotPayloadHash(first), snapshotPayloadHash(second))
}

func TestSnapshotPayloadHashIncludesPayloadFields(t *testing.T) {
	first, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		Nonce:         []byte("12345678901234567890123456789012"),
		Timestamp:     time.Unix(1, 0).UTC(),
		Cluster: inventoryv1.Cluster{
			Nodes: []inventoryv1.Node{{
				Name: "node-1",
				Resources: inventoryv1.NodeResources{
					CPU: inventoryv1.CPU{Quantity: inventoryv1.ResourcePair{
						Allocatable: testQuantity("32"),
						Allocated:   testQuantity("1250m"),
						Capacity:    testQuantity("32"),
					}},
					Memory: inventoryv1.Memory{Quantity: inventoryv1.ResourcePair{
						Allocatable: testQuantity("128Gi"),
						Allocated:   testQuantity("708Mi"),
						Capacity:    testQuantity("128Gi"),
					}},
				},
			}},
		},
		EvidenceSections: []inventoryv1.SnapshotEvidenceSection{{
			Name:    "test",
			Payload: []byte("first"),
		}},
	})
	require.NoError(t, err)

	second, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		Nonce:         []byte("21098765432109876543210987654321"),
		Timestamp:     time.Unix(2, 0).UTC(),
		Cluster: inventoryv1.Cluster{
			Nodes: []inventoryv1.Node{{
				Name: "node-1",
				Resources: inventoryv1.NodeResources{
					CPU: inventoryv1.CPU{Quantity: inventoryv1.ResourcePair{
						Allocatable: testQuantity("32"),
						Allocated:   testQuantity("2500m"),
						Capacity:    testQuantity("32"),
					}},
					Memory: inventoryv1.Memory{Quantity: inventoryv1.ResourcePair{
						Allocatable: testQuantity("128Gi"),
						Allocated:   testQuantity("1Gi"),
						Capacity:    testQuantity("128Gi"),
					}},
				},
			}},
		},
		EvidenceSections: []inventoryv1.SnapshotEvidenceSection{{
			Name:    "test",
			Payload: []byte("second"),
		}},
	})
	require.NoError(t, err)

	require.NotEqual(t, snapshotPayloadHash(first), snapshotPayloadHash(second))
}

func TestSnapshotPayloadHashIncludesInventoryMaterial(t *testing.T) {
	first, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		ResourceSummary: inventoryv1.SnapshotResourceSummary{
			TotalVCPUs: 32,
		},
	})
	require.NoError(t, err)

	second, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		ResourceSummary: inventoryv1.SnapshotResourceSummary{
			TotalVCPUs: 64,
		},
	})
	require.NoError(t, err)

	require.NotEqual(t, snapshotPayloadHash(first), snapshotPayloadHash(second))
}

func TestSnapshotPayloadHashIncludesCapacityMaterial(t *testing.T) {
	first, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		Cluster: inventoryv1.Cluster{
			Nodes: []inventoryv1.Node{{
				Name: "node-1",
				Resources: inventoryv1.NodeResources{
					CPU: inventoryv1.CPU{Quantity: inventoryv1.ResourcePair{
						Allocatable: testQuantity("32"),
						Capacity:    testQuantity("32"),
					}},
				},
			}},
		},
	})
	require.NoError(t, err)

	second, err := protoMarshalDeterministic(&inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      "akash1provider",
		ChainID:       "akash-local",
		Cluster: inventoryv1.Cluster{
			Nodes: []inventoryv1.Node{{
				Name: "node-1",
				Resources: inventoryv1.NodeResources{
					CPU: inventoryv1.CPU{Quantity: inventoryv1.ResourcePair{
						Allocatable: testQuantity("64"),
						Capacity:    testQuantity("64"),
					}},
				},
			}},
		},
	})
	require.NoError(t, err)

	require.NotEqual(t, snapshotPayloadHash(first), snapshotPayloadHash(second))
}

func TestVerifySnapshotEnvelopeRejectsNonceMismatch(t *testing.T) {
	priv := secp256k1.GenPrivKey()
	provider := sdk.AccAddress(priv.PubKey().Address()).String()
	payloadBytes := mustSnapshotPayload(t, provider, []byte("12345678901234567890123456789012"))

	resp := &inventoryv1.GetInventorySnapshotResponse{
		SnapshotPayload: payloadBytes,
		Signature:       []byte("signature"),
		Provider:        provider,
	}

	_, err := verifySnapshotEnvelope(resp, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	require.ErrorContains(t, err, "snapshot nonce mismatch")
}

func TestMarshalEvidenceCanonicalIsStable(t *testing.T) {
	evidence := EvidenceDocument{
		SchemaVersion:         evidenceSchema,
		ChainID:               "akash-local",
		Provider:              "akash1provider",
		Auditor:               "akash1auditor",
		AuditEscrowID:         "7",
		TargetTier:            "L1",
		AttestedTier:          "L1",
		AttestedCapabilities:  []string{"persistent_storage"},
		CollectedAt:           "2026-05-19T00:00:00Z",
		BlockHeight:           "123",
		SnapshotHash:          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ChallengeSnapshotHash: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		InventoryNonce:        "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		Software: SoftwareEvidence{
			Version:            "test",
			BinaryHash:         "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			VerificationStatus: "observed_only",
		},
		NetworkBaseline: NetworkBaseline{
			ProofRef: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		SustainedValidation: SustainedValidation{
			BaselineID:    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Window:        "attestation_ttl",
			LastCheckedAt: "2026-05-19T00:00:00Z",
			Status:        "not_evaluated",
			ProofRef:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Checks: []EvidenceCheck{{
			Name:     "inventory_signature_valid",
			Status:   "pass",
			ProofRef: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Details: map[string]any{
				"z": true,
				"a": "first",
			},
		}},
		FaultContext: FaultContext{
			FaultAttribution: "unspecified",
			Reason:           "unspecified",
		},
	}

	first, firstHash, err := marshalEvidenceCanonical(evidence)
	require.NoError(t, err)
	second, secondHash, err := marshalEvidenceCanonical(evidence)
	require.NoError(t, err)

	require.Equal(t, string(first), string(second))
	require.Equal(t, firstHash, secondHash)
	require.True(t, strings.HasPrefix(firstHash, "sha256:"))
	require.NotContains(t, string(first), "\n")
}

func TestMarshalEvidenceCanonicalEmptyAttestedCapabilitiesIsArray(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.AttestedCapabilities = nil

	raw, _, err := marshalEvidenceCanonical(evidence)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"attested_capabilities":[]`)
	require.NotContains(t, string(raw), `"attested_capabilities":null`)
}

func TestMarshalEvidenceCanonicalSortsAttestedCapabilities(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.AttestedCapabilities = []string{"persistent_storage", "bare_metal"}

	raw, _, err := marshalEvidenceCanonical(evidence)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"attested_capabilities":["bare_metal","persistent_storage"]`)
}

func TestEvidenceSchemaArtifactIsCanonicalV1(t *testing.T) {
	var schema map[string]any
	require.NoError(t, json.Unmarshal(embeddedEvidenceSchema, &schema))
	require.Equal(t, "https://json-schema.org/draft/2020-12/schema", schema["$schema"])
	require.Equal(t, evidenceSchema, schema["$id"])
	require.Contains(t, schema, "$defs")
	require.NotContains(t, schema, "definitions")
}

func TestMarshalEvidenceCanonicalRejectsSchemaViolationBeforeHash(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.Software.BinaryHash = "not-a-sha256-ref"

	raw, hash, err := marshalEvidenceCanonical(evidence)
	require.ErrorContains(t, err, "evidence schema validation failed")
	require.ErrorContains(t, err, "software.binary_hash")
	require.Nil(t, raw)
	require.Empty(t, hash)
}

func TestMarshalEvidenceCanonicalRejectsDuplicateCapabilities(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.AttestedCapabilities = []string{"persistent_storage", "persistent_storage"}

	_, _, err := marshalEvidenceCanonical(evidence)
	require.ErrorContains(t, err, "evidence schema validation failed")
	require.ErrorContains(t, err, "attested_capabilities")
}

func TestMarshalEvidenceCanonicalRejectsAttestedTierAboveTargetTier(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.TargetTier = "L1"
	evidence.AttestedTier = "L2"

	_, _, err := marshalEvidenceCanonical(evidence)
	require.ErrorContains(t, err, "evidence semantic validation failed")
	require.ErrorContains(t, err, `attested_tier "L2" exceeds target_tier "L1"`)
}

func testQuantity(val string) *resource.Quantity {
	q := resource.MustParse(val)
	return &q
}

func TestMarshalEvidenceCanonicalRejectsMalformedBase64(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.InventoryNonce = "not-base64"

	_, _, err := marshalEvidenceCanonical(evidence)
	require.ErrorContains(t, err, "evidence semantic validation failed")
	require.ErrorContains(t, err, "inventory_nonce must be base64")
}

func TestMarshalEvidenceCanonicalRejectsMalformedTimestamp(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.CollectedAt = "not-a-date-time"

	_, _, err := marshalEvidenceCanonical(evidence)
	require.ErrorContains(t, err, "evidence schema validation failed")
	require.ErrorContains(t, err, "collected_at")
}

func TestMarshalEvidenceCanonicalRejectsUint64Overflow(t *testing.T) {
	evidence := validEvidenceDocument()
	evidence.BlockHeight = "18446744073709551616"

	_, _, err := marshalEvidenceCanonical(evidence)
	require.ErrorContains(t, err, "evidence semantic validation failed")
	require.ErrorContains(t, err, "block_height must be a uint64 string")
}

func TestValidateEvidenceInputsRequiresSoftwareBinaryHash(t *testing.T) {
	cfg := validCollectConfig()
	cfg.softwareBinaryHash = ""

	err := validateEvidenceInputs(cfg)
	require.ErrorContains(t, err, "software-binary-hash is required")
}

func TestValidateEvidenceInputsRejectsInvalidSoftwareBinaryHash(t *testing.T) {
	cfg := validCollectConfig()
	cfg.softwareBinaryHash = "sha256:not-hex"

	err := validateEvidenceInputs(cfg)
	require.ErrorContains(t, err, "software-binary-hash must use sha256:<64 hex> form")
}

func TestValidateEvidenceInputsRejectsAttestedTierAboveTargetTier(t *testing.T) {
	cfg := validCollectConfig()
	cfg.targetTier = "L1"
	cfg.attestedTier = "L2"

	err := validateEvidenceInputs(cfg)
	require.ErrorContains(t, err, `attested-tier "L2" exceeds target-tier "L1"`)
}

func TestValidateEvidenceInputsRejectsUnknownCapability(t *testing.T) {
	cfg := validCollectConfig()
	cfg.attestedCapabilities = []string{"gpu"}

	err := validateEvidenceInputs(cfg)
	require.ErrorContains(t, err, `invalid capability "gpu"`)
}

func TestValidateEvidenceInputsRejectsDuplicateCapability(t *testing.T) {
	cfg := validCollectConfig()
	cfg.attestedCapabilities = []string{"persistent_storage", "persistent_storage"}

	err := validateEvidenceInputs(cfg)
	require.ErrorContains(t, err, `duplicate capability "persistent_storage"`)
}

func TestValidateEvidenceInputsAcceptsSoftwareBinaryHash(t *testing.T) {
	cfg := validCollectConfig()

	err := validateEvidenceInputs(cfg)
	require.NoError(t, err)
}

func TestEvidenceChecksMapObservedChainFacts(t *testing.T) {
	payloadHash := []byte("12345678901234567890123456789012")
	committed := &verifiedSnapshot{
		PayloadHash:           payloadHash,
		SignatureVerified:     true,
		ProviderPubKeyAddress: "akash1provider",
		Payload: &inventoryv1.SnapshotPayload{
			Timestamp: time.Unix(1, 0).UTC(),
			ResourceSummary: inventoryv1.SnapshotResourceSummary{
				SoftwareVersion: "provider-services-test",
			},
		},
	}
	challenge := &verifiedSnapshot{
		PayloadHash:           []byte("abcdefabcdefabcdefabcdefabcdef12"),
		SignatureVerified:     true,
		ProviderPubKeyAddress: "akash1provider",
		Payload: &inventoryv1.SnapshotPayload{
			Timestamp: time.Unix(2, 0).UTC(),
			Nonce:     []byte("12345678901234567890123456789012"),
		},
	}
	chainFacts := &chainFactsResult{
		ProviderPubKeyAddress:  "akash1provider",
		ProviderRegistered:     true,
		ProviderBondObserved:   true,
		ProviderBondSufficient: true,
		SnapshotObserved:       true,
		SnapshotHash:           payloadHash,
		LeaseStatsObserved:     true,
		TotalLeases:            10,
		CompletedLeases:        9,
		ProviderFaultedLeases:  1,
	}

	checks := evidenceChecks(committed, challenge, chainFacts)
	byName := evidenceChecksByName(checks)

	require.Equal(t, "pass", byName["provider_registered_on_chain"].Status)
	require.Equal(t, "pass", byName["provider_bond_sufficient"].Status)
	require.Equal(t, "not_evaluated", byName["provider_age_sufficient"].Status)
	require.Equal(t, "not_evaluated", byName["lease_completion_sufficient"].Status)
	require.Equal(t, uint64(10), byName["lease_completion_sufficient"].Details["total_leases"])
	require.Equal(t, "pass", byName["snapshot_not_suspended"].Status)
	require.Equal(t, "pass", byName["snapshot_hash_matches_chain"].Status)
	require.Equal(t, "pass", byName["inventory_signature_valid"].Status)
}

func TestEvidenceChecksDoNotPassUnobservedFacts(t *testing.T) {
	payloadHash := []byte("12345678901234567890123456789012")
	committed := &verifiedSnapshot{
		PayloadHash: payloadHash,
		Payload: &inventoryv1.SnapshotPayload{
			Timestamp: time.Unix(1, 0).UTC(),
			ResourceSummary: inventoryv1.SnapshotResourceSummary{
				SoftwareVersion: "provider-services-test",
			},
		},
	}
	challenge := &verifiedSnapshot{
		PayloadHash: []byte("abcdefabcdefabcdefabcdefabcdef12"),
		Payload: &inventoryv1.SnapshotPayload{
			Timestamp: time.Unix(2, 0).UTC(),
			Nonce:     []byte("12345678901234567890123456789012"),
		},
	}

	checks := evidenceChecks(committed, challenge, &chainFactsResult{})
	byName := evidenceChecksByName(checks)

	require.Equal(t, "fail", byName["provider_registered_on_chain"].Status)
	require.Equal(t, "not_evaluated", byName["provider_bond_sufficient"].Status)
	require.Equal(t, "not_evaluated", byName["lease_completion_sufficient"].Status)
	require.Nil(t, byName["lease_completion_sufficient"].Details)
	require.Equal(t, "not_evaluated", byName["snapshot_not_suspended"].Status)
	require.Equal(t, "not_evaluated", byName["snapshot_hash_matches_chain"].Status)
	require.Equal(t, "not_evaluated", byName["inventory_signature_valid"].Status)
}

func evidenceChecksByName(checks []EvidenceCheck) map[string]EvidenceCheck {
	res := make(map[string]EvidenceCheck, len(checks))
	for _, check := range checks {
		res[check.Name] = check
	}

	return res
}

func mustSnapshotPayload(t *testing.T, provider string, nonce []byte) []byte {
	t.Helper()

	payload := &inventoryv1.SnapshotPayload{
		SchemaVersion: 1,
		Provider:      provider,
		ChainID:       "akash-local",
		Nonce:         nonce,
		Timestamp:     time.Unix(1, 0).UTC(),
		ResourceSummary: inventoryv1.SnapshotResourceSummary{
			SoftwareVersion: "provider-services-test",
		},
	}

	raw, err := proto.Marshal(payload)
	require.NoError(t, err)

	return raw
}

func validEvidenceDocument() EvidenceDocument {
	return EvidenceDocument{
		SchemaVersion:         evidenceSchema,
		ChainID:               "akash-local",
		Provider:              "akash1provider",
		Auditor:               "akash1auditor",
		AuditEscrowID:         "7",
		TargetTier:            "L1",
		AttestedTier:          "L1",
		AttestedCapabilities:  []string{"persistent_storage"},
		CollectedAt:           "2026-05-19T00:00:00Z",
		BlockHeight:           "123",
		SnapshotHash:          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ChallengeSnapshotHash: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		InventoryNonce:        "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		Software: SoftwareEvidence{
			Version:            "test",
			BinaryHash:         "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			VerificationStatus: "observed_only",
		},
		NetworkBaseline: NetworkBaseline{
			ProofRef: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		SustainedValidation: SustainedValidation{
			BaselineID:    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Window:        "attestation_ttl",
			LastCheckedAt: "2026-05-19T00:00:00Z",
			Status:        "not_evaluated",
			ProofRef:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Checks: []EvidenceCheck{{
			Name:     "inventory_signature_valid",
			Status:   "pass",
			ProofRef: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Details: map[string]any{
				"a": "first",
				"z": true,
			},
		}},
		FaultContext: FaultContext{
			FaultAttribution: "unspecified",
			Reason:           "unspecified",
		},
	}
}

func validCollectConfig() collectConfig {
	return collectConfig{
		providerGRPC:       "provider.example.com:8443",
		chainGRPC:          "rpc.example.com:9090",
		auditor:            "akash1auditor",
		auditEscrowID:      "7",
		targetTier:         "L1",
		attestedTier:       "L1",
		softwareBinaryHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func writeCollectedEvidenceArtifact(t *testing.T, mutate func(*EvidenceDocument)) (string, string) {
	t.Helper()

	dir := t.TempDir()
	payload := []byte("canonical committed snapshot payload")
	challengePayload := []byte("canonical challenge snapshot payload")
	payloadHash := sha256Ref(sha256Bytes(payload))
	challengePayloadHash := sha256Ref(sha256Bytes(challengePayload))
	nonce := []byte("12345678901234567890123456789012")

	evidence := validEvidenceDocument()
	evidence.SnapshotHash = payloadHash
	evidence.ChallengeSnapshotHash = challengePayloadHash
	evidence.InventoryNonce = base64.StdEncoding.EncodeToString(nonce)
	evidence.NetworkBaseline.ProofRef = payloadHash
	evidence.SustainedValidation.BaselineID = payloadHash
	evidence.SustainedValidation.ProofRef = payloadHash
	for idx := range evidence.Checks {
		evidence.Checks[idx].ProofRef = payloadHash
	}
	mutate(&evidence)

	raw, hash, err := marshalEvidenceCanonical(evidence)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, evidenceDraftFile), raw, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, evidenceHashFile), []byte(hash+"\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, nonceFile), nonce, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, snapshotPayloadFile), payload, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, snapshotSigFile), []byte("signature"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, snapshotJSONFile), []byte("{}\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, challengeSnapshotPayloadFile), challengePayload, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, challengeSnapshotSigFile), []byte("challenge-signature"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, challengeSnapshotJSONFile), []byte("{}\n"), 0o644))

	collection := collectionArtifact{
		SchemaVersion:         evidenceSchema + ".collection",
		CollectedAt:           evidence.CollectedAt,
		Provider:              evidence.Provider,
		Auditor:               evidence.Auditor,
		AuditEscrowID:         evidence.AuditEscrowID,
		ChainID:               evidence.ChainID,
		BlockHeight:           evidence.BlockHeight,
		SnapshotPayloadHash:   payloadHash,
		CommittedSnapshotHash: payloadHash,
		ChallengeSnapshotHash: challengePayloadHash,
		InventoryNonce:        evidence.InventoryNonce,
		Signature:             base64.StdEncoding.EncodeToString([]byte("signature")),
		ChallengeSignature:    base64.StdEncoding.EncodeToString([]byte("challenge-signature")),
		SignatureVerified:     true,
		Files: map[string]string{
			"nonce":                      filepath.Join(dir, nonceFile),
			"snapshot_payload":           filepath.Join(dir, snapshotPayloadFile),
			"signature":                  filepath.Join(dir, snapshotSigFile),
			"payload_json":               filepath.Join(dir, snapshotJSONFile),
			"challenge_snapshot_payload": filepath.Join(dir, challengeSnapshotPayloadFile),
			"challenge_signature":        filepath.Join(dir, challengeSnapshotSigFile),
			"challenge_payload_json":     filepath.Join(dir, challengeSnapshotJSONFile),
			"evidence_draft":             filepath.Join(dir, evidenceDraftFile),
		},
	}
	require.NoError(t, writeJSON(filepath.Join(dir, collectionFile), collection))

	return dir, hash
}
