package main

import (
	"bytes"
	"fmt"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	inventoryv1 "pkg.akt.dev/go/inventory/v1"
)

type verifiedSnapshot struct {
	PayloadBytes          []byte
	Payload               *inventoryv1.SnapshotPayload
	PayloadHash           []byte
	Provider              string
	SignatureVerified     bool
	SignatureSkipped      bool
	ProviderPubKeyAddress string
}

func verifySnapshotEnvelope(resp *inventoryv1.GetInventorySnapshotResponse, nonce []byte) (*verifiedSnapshot, error) {
	if resp == nil {
		return nil, fmt.Errorf("empty inventory snapshot response")
	}
	if len(resp.GetSnapshotPayload()) == 0 {
		return nil, fmt.Errorf("empty inventory snapshot payload")
	}
	if len(resp.GetSignature()) == 0 {
		return nil, fmt.Errorf("empty inventory snapshot signature")
	}

	payload, err := protoUnmarshalSnapshotPayload(resp.GetSnapshotPayload())
	if err != nil {
		return nil, fmt.Errorf("decode snapshot payload: %w", err)
	}
	if !bytes.Equal(payload.GetNonce(), nonce) {
		return nil, fmt.Errorf("snapshot nonce mismatch")
	}
	if payload.GetProvider() == "" {
		return nil, fmt.Errorf("snapshot payload missing provider")
	}
	if resp.GetProvider() != "" && resp.GetProvider() != payload.GetProvider() {
		return nil, fmt.Errorf("snapshot response provider %q does not match payload provider %q", resp.GetProvider(), payload.GetProvider())
	}
	if payload.GetChainID() == "" {
		return nil, fmt.Errorf("snapshot payload missing chain_id")
	}
	if payload.GetSchemaVersion() == 0 {
		return nil, fmt.Errorf("snapshot payload missing schema_version")
	}

	return &verifiedSnapshot{
		PayloadBytes: append([]byte(nil), resp.GetSnapshotPayload()...),
		Payload:      payload,
		PayloadHash:  snapshotPayloadHash(resp.GetSnapshotPayload()),
		Provider:     payload.GetProvider(),
	}, nil
}

func verifyCommittedSnapshotEnvelope(resp *inventoryv1.GetCommittedInventorySnapshotResponse) (*verifiedSnapshot, error) {
	if resp == nil {
		return nil, fmt.Errorf("empty committed inventory snapshot response")
	}
	if len(resp.GetSnapshotPayload()) == 0 {
		return nil, fmt.Errorf("empty committed inventory snapshot payload")
	}
	if len(resp.GetSignature()) == 0 {
		return nil, fmt.Errorf("empty committed inventory snapshot signature")
	}

	payload, err := protoUnmarshalSnapshotPayload(resp.GetSnapshotPayload())
	if err != nil {
		return nil, fmt.Errorf("decode committed snapshot payload: %w", err)
	}
	if len(payload.GetNonce()) != 0 {
		return nil, fmt.Errorf("committed snapshot payload must not contain nonce")
	}
	if payload.GetProvider() == "" {
		return nil, fmt.Errorf("committed snapshot payload missing provider")
	}
	if resp.GetProvider() != "" && resp.GetProvider() != payload.GetProvider() {
		return nil, fmt.Errorf("committed snapshot response provider %q does not match payload provider %q", resp.GetProvider(), payload.GetProvider())
	}
	if payload.GetChainID() == "" {
		return nil, fmt.Errorf("committed snapshot payload missing chain_id")
	}
	if payload.GetSchemaVersion() == 0 {
		return nil, fmt.Errorf("committed snapshot payload missing schema_version")
	}

	hash := snapshotPayloadHash(resp.GetSnapshotPayload())
	if len(resp.GetSnapshotHash()) != 0 && !bytes.Equal(resp.GetSnapshotHash(), hash) {
		return nil, fmt.Errorf("committed snapshot hash does not match payload")
	}

	return &verifiedSnapshot{
		PayloadBytes: append([]byte(nil), resp.GetSnapshotPayload()...),
		Payload:      payload,
		PayloadHash:  hash,
		Provider:     payload.GetProvider(),
	}, nil
}

func verifyProviderSignature(payload, signature []byte, pubKey cryptotypes.PubKey, provider string) error {
	if pubKey == nil {
		return fmt.Errorf("missing provider public key")
	}

	pubKeyAddress := sdk.AccAddress(pubKey.Address()).String()
	if pubKeyAddress != provider {
		return fmt.Errorf("provider public key address %q does not match snapshot provider %q", pubKeyAddress, provider)
	}

	if !pubKey.VerifySignature(payload, signature) {
		return fmt.Errorf("provider signature verification failed")
	}

	return nil
}
