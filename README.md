# Auditor CLI

`auditor-cli` is the AEP-86 reference auditor helper.

This tool intentionally lives outside consensus code and does not broadcast
transactions. It collects provider evidence, verifies local artifacts, compares
baseline/current evidence, and prints the `akash tx verification ...` command an
operator can run through the normal chain CLI or governance flow.

- generates a cryptographically random 32-byte nonce
- calls provider `akash.inventory.v1.InventoryService/GetInventorySnapshot` for a fresh nonce-bound challenge
- calls provider `akash.inventory.v1.InventoryService/GetCommittedInventorySnapshot` for the exact committed payload
- decodes `akash.inventory.v1.SnapshotPayload`
- verifies nonce/provider/chain binding on the challenge payload
- verifies the committed payload hash against the provider snapshot hash on-chain
- queries the chain gRPC auth account for the provider public key
- verifies the provider signature over both raw snapshot payloads
- writes raw artifacts plus a draft `akash.audit.evidence.v1` JSON document
- verifies that `evidence.draft.json` is schema-valid canonical JSON and matches `evidence.draft.sha256`
- compares a current evidence artifact against a baseline artifact
- prepares submit and revoke transaction commands from verified evidence artifacts without broadcasting them

## Run

```sh
GOWORK=off go run ./cmd/auditor-cli collect \
  --provider-grpc provider.example.com:8443 \
  --chain-grpc rpc.example.com:9090 \
  --auditor akash1... \
  --audit-escrow-id 0 \
  --target-tier L1 \
  --software-binary-hash sha256:<64-hex> \
  --output-dir ./aep86-audit
```

The provider endpoint is the existing provider daemon gRPC endpoint with the public AEP-86 inventory service registered.
The chain endpoint is an Akash node gRPC endpoint used to query the provider account public key and best-effort
verification facts.
Collection requires the provider to have already posted a snapshot hash on-chain. The draft evidence records that
committed hash as `snapshot_hash` and the fresh challenge hash as `challenge_snapshot_hash`.
`--software-binary-hash` is required and must use `sha256:<64-hex>` form so the draft evidence satisfies the
strict evidence schema.

For local devnets with self-signed provider certificates, add `--provider-skip-tls-verify`. For plaintext test servers,
add `--provider-insecure`.

Validate the local artifact directory before submitting evidence elsewhere:

```sh
GOWORK=off go run ./cmd/auditor-cli verify ./aep86-audit
```

Prepare a submission command from a verified artifact directory. This only
prints the command; it does not submit to chain.

```sh
GOWORK=off go run ./cmd/auditor-cli submit \
  --fee 100uakt \
  --deposit 200uakt \
  ./aep86-audit
```

Compare current evidence against the original baseline:

```sh
GOWORK=off go run ./cmd/auditor-cli sustain ./aep86-baseline ./aep86-current
```

Write a sustained-validation evidence artifact. If the comparison fails, the
output evidence includes `fault_context.reason` and can be used to prepare an
auditor revocation command.

```sh
GOWORK=off go run ./cmd/auditor-cli sustain \
  --output-dir ./aep86-sustained \
  ./aep86-baseline \
  ./aep86-current
```

Prepare a revocation command from verified revocation evidence. Normal
attestation evidence has `fault_context.reason: "unspecified"` and is rejected
by `revoke`; run `sustain --output-dir` first so the reason is committed into
the evidence hash.

```sh
GOWORK=off go run ./cmd/auditor-cli revoke \
  --reason software_identity_changed \
  ./aep86-sustained
```

`submit` and `revoke` are dry-run helpers. They validate canonical
`evidence.draft.json`, verify `evidence.draft.sha256`, check optional
provider/auditor/audit-escrow/tier/capability/chain flags against the evidence,
and print the exact `akash tx verification ...` command. Broadcasting remains
the job of the Akash chain CLI or the sandbox governance helper scripts.
