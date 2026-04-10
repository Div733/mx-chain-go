package hooks

import (
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

// Validate at startup that the prefix constants in this module match
// the exported constants in mx-chain-vm-common-go/builtInFunctions/drwa.go.
// A divergence here silently breaks the entire enforcement system because the
// sync adapter writes keys that the transfer gate cannot read.
func init() {
	pairs := [][2]string{
		{drwaSyncTokenPolicyPrefix, builtInFunctions.DRWATokenPolicyPrefix},
		{drwaSyncHolderMirrorPrefix, builtInFunctions.DRWAHolderMirrorPrefix},
		{drwaSyncHolderProfilePrefix, builtInFunctions.DRWAHolderProfilePrefix},
		{drwaSyncHolderAuditorAuthPrefix, builtInFunctions.DRWAHolderAuditorAuthPrefix},
		{drwaSyncAssetRecordPrefix, builtInFunctions.DRWAAssetRecordPrefix},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			panic("CRIT-03: DRWA prefix mismatch between mx-chain-go and mx-chain-vm-common-go: " +
				"local=" + p[0] + " expected=" + p[1])
		}
	}
}

type drwaSyncOperationType string

const (
	drwaSyncOpTokenPolicy        drwaSyncOperationType = "token_policy"
	drwaSyncOpAssetRecord        drwaSyncOperationType = "asset_record"
	drwaSyncOpHolderMirror       drwaSyncOperationType = "holder_mirror"
	drwaSyncOpHolderProfile      drwaSyncOperationType = "holder_profile"
	drwaSyncOpHolderAuditorAuth  drwaSyncOperationType = "holder_auditor_authorization"
	drwaSyncOpHolderMirrorDelete drwaSyncOperationType = "holder_mirror_delete"
)

const (
	drwaSyncCallerPolicyRegistry   = "policy_registry"
	drwaSyncCallerAssetManager     = "asset_manager"
	drwaSyncCallerIdentityRegistry = "identity_registry"
	drwaSyncCallerAttestation      = "attestation"
	drwaSyncCallerRecoveryAdmin    = "recovery_admin"
)

const (
	drwaSyncRejectUnauthorizedCaller = "DRWA_SYNC_UNAUTHORIZED_CALLER"
	drwaSyncRejectPayloadTooLarge    = "DRWA_SYNC_PAYLOAD_TOO_LARGE"
	drwaSyncRejectHashMismatch       = "DRWA_SYNC_HASH_MISMATCH"
	drwaSyncRejectReplayStale        = "DRWA_SYNC_REPLAY_STALE"
	drwaSyncRejectReplayDuplicate    = "DRWA_SYNC_REPLAY_DUPLICATE"
	drwaSyncRejectVersionOverflow    = "DRWA_SYNC_VERSION_OVERFLOW"
	drwaSyncRejectVersionGap         = "DRWA_SYNC_VERSION_GAP"
	drwaSyncRejectBatchAtomicity     = "DRWA_SYNC_BATCH_ATOMICITY_ABORT"
)

const (
	// MUST match DRWATokenPolicyPrefix et al. in
	// mx-chain-vm-common-go/builtInFunctions/drwa.go.
	// Validated at startup by init(); panics on divergence.
	drwaSyncTokenPolicyPrefix       = "drwa:token:"
	drwaSyncAssetRecordPrefix       = "drwa:asset:"
	drwaSyncHolderMirrorPrefix      = "drwa:holder:"
	drwaSyncHolderProfilePrefix     = "drwa:profile:"
	drwaSyncHolderAuditorAuthPrefix = "drwa:auditor:"
	drwaSyncMaxOperations           = 256
	// 1 MB payload limit. With 256 max operations x ~4KB average per
	// holder mirror (token ID + address + compliance fields + body), this
	// supports ~250 holder updates per envelope. Tokens with >250 regulated
	// holders must use multiple sync envelopes across multiple transactions.
	drwaSyncMaxPayloadBytes = 1 << 20
)

type drwaSyncEnvelope struct {
	CallerDomain string              `json:"caller_domain"`
	PayloadHash  []byte              `json:"payload_hash"`
	Operations   []drwaSyncOperation `json:"operations"`
	Noop         bool                `json:"noop,omitempty"`
}

type drwaSyncOperation struct {
	OperationType drwaSyncOperationType `json:"operation_type"`
	TokenID       string                `json:"token_id"`
	Holder        string                `json:"holder,omitempty"`
	Version       uint64                `json:"version"`
	Body          []byte                `json:"body"`
}

type drwaSyncStoredValue struct {
	Version uint64 `json:"version"`
	Body    []byte `json:"body"`
}

type drwaSyncApplyResult struct {
	AppliedOperations int
	LastTokenID       string
	Noop              bool
}
