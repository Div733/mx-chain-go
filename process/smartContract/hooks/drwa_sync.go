package hooks

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
)

// drwaBinaryHashSize is the byte length of the keccak256 hash prefix in the
// binary hook payload produced by the Rust managedDRWASyncMirror call.
const drwaBinaryHashSize = 32


type drwaSyncStateAdapter interface {
	GetTokenPolicyVersion(tokenID string) (uint64, error)
	GetAssetRecordVersion(tokenID string) (uint64, error)
	GetHolderMirrorVersion(tokenID, holder string) (uint64, error)
	GetHolderProfileVersion(holder string) (uint64, error)
	GetHolderAuditorAuthorizationVersion(tokenID, holder string) (uint64, error)
	GetAuthorizedCallerAddress(domain string) ([]byte, error)
	PutTokenPolicyBody(tokenID string, version uint64, body []byte) error
	PutAssetRecordBody(tokenID string, version uint64, body []byte) error
	PutHolderMirrorBody(tokenID, holder string, version uint64, body []byte) error
	PutHolderProfileBody(holder string, version uint64, body []byte) error
	PutHolderAuditorAuthorizationBody(tokenID, holder string, version uint64, body []byte) error
	DeleteHolderMirror(tokenID, holder string, version uint64) error
	Snapshot() int
	Rollback(snapshot int) error
	IsInterfaceNil() bool
}

func decodeDRWASyncEnvelope(payload []byte) (*drwaSyncEnvelope, error) {
	if len(payload) == 0 {
		return nil, errors.New("nil DRWA sync payload")
	}
	if len(payload) > drwaSyncMaxPayloadBytes {
		return nil, errors.New(drwaSyncRejectPayloadTooLarge)
	}

	// Binary path: payload produced by the Rust managedDRWASyncMirror hook.
	// Format: [32-byte keccak256 hash] || [canonical binary payload].
	// Detected by the first byte not being '{' (JSON always starts with '{').
	if payload[0] != '{' {
		envelope, err := decodeDRWASyncEnvelopeBinary(payload)
		if err != nil {
			recordDRWAMetric(drwaMetricSyncDecodeFailure)
		}
		return envelope, err
	}

	envelope := &drwaSyncEnvelope{}
	err := json.Unmarshal(payload, envelope)
	if err != nil {
		recordDRWAMetric(drwaMetricSyncDecodeFailure)
		return nil, err
	}

	// Check operation count immediately after unmarshal, before any
	// further processing. Bounds memory from malicious JSON payloads that could
	// contain thousands of tiny operations within the 1 MB size limit.
	if len(envelope.Operations) > drwaSyncMaxOperations {
		recordDRWAMetric(drwaMetricSyncDecodeFailure)
		return nil, fmt.Errorf("DRWA JSON sync envelope contains %d operations, exceeding limit of %d",
			len(envelope.Operations), drwaSyncMaxOperations)
	}

	return envelope, nil
}

func decodeDRWASyncEnvelopeBinary(payload []byte) (*drwaSyncEnvelope, error) {
	if len(payload) < drwaBinaryHashSize+1 {
		return nil, errors.New("DRWA binary sync payload too short")
	}

	payloadHash := make([]byte, drwaBinaryHashSize)
	copy(payloadHash, payload[:drwaBinaryHashSize])
	canonicalPayload := payload[drwaBinaryHashSize:]

	envelope, err := parseDRWABinaryPayload(canonicalPayload)
	if err != nil {
		return nil, fmt.Errorf("DRWA binary payload parse error: %w", err)
	}
	envelope.PayloadHash = payloadHash

	return envelope, nil
}

func parseDRWABinaryPayload(data []byte) (*drwaSyncEnvelope, error) {
	if len(data) == 0 {
		return nil, errors.New("empty DRWA binary canonical payload")
	}

	r := bytes.NewReader(data)

	callerTagByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("reading caller tag: %w", err)
	}
	callerDomain, err := drwaCallerDomainFromTag(callerTagByte)
	if err != nil {
		return nil, err
	}

	var operations []drwaSyncOperation
	for r.Len() > 0 {
		// Cap operations before full allocation (matches JSON path).
		if len(operations) >= drwaSyncMaxOperations {
			return nil, fmt.Errorf("DRWA binary payload exceeds %d operations", drwaSyncMaxOperations)
		}
		op, err := readDRWABinaryOperation(r)
		if err != nil {
			return nil, err
		}
		operations = append(operations, op)
	}

	return &drwaSyncEnvelope{
		CallerDomain: callerDomain,
		Operations:   operations,
	}, nil
}

func readDRWABinaryOperation(r *bytes.Reader) (drwaSyncOperation, error) {
	opTagByte, err := r.ReadByte()
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading operation tag: %w", err)
	}
	opType, err := drwaOperationTypeFromTag(opTagByte)
	if err != nil {
		return drwaSyncOperation{}, err
	}

	tokenIDBytes, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading token_id: %w", err)
	}

	holderBytes, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading holder: %w", err)
	}

	var versionBuf [8]byte
	if _, err = io.ReadFull(r, versionBuf[:]); err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading version: %w", err)
	}
	version := binary.BigEndian.Uint64(versionBuf[:])

	body, err := readDRWABinaryLenPrefixed(r)
	if err != nil {
		return drwaSyncOperation{}, fmt.Errorf("reading body: %w", err)
	}

	// For token_policy the holder field is 32 zero bytes (canonical placeholder).
	// Represent as empty string in-memory, matching JSON behaviour.
	holder := ""
	if opType != drwaSyncOpTokenPolicy {
		holder = string(holderBytes)
	}

	return drwaSyncOperation{
		OperationType: opType,
		TokenID:       string(tokenIDBytes),
		Holder:        holder,
		Version:       version,
		Body:          body,
	}, nil
}

// drwaSyncMaxFieldBytes caps the length of any single binary field to prevent
// memory exhaustion from corrupted length prefixes. Set to 64 KB — no legitimate
// DRWA field (token ID, holder address, policy body) exceeds this.
const drwaSyncMaxFieldBytes = 64 * 1024

func readDRWABinaryLenPrefixed(r *bytes.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length prefix: %w", err)
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 {
		return []byte{}, nil
	}
	if length > drwaSyncMaxFieldBytes {
		return nil, fmt.Errorf("DRWA binary field length %d exceeds max %d", length, drwaSyncMaxFieldBytes)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("reading %d-byte value: %w", length, err)
	}
	return value, nil
}

func drwaCallerDomainFromTag(tag byte) (string, error) {
	switch tag {
	case 0:
		return drwaSyncCallerPolicyRegistry, nil
	case 1:
		return drwaSyncCallerAssetManager, nil
	case 2:
		return drwaSyncCallerIdentityRegistry, nil
	case 3:
		return drwaSyncCallerAttestation, nil
	case 4:
		return drwaSyncCallerRecoveryAdmin, nil
	default:
		return "", fmt.Errorf("unknown DRWA caller domain tag: %d", tag)
	}
}

func drwaOperationTypeFromTag(tag byte) (drwaSyncOperationType, error) {
	switch tag {
	case 0:
		return drwaSyncOpTokenPolicy, nil
	case 1:
		return drwaSyncOpAssetRecord, nil
	case 2:
		return drwaSyncOpHolderMirror, nil
	case 3:
		return drwaSyncOpHolderProfile, nil
	case 4:
		return drwaSyncOpHolderAuditorAuth, nil
	case 5:
		return drwaSyncOpHolderMirrorDelete, nil
	default:
		return "", fmt.Errorf("unknown DRWA operation type tag: %d", tag)
	}
}

func applyDRWASyncEnvelope(
	adapter drwaSyncStateAdapter,
	envelope *drwaSyncEnvelope,
	maxOperations int,
	callerAddress []byte,
) (*drwaSyncApplyResult, error) {
	if adapter == nil {
		return nil, errors.New("nil DRWA sync adapter")
	}
	if envelope == nil {
		return nil, errors.New("nil DRWA sync envelope")
	}
	if len(envelope.Operations) == 0 {
		if err := verifyDRWANoopEnvelopeHash(envelope); err != nil {
			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}
		recordDRWAMetric(drwaMetricSyncApplyNoop)
		return &drwaSyncApplyResult{Noop: true}, nil
	}
	if len(envelope.Operations) > maxOperations {
		recordDRWAMetric(drwaMetricSyncApplyFailure)
		return nil, errors.New(drwaSyncRejectPayloadTooLarge)
	}
	if !isDRWASyncCallerAuthorized(adapter, envelope.CallerDomain, envelope.Operations, callerAddress) {
		recordDRWAMetric(drwaMetricSyncApplyFailure)
		recordDRWAMetric(drwaMetricSyncUnauthorizedCaller)
		return nil, errors.New(drwaSyncRejectUnauthorizedCaller)
	}

	payloadHash, err := computeDRWASyncHash(envelope.CallerDomain, envelope.Operations)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payloadHash, envelope.PayloadHash) {
		recordDRWAMetric(drwaMetricSyncApplyFailure)
		recordDRWAMetric(drwaMetricSyncHashMismatch)
		return nil, errors.New(drwaSyncRejectHashMismatch)
	}

	snapshot := adapter.Snapshot()
	result := &drwaSyncApplyResult{}

	for _, operation := range envelope.Operations {
		err = applyDRWASyncOperation(adapter, operation)
		if err != nil {
			rollbackErr := adapter.Rollback(snapshot)
			if rollbackErr != nil {
				recordDRWAMetric(drwaMetricSyncApplyFailure)
				return nil, fmt.Errorf("%s: %w", drwaSyncRejectBatchAtomicity, rollbackErr)
			}

			recordDRWAMetric(drwaMetricSyncApplyFailure)
			return nil, err
		}

		result.AppliedOperations++
		result.LastTokenID = operation.TokenID
	}

	recordDRWAMetric(drwaMetricSyncApplySuccess)
	return result, nil
}

func applyDRWASyncOperation(adapter drwaSyncStateAdapter, operation drwaSyncOperation) error {
	switch operation.OperationType {
	case drwaSyncOpTokenPolicy:
		currentVersion, err := adapter.GetTokenPolicyVersion(operation.TokenID)
		if err != nil {
			return err
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		return adapter.PutTokenPolicyBody(operation.TokenID, operation.Version, operation.Body)
	case drwaSyncOpAssetRecord:
		currentVersion, err := adapter.GetAssetRecordVersion(operation.TokenID)
		if err != nil {
			return err
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		return adapter.PutAssetRecordBody(operation.TokenID, operation.Version, operation.Body)
	case drwaSyncOpHolderMirror:
		currentVersion, err := adapter.GetHolderMirrorVersion(operation.TokenID, operation.Holder)
		if err != nil {
			return err
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		return adapter.PutHolderMirrorBody(operation.TokenID, operation.Holder, operation.Version, operation.Body)
	case drwaSyncOpHolderProfile:
		currentVersion, err := adapter.GetHolderProfileVersion(operation.Holder)
		if err != nil {
			return err
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		return adapter.PutHolderProfileBody(operation.Holder, operation.Version, operation.Body)
	case drwaSyncOpHolderAuditorAuth:
		currentVersion, err := adapter.GetHolderAuditorAuthorizationVersion(operation.TokenID, operation.Holder)
		if err != nil {
			return err
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		return adapter.PutHolderAuditorAuthorizationBody(operation.TokenID, operation.Holder, operation.Version, operation.Body)
	case drwaSyncOpHolderMirrorDelete:
		currentVersion, err := adapter.GetHolderMirrorVersion(operation.TokenID, operation.Holder)
		if err != nil {
			return err
		}
		err = validateDRWASyncVersion(currentVersion, operation.Version)
		if err != nil {
			return err
		}

		return adapter.DeleteHolderMirror(operation.TokenID, operation.Holder, operation.Version)
	default:
		return fmt.Errorf("unknown DRWA sync operation type: %s", operation.OperationType)
	}
}

// Each rejection reason has a distinct error constant for
// unambiguous diagnostics: overflow, stale, duplicate, non-sequential.
func validateDRWASyncVersion(currentVersion, nextVersion uint64) error {
	if currentVersion == math.MaxUint64 {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectVersionOverflow)
	}
	if nextVersion < currentVersion {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectReplayStale)
	}
	if nextVersion == currentVersion {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectReplayDuplicate)
	}
	if nextVersion != currentVersion+1 {
		recordDRWAMetric(drwaMetricSyncReplayRejected)
		return errors.New(drwaSyncRejectVersionGap)
	}

	return nil
}

func isDRWASyncCallerAuthorized(
	adapter drwaSyncStateAdapter,
	callerDomain string,
	operations []drwaSyncOperation,
	callerAddress []byte,
) bool {
	if len(callerAddress) == 0 {
		return false
	}

	validOperations := false
	switch callerDomain {
	case drwaSyncCallerPolicyRegistry:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpTokenPolicy {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerAssetManager:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpHolderMirror && operation.OperationType != drwaSyncOpAssetRecord {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerIdentityRegistry:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpHolderProfile {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerAttestation:
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpHolderAuditorAuth {
				return false
			}
		}
		validOperations = true
	case drwaSyncCallerRecoveryAdmin:
		// SECURITY — recovery_admin has the broadest write scope
		// (token_policy, holder_mirror, holder_mirror_delete). A compromised
		// recovery admin key can override ALL compliance state.
		// DEPLOYMENT: key MUST be in HSM with multi-party access control.
		// All recovery_admin operations MUST emit high-priority alerts.
		for _, operation := range operations {
			if operation.OperationType != drwaSyncOpTokenPolicy &&
				operation.OperationType != drwaSyncOpHolderMirror &&
				operation.OperationType != drwaSyncOpHolderMirrorDelete {
				return false
			}
		}
		validOperations = true
	default:
		return false
	}
	if !validOperations {
		return false
	}

	expectedAddress, err := adapter.GetAuthorizedCallerAddress(callerDomain)
	if err != nil || len(expectedAddress) == 0 {
		return false
	}

	return bytes.Equal(expectedAddress, callerAddress)
}

// verifyDRWANoopEnvelopeHash verifies the hash of a noop (zero-operation)
// envelope when a PayloadHash is present. Detects corrupted or tampered
// payloads even when the operation list is empty.
func verifyDRWANoopEnvelopeHash(envelope *drwaSyncEnvelope) error {
	if len(envelope.PayloadHash) == 0 {
		return nil
	}
	expectedHash, err := computeDRWASyncHash(envelope.CallerDomain, nil)
	if err != nil {
		return fmt.Errorf("noop envelope hash computation failed: %w", err)
	}
	if !bytes.Equal(envelope.PayloadHash, expectedHash) {
		return errors.New("noop envelope hash mismatch")
	}
	return nil
}

func computeDRWASyncHash(callerDomain string, operations []drwaSyncOperation) ([]byte, error) {
	payload, err := serializeDRWASyncEnvelopePayload(callerDomain, operations)
	if err != nil {
		return nil, err
	}

	return keccak.NewKeccak().Compute(string(payload)), nil
}

func serializeDRWASyncEnvelopePayload(callerDomain string, operations []drwaSyncOperation) ([]byte, error) {
	var payload bytes.Buffer

	callerTag, err := drwaCallerDomainTag(callerDomain)
	if err != nil {
		return nil, err
	}

	payload.WriteByte(callerTag)
	for _, operation := range operations {
		opTag, err := drwaOperationTypeTag(operation.OperationType)
		if err != nil {
			return nil, err
		}

		payload.WriteByte(opTag)
		writeDRWALengthPrefixed(&payload, []byte(operation.TokenID))
		writeDRWALengthPrefixed(&payload, drwaSerializedHolder(operation))

		versionBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(versionBytes, operation.Version)
		payload.Write(versionBytes)
		writeDRWALengthPrefixed(&payload, operation.Body)
	}

	return payload.Bytes(), nil
}

func drwaCallerDomainTag(callerDomain string) (byte, error) {
	switch callerDomain {
	case drwaSyncCallerPolicyRegistry:
		return 0, nil
	case drwaSyncCallerAssetManager:
		return 1, nil
	case drwaSyncCallerIdentityRegistry:
		return 2, nil
	case drwaSyncCallerAttestation:
		return 3, nil
	case drwaSyncCallerRecoveryAdmin:
		return 4, nil
	default:
		return 0, fmt.Errorf("unknown DRWA sync caller domain: %s", callerDomain)
	}
}

func drwaOperationTypeTag(operationType drwaSyncOperationType) (byte, error) {
	switch operationType {
	case drwaSyncOpTokenPolicy:
		return 0, nil
	case drwaSyncOpHolderMirror:
		return 2, nil
	case drwaSyncOpHolderProfile:
		return 3, nil
	case drwaSyncOpHolderAuditorAuth:
		return 4, nil
	case drwaSyncOpHolderMirrorDelete:
		return 5, nil
	case drwaSyncOpAssetRecord:
		return 1, nil
	default:
		return 0, fmt.Errorf("unknown DRWA sync operation type: %s", operationType)
	}
}

func drwaSerializedHolder(operation drwaSyncOperation) []byte {
	if operation.OperationType == drwaSyncOpTokenPolicy || operation.OperationType == drwaSyncOpAssetRecord {
		return make([]byte, 32)
	}

	return []byte(operation.Holder)
}

func writeDRWALengthPrefixed(payload *bytes.Buffer, value []byte) {
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(value)))
	payload.Write(lengthBytes)
	payload.Write(value)
}
