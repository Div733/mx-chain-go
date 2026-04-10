package hooks

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/state"
	vmcommon "github.com/multiversx/mx-chain-vm-common-go"
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

type drwaHookStateAdapter struct {
	accounts state.AccountsAdapter
}

func newDRWAHookStateAdapter(accounts state.AccountsAdapter) (*drwaHookStateAdapter, error) {
	if accounts == nil || accounts.IsInterfaceNil() {
		return nil, ErrNilDRWAAccountsAdapter
	}

	return &drwaHookStateAdapter{
		accounts: accounts,
	}, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (a *drwaHookStateAdapter) IsInterfaceNil() bool {
	return a == nil
}

// buildDRWATokenPolicyKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWATokenPolicyKey = builtInFunctions.BuildDRWATokenPolicyKey

// buildDRWAHolderMirrorKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWAHolderMirrorKey = builtInFunctions.BuildDRWAHolderMirrorKey

// buildDRWAHolderProfileKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWAHolderProfileKey = builtInFunctions.BuildDRWAHolderProfileKey

// buildDRWAHolderAuditorAuthorizationKey delegates to the canonical key builder in mx-chain-vm-common-go.
var buildDRWAHolderAuditorAuthorizationKey = builtInFunctions.BuildDRWAHolderAuditorAuthorizationKey

func buildDRWAAssetRecordKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncAssetRecordPrefix + hex.EncodeToString(tokenIdentifier) + ":record")
}

func buildDRWAAuthorizedCallerKey(domain string) []byte {
	return []byte("drwa:auth:" + domain)
}

// drwaSyncEvidencePrefix is the storage namespace for all DRWA audit evidence.
// Using a dedicated prefix keeps evidence keys out of the token-policy namespace
// and allows targeted enumeration during forensic inspection.
const drwaSyncEvidencePrefix = "drwa:evidence:"

func buildDRWARecoveryEvidenceKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncEvidencePrefix + hex.EncodeToString(tokenIdentifier) + ":recovery:latest")
}

func buildDRWARecoveryEvidenceHistoryKey(tokenIdentifier []byte, payloadHash []byte) []byte {
	return []byte(fmt.Sprintf("%s%s:recovery:history:%x", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), payloadHash))
}

func buildDRWARolloutEvidenceKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncEvidencePrefix + hex.EncodeToString(tokenIdentifier) + ":rollout:latest")
}

func buildDRWARolloutEvidenceHistoryKey(tokenIdentifier []byte, payloadHash []byte) []byte {
	return []byte(fmt.Sprintf("%s%s:rollout:history:%x", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), payloadHash))
}

func buildDRWARolloutVerificationKey(tokenIdentifier []byte) []byte {
	return []byte(drwaSyncEvidencePrefix + hex.EncodeToString(tokenIdentifier) + ":rollout:verification:latest")
}

func buildDRWARolloutVerificationHistoryKey(tokenIdentifier []byte, payloadHash []byte) []byte {
	return []byte(fmt.Sprintf("%s%s:rollout:verification:history:%x", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), payloadHash))
}

func buildDRWAHolderDeleteAuditKey(tokenIdentifier []byte, address []byte, version uint64) []byte {
	return []byte(fmt.Sprintf("%s%s:holder-delete:%s:%d", drwaSyncEvidencePrefix, hex.EncodeToString(tokenIdentifier), hex.EncodeToString(address), version))
}

type drwaDeleteAuditRecord struct {
	TokenID string `json:"token_id"`
	Holder  string `json:"holder"`
	Version uint64 `json:"version"`
}

func (d *drwaHookStateAdapter) GetTokenPolicyVersion(tokenID string) (uint64, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(systemAccount, buildDRWATokenPolicyKey([]byte(tokenID)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetAssetRecordVersion(tokenID string) (uint64, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(systemAccount, buildDRWAAssetRecordKey([]byte(tokenID)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetHolderMirrorVersion(tokenID, holder string) (uint64, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(holderAccount, buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetHolderProfileVersion(holder string) (uint64, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(holderAccount, buildDRWAHolderProfileKey([]byte(holder)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetHolderAuditorAuthorizationVersion(tokenID, holder string) (uint64, error) {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return 0, err
	}

	storedValue, err := d.readStoredValue(holderAccount, buildDRWAHolderAuditorAuthorizationKey([]byte(tokenID), []byte(holder)))
	if err != nil || storedValue == nil {
		return 0, err
	}

	return storedValue.Version, nil
}

func (d *drwaHookStateAdapter) GetAuthorizedCallerAddress(domain string) ([]byte, error) {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return nil, err
	}

	value, _, err := systemAccount.AccountDataHandler().RetrieveValue(buildDRWAAuthorizedCallerKey(domain))
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	return append([]byte(nil), value...), nil
}

func (d *drwaHookStateAdapter) PutAuthorizedCallerAddress(domain string, address []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWAAuthorizedCallerKey(domain), append([]byte(nil), address...))
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

func (d *drwaHookStateAdapter) PutTokenPolicyBody(tokenID string, version uint64, body []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.writeStoredValue(systemAccount, buildDRWATokenPolicyKey([]byte(tokenID)), version, body)
}

func (d *drwaHookStateAdapter) PutAssetRecordBody(tokenID string, version uint64, body []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.writeStoredValue(systemAccount, buildDRWAAssetRecordKey([]byte(tokenID)), version, body)
}

func (d *drwaHookStateAdapter) PutHolderMirrorBody(tokenID, holder string, version uint64, body []byte) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	return d.writeStoredValue(holderAccount, buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)), version, body)
}

func (d *drwaHookStateAdapter) PutHolderProfileBody(holder string, version uint64, body []byte) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	return d.writeStoredValue(holderAccount, buildDRWAHolderProfileKey([]byte(holder)), version, body)
}

func (d *drwaHookStateAdapter) PutHolderAuditorAuthorizationBody(tokenID, holder string, version uint64, body []byte) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	return d.writeStoredValue(
		holderAccount,
		buildDRWAHolderAuditorAuthorizationKey([]byte(tokenID), []byte(holder)),
		version,
		body,
	)
}

func (d *drwaHookStateAdapter) DeleteHolderMirror(tokenID, holder string, version uint64) error {
	holderAccount, err := d.getUserAccount([]byte(holder))
	if err != nil {
		return err
	}

	// Write tombstone as JSON (same format as writeStoredValue) with nil body.
	// Previous implementation wrote raw 8-byte big-endian which caused json.Unmarshal
	// failures in readStoredValue, permanently blocking re-enrollment and recovery.
	// The tombstone preserves the version so re-enrollment via version 1 is rejected
	// by validateDRWASyncVersion (requires nextVersion == currentVersion + 1).
	tombstonePayload, jsonErr := json.Marshal(&drwaSyncStoredValue{
		Version: version,
		Body:    nil,
	})
	if jsonErr != nil {
		return jsonErr
	}
	err = holderAccount.AccountDataHandler().SaveKeyValue(buildDRWAHolderMirrorKey([]byte(tokenID), []byte(holder)), tombstonePayload)
	if err != nil {
		return err
	}

	err = d.accounts.SaveAccount(holderAccount)
	if err != nil {
		return err
	}

	return d.persistHolderDeleteAudit(tokenID, holder, version)
}

func (d *drwaHookStateAdapter) PersistRecoveryEvidence(tokenID string, payload []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.persistArtifact(systemAccount, buildDRWARecoveryEvidenceKey([]byte(tokenID)), buildDRWARecoveryEvidenceHistoryKey, tokenID, payload)
}

func (d *drwaHookStateAdapter) PersistRolloutEvidence(tokenID string, payload []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.persistArtifact(systemAccount, buildDRWARolloutEvidenceKey([]byte(tokenID)), buildDRWARolloutEvidenceHistoryKey, tokenID, payload)
}

func (d *drwaHookStateAdapter) PersistRolloutVerification(tokenID string, payload []byte) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	return d.persistArtifact(systemAccount, buildDRWARolloutVerificationKey([]byte(tokenID)), buildDRWARolloutVerificationHistoryKey, tokenID, payload)
}

func (d *drwaHookStateAdapter) Snapshot() int {
	return d.accounts.JournalLen()
}

func (d *drwaHookStateAdapter) Rollback(snapshot int) error {
	return d.accounts.RevertToSnapshot(snapshot)
}

func (d *drwaHookStateAdapter) readStoredValue(account vmcommon.UserAccountHandler, key []byte) (*drwaSyncStoredValue, error) {
	value, _, err := account.AccountDataHandler().RetrieveValue(key)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}

	storedValue := &drwaSyncStoredValue{}
	err = json.Unmarshal(value, storedValue)
	if err != nil {
		// Backward-compat: handle legacy 8-byte binary tombstones written
		// before the JSON tombstone fix. These are big-endian uint64 version with nil body.
		if len(value) == 8 {
			ver := uint64(value[0])<<56 | uint64(value[1])<<48 | uint64(value[2])<<40 |
				uint64(value[3])<<32 | uint64(value[4])<<24 | uint64(value[5])<<16 |
				uint64(value[6])<<8 | uint64(value[7])
			return &drwaSyncStoredValue{Version: ver, Body: nil}, nil
		}
		return nil, err
	}

	return storedValue, nil
}

func (d *drwaHookStateAdapter) writeStoredValue(account vmcommon.UserAccountHandler, key []byte, version uint64, body []byte) error {
	payload, err := json.Marshal(&drwaSyncStoredValue{
		Version: version,
		Body:    body,
	})
	if err != nil {
		return err
	}

	err = account.AccountDataHandler().SaveKeyValue(key, payload)
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(account)
}

func (d *drwaHookStateAdapter) getUserAccount(address []byte) (vmcommon.UserAccountHandler, error) {
	accountHandler, err := d.accounts.LoadAccount(address)
	if err != nil {
		return nil, err
	}

	userAccount, ok := accountHandler.(vmcommon.UserAccountHandler)
	if !ok {
		return nil, process.ErrWrongTypeAssertion
	}

	return userAccount, nil
}

func (d *drwaHookStateAdapter) persistArtifact(
	systemAccount vmcommon.UserAccountHandler,
	latestKey []byte,
	historyKeyBuilder func([]byte, []byte) []byte,
	tokenID string,
	payload []byte,
) error {
	payloadCopy := append([]byte(nil), payload...)
	payloadHash := keccak.NewKeccak().Compute(string(payloadCopy))

	// Known limitation: the in-memory account is partially mutated if the second SaveKeyValue fails.
	// The trie commit (SaveAccount) is not reached, so persistent state is not affected.
	err := systemAccount.AccountDataHandler().SaveKeyValue(latestKey, payloadCopy)
	if err != nil {
		return err
	}

	err = systemAccount.AccountDataHandler().SaveKeyValue(historyKeyBuilder([]byte(tokenID), payloadHash), payloadCopy)
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}

func (d *drwaHookStateAdapter) persistHolderDeleteAudit(tokenID, holder string, version uint64) error {
	systemAccount, err := d.getUserAccount(core.SystemAccountAddress)
	if err != nil {
		return err
	}

	payload, err := json.Marshal(&drwaDeleteAuditRecord{
		TokenID: tokenID,
		Holder:  holder,
		Version: version,
	})
	if err != nil {
		return err
	}

	err = systemAccount.AccountDataHandler().SaveKeyValue(buildDRWAHolderDeleteAuditKey([]byte(tokenID), []byte(holder), version), payload)
	if err != nil {
		return err
	}

	return d.accounts.SaveAccount(systemAccount)
}
