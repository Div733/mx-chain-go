# Security Audit Report — mx-chain-go-NewArc

**Scope:** Full repository audit  
**Confirmed real findings fixed:** 2  
**Confirmed real findings open:** 0

---

## Summary

| ID | File | Severity | Class | Status |
|---|---|---|---|---|
| FINDING-1 | `sharding/nodesCoordinator/indexHashedNodesCoordinator.go` — `GetValidatorsIndexes` | High | Nil pointer dereference via TOCTOU race | ✅ Fixed |
| FINDING-2 | `process/block/baseProcess.go` — `saveIntermediateTxs` | Info | Silent no-op on type assertion failure | ✅ Fixed |
| FINDING-3 | `consensus/spos/worker.go` — `DisplayStatistics` | High | Index out of range panic kills consensus worker | ✅ False Positive |

---

## FINDING-1 — Nil Pointer Dereference in `GetValidatorsIndexes` ✅ Fixed

### Location
`sharding/nodesCoordinator/indexHashedNodesCoordinator.go` — `GetValidatorsIndexes`, lines 638–668

### What the Bug Was

A TOCTOU race between two separate lock acquisitions:

1. `GetAllEligibleValidatorsPublicKeys(epoch)` acquires `mutNodesConfig.RLock`, reads the epoch entry, then **releases the lock** before returning.
2. A concurrent `EpochStartAction` acquires `mutNodesConfig.Lock` and calls `delete(ihnc.nodesConfig, epoch)` for epochs older than `nodesCoordinatorStoredEpochs = 4`.
3. `GetValidatorsIndexes` then acquires `mutNodesConfig.RLock` a second time and gets `nil` for the now-deleted epoch.
4. `nodesConfig.shardID` on a nil pointer **panics**.

`GetValidatorsIndexes` is called every consensus round, on every block indexed to outport, and on block commit. A panic here takes down the node process entirely. `ShuffleOutForEpoch` already had the correct nil guard — `GetValidatorsIndexes` was the only caller missing it.

```go
// BEFORE — panics if epoch evicted between the two lock acquisitions
ihnc.mutNodesConfig.RLock()
nodesConfig := ihnc.nodesConfig[epoch]
ihnc.mutNodesConfig.RUnlock()

for _, pubKey := range publicKeys {
    for index, value := range validatorsPubKeys[nodesConfig.shardID] {  // PANIC if nodesConfig == nil
```

### Fix Applied

```go
// AFTER
ihnc.mutNodesConfig.RLock()
nodesConfig := ihnc.nodesConfig[epoch]
ihnc.mutNodesConfig.RUnlock()

if nodesConfig == nil {
    return nil, fmt.Errorf("%w epoch=%v", ErrEpochNodesConfigDoesNotExist, epoch)
}
```

### Why It Mattered

Without this fix, any validator node could be crashed remotely by triggering an epoch transition while `GetValidatorsIndexes` is mid-execution — a realistic race on a live network. A crashed validator loses its consensus slot, accrues rating penalties, and risks slashing. At scale, coordinated crashes across multiple validators could degrade or halt consensus.

**File changed:** `sharding/nodesCoordinator/indexHashedNodesCoordinator.go`

---

## FINDING-2 — Silent No-op on Type Assertion Failure in `saveIntermediateTxs` ✅ Fixed

### Location
`process/block/baseProcess.go` — `saveIntermediateTxs`, lines 3296–3315

### What the Bug Was

When the type assertion on the cached intermediate transactions failed, the function logged a warning but continued with a nil map. `range` over a nil map is a no-op in Go, so the function returned `nil` (success) without saving anything. The caller (`saveExecutedData`) received no error and proceeded as if the save had succeeded — a broken function contract that silently dropped intermediate transaction data.

```go
// BEFORE — silent no-op, returns nil (success) without saving anything
cachedIntermediateTxsMap, ok := cachedIntermediateTxs.(map[block.Type]map[string]data.TransactionHandler)
if !ok {
    log.Warn("saveIntermediateTxs: intermediateTxs cannot cast to concrete type", "hash", headerHash)
    // no return — falls through with nil map, range is a no-op, returns nil
}
```

### Fix Applied

```go
// AFTER — explicit error returned
cachedIntermediateTxsMap, ok := cachedIntermediateTxs.(map[block.Type]map[string]data.TransactionHandler)
if !ok {
    return fmt.Errorf("%w: intermediate txs for header %s cannot cast to concrete type",
        process.ErrWrongTypeAssertion, hex.EncodeToString(headerHash))
}
```

### Why It Mattered

Intermediate transactions (SCRs, reward txs) that fail to persist are lost silently. The block commit path believes the save succeeded, so no retry or recovery is triggered. This can lead to state inconsistency between nodes — one node missing intermediate tx records that others have — which breaks state root agreement and can cause a node to fork off the canonical chain.

**File changed:** `process/block/baseProcess.go`

---

---

## FINDING-3 — Index Out of Range in `DisplayStatistics` ✅ False Positive

### Location
`consensus/spos/worker.go` — `DisplayStatistics`

### What Was Suspected

`DisplayStatistics` accesses `consensusMessages[0]` without a length guard, which would panic if the slice were empty.

### Why It Is a False Positive

After full trace of the write path, map entries in `mapDisplayHashConsensusMessage` are exclusively created via `doJobOnMessageWithSignature`:

```go
func (wrk *Worker) doJobOnMessageWithSignature(cnsMsg *consensus.Message, p2pMsg p2p.MessageP2P) {
    wrk.mutDisplayHashConsensusMessage.Lock()
    defer wrk.mutDisplayHashConsensusMessage.Unlock()

    hash := string(cnsMsg.BlockHeaderHash)
    wrk.mapDisplayHashConsensusMessage[hash] = append(wrk.mapDisplayHashConsensusMessage[hash], cnsMsg)
    // cnsMsg is always non-nil here — callers validate it before reaching this point
}
```

Every map entry is created by appending a non-nil `cnsMsg`. There is no code path that inserts an explicit empty slice for any key. Therefore `consensusMessages` will always contain at least one element when the key exists, making `[0]` safe.

**No code change required. No file changed.**

---

## Files Changed

| File | Finding |
|---|---|
| `sharding/nodesCoordinator/indexHashedNodesCoordinator.go` | FINDING-1 |
| `process/block/baseProcess.go` | FINDING-2 |
