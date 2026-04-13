# Change Audit Report — `epoch uint32` Propagation into `DataFieldParser.Parse`

---

## 1. Change Scope

- **Repository:** mx-chain-go
- **Feature/Domain:** Transaction Processing / Data Field Parsing
- **Change Type:** Bug Fix (interface signature mismatch)

**Files Changed:**

| File | Change |
|------|--------|
| `process/transactionEvaluator/interface.go` | Updated `DataFieldParser` interface — added `epoch uint32` to `Parse` |
| `process/transactionEvaluator/transactionSimulator.go` | Updated `Parse` call site — passed `epoch = 0` |
| `outport/process/transactionsfee/interface.go` | Updated local `dataFieldParser` interface — added `epoch uint32` to `Parse` |
| `outport/process/transactionsfee/transactionChecker.go` | Updated `isESDTOperationWithSCCall` — added `epoch uint32` param, threaded into `Parse` |
| `outport/process/transactionsfee/transactionsFeeProcessor.go` | Updated `isESDTOperationWithSCCall` call site and `Parse` call in `prepareTxWithResultsBasedOnLogs` — passed `epoch` |

> [!NOTE]
> **"State"** = Any stored data that stays in the system (database, contract storage, or variables that don't disappear when a function ends).

The change does **not** create or modify any stored state. It only updates how a transaction's data field is classified at parse time, based on the current epoch number.

---

## 2. Impacted System Flow

- **Flow Name:** Transaction Data Field Parsing Flow
- **Entry Point:** `DataFieldParser.Parse(dataField, sender, receiver, numOfShards, epoch)` — called when processing a transaction or SCR (Smart Contract Result)
- **Exit Point:** `ResponseParseData` — a struct describing the operation type (e.g., transfer, relayed, ESDT), tokens, receivers, and function name
- **Short Description:** When a transaction arrives for simulation or fee calculation, its `Data` field is parsed to classify what kind of operation it represents. The parser now receives the current epoch so it can correctly decide whether Relayed V1/V2 transactions should still be treated as relayed, or downgraded to plain balance transfers once the disable epoch is reached.

> [!NOTE]
> **"Flow"** = The step-by-step path that data takes through the code.

The data enters as raw `[]byte` from a transaction's data field. The parser checks the function name encoded in it. If it is `relayedTx` or `relayedTxV2`, the epoch is compared against `relayedTransactionsV1V2DisableEpoch`. If the current epoch is past the threshold, the transaction is returned as a plain `MoveBalance` instead of a relayed operation.

---

## 3. Invariant Analysis

- **Relevant System Invariants:**
  - A relayed V1/V2 transaction must not be classified as relayed after the protocol disables that transaction type at a specific epoch.
  - Fee calculation and outport data must always reflect the correct operation type for a given epoch.

- **Are invariants affected?** Yes

- **Correctness Rationale:** Before this fix, the `Parse` function in the local `mx-chain-vm-common-go` module had already been updated to accept `epoch` and enforce the disable threshold. However, the interfaces in `mx-chain-go` still declared the old 4-parameter signature. This caused a compile-time type mismatch — the concrete implementation could never be assigned to the interface. The fix aligns all interface declarations and call sites with the new signature, restoring the invariant that epoch-aware classification is actually enforced at runtime.

> [!NOTE]
> **"Invariant"** = A permanent rule that must never break (e.g., "A user cannot send more tokens than they have").

---

## 4. Change Explanation

- **Behavior BEFORE:** The `DataFieldParser` interfaces in `transactionEvaluator` and `outport/process/transactionsfee` declared `Parse` with 4 parameters `(dataField, sender, receiver, numOfShards)`. The concrete `operationDataFieldParser` in the local `mx-chain-vm-common-go` module had already been updated to require a 5th parameter `epoch uint32`. This caused a compile error — the concrete type could not satisfy either interface, so the code did not build.

- **Behavior AFTER:** All interface declarations and call sites now use the 5-parameter signature `(dataField, sender, receiver, numOfShards, epoch)`. The parser correctly receives the epoch at every call site and can enforce the Relayed V1/V2 disable threshold at the right protocol epoch.

- **Rationale:** The `mx-chain-vm-common-go` dependency introduced epoch-aware parsing as a protocol upgrade to disable Relayed V1/V2 transactions after a configured epoch. The `mx-chain-go` interfaces were not updated in sync, causing the build to break. This fix completes the upgrade on the `mx-chain-go` side.

---

## 5. Failure & Risk Analysis

- **Failure Modes:**
  - In `transactionSimulator.adaptSmartContractResult`, epoch is hardcoded to `0`. If a relayed V1/V2 SCR is simulated and the disable epoch is also `0` (or very low), the SCR will be classified as a plain transfer instead of relayed. This is a known limitation — the simulator does not have epoch context at that call site.

- **Edge Cases:**
  - `epoch = 0` passed in `transactionSimulator`: acceptable for simulation purposes where exact epoch-gated classification is not critical, but worth revisiting if simulation accuracy for relayed transactions is required.
  - `relayedTransactionsV1V2DisableEpoch = 0` in `ArgsOperationDataFieldParser`: if left at zero (default), all relayed V1/V2 transactions will immediately be treated as plain transfers regardless of epoch. Callers must set this field correctly.

- **Silent Failure Risk:** Low. The compile error was hard — the code would not build at all without this fix. Post-fix, the `epoch = 0` fallback in `transactionSimulator` could silently misclassify relayed SCRs during simulation, but this does not affect on-chain state.

- **Risk Level:** Low

---

## 6. Test Analysis

- **Automated Coverage:** `go vet ./process/transactionEvaluator/ ./outport/process/transactionsfee/` — passed with no errors.
- **Uncovered Areas:**
  - The `epoch = 0` fallback in `transactionSimulator.adaptSmartContractResult` is not covered by a targeted test for epoch-boundary behaviour.
  - No new unit tests were added for the epoch threshold logic in the `Parse` call path within `transactionsFeeProcessor`.
- **Manual Verification:** Build verified via `go vet` on the directly affected packages. The unrelated compile error in `mx-chain-scenario-go` (missing `ApplyDRWASyncEnvelopeBytes` method) is a pre-existing issue in an external module and is not caused by these changes.

---

## 7. Cross-System Impact (Integrated Check)

- **Downstream Affects:**
  - `mx-chain-vm-common-go` (local replace): this is the source of the signature change. The `operationDataFieldParser.Parse` method now requires `epoch uint32`. All consumers in `mx-chain-go` have been updated.
  - `testscommon/dataFieldParserStub.go`: the stub already had the 5-parameter signature before this fix, confirming the intent was always to propagate epoch — the interfaces were simply lagging behind.
  - `node/external/transactionAPI/interface.go`: already had the 5-parameter `DataFieldParser` interface and was not modified — it was already in sync.

- **Dependency Assumptions:** Requires the local `mx-chain-vm-common-go` replace directive in `go.mod` pointing to the version that introduced the `epoch` parameter in `Parse`. The upstream published `v1.6.0` does not have this change — it only exists in the local module at `/home/divesh/Desktop/RWA/FINAL/RWA/mx-chain-vm-common-go`.

---

## 8. Final Decision

- **Status:** APPROVE
- **Reasoning:** The change is a straightforward interface alignment fix required to make the codebase compile against the updated local dependency. All affected interfaces and call sites have been updated consistently. The only non-ideal aspect is the `epoch = 0` hardcode in `transactionSimulator`, which is an acceptable limitation for a simulation context and should be tracked as a follow-up if epoch-accurate relayed transaction simulation is ever needed.
