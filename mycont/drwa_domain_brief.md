# Domain Brief: DRWA (Dharitri Real World Assets)

**Target Audience:** Junior Developers / Security Auditors  
**Focus:** Execution logic, system invariants, and audit surface area

---

## 1. Problem Definition (WHY)
### The Bypass Problem
Standard token standards (like ERC-20 or ESDT) rely on smart contracts to check compliance. However, a malicious or buggy contract can accidentally bypass these checks or be bypassed by low-level calls.

### The DRWA Solution
DRWA moves compliance enforcement **into the Virtual Machine (VM)** layer. 
*   **Enforcement is Mandatory:** Transfers are intercepted by the blockchain node before the smart contract even runs.
*   **Impossible to Bypass:** If the VM says "No," the transaction is killed at the protocol level.
*   **Regulatory Grade:** Provides institutional-grade KYC/AML that is cryptographically tied to the token itself.

---

## 2. Core Concepts
*   **Asset Mirroring:** A "shadow" copy of compliance data (KYC, limits) exists in the shard-local state for instant VM lookups.
*   **Denial Codes (0–11):** A fixed set of 12 reasons why a transfer is blocked (e.g., Code 2 = KYC Required, Code 10 = Jurisdiction Blocked).
*   **Sync Envelopes:** Binary payloads that update the VM's shadow state whenever a registry contract changes (Atomic update).
*   **VM Gate:** The specific piece of Go code that runs on every `transfer` and `processNotifications`.

---

## 3. High-Level System Components
| Component | Responsibility |
| :--- | :--- |
| **VM Enforcement Gate** (`go-core`) | The "Guard." Intercepts transfers and checks the 12 denial codes. |
| **Sync Module** (`go-node`) | The "Bridge." Updates shard-local state based on contract events. |
| **Policy Registry** (Rust SC) | The "Brain." Stores who can hold what and global token pauses. |
| **Identity Registry** (Rust SC) | The "Source." Stores KYC and AML status for every wallet address. |
| **Asset Manager** (Rust SC) | The "Admin." Links a physical asset's metadata to its blockchain token ID. |
| **SDKs** (JS/Go) | The "Tools." Allow apps to simulate transfers to see if they *would* fail. |

---

## 4. Key Flows
### Flow A: Asset Tokenization & Policy Setup
1.  **Input:** Asset metadata + Compliance rules (e.g., "Institutional only").
2.  **Step:** `AssetManager` registers the new Token ID.
3.  **Step:** `PolicyRegistry` defines the 12-rule policy for that Token ID.
4.  **Step:** Contract emits a **Sync Envelope**.
5.  **Step:** VM Sync Module receives the envelope and updates the shard-local shadow state.
6.  **Output:** Token is now "DRWA-Active" and locked behind the VM gate.

### Flow B: Compliant Token Transfer
1.  **Input:** Sender, Receiver, Token ID, Amount.
2.  **Step (VM Gate):** VM looks up the Token Policy in shadow state.
3.  **Step (VM Gate):** VM looks up Sender's identity (KYC/AML) in shadow state.
4.  **Step (VM Gate):** VM looks up Receiver's identity in shadow state.
5.  **Step (Decision):** If any of the 12 codes trigger → **TX REVERT**.
6.  **Output:** Success only if all 12 conditions pass.

---

## 5. Critical Invariants (The "Golden Rules")
1.  **No Bypass:** No ESDT/DCDT transfer can ever occur for a DRWA-enabled token without passing the VM gate.
2.  **State Atomicity:** If a Sync Envelope fails to process, the entire transaction that triggered it **must** revert.
3.  **Consistency:** The shard-local shadow state must always match the Registry Contract state (No "drift").
4.  **Code 0 Priority:** If a token is marked as DRWA-enabled but has **no synced policy**, code 0 (PolicyNotSynced) must block all transfers.
5.  **Immutability:** Once a transfer is denied by the VM, no smart contract "catch" block can override that failure.

---

## 6. Realistic Failure Scenarios
*   **Sync Drift:** A contract updates a KYC status, but the VM doesn't receive the envelope. *Result: A blacklisted user continues to trade.*
*   **Gas Exhaustion:** In a `MultiESDTTransfer`, checking 10 tokens means running the gate 10 times. If gas isn't pre-calculated, the TX fails mid-way.
*   **Rollout Deadlock:** A token is upgraded to DRWA, but the policy isn't synced in the same block. *Result: All users are locked out (Code 0).*
*   **Binary Overflow:** A sync envelope is too large for the Go node to process, causing the shard to stop processing that contract.

---

## 7. Audit Relevance (How to Review)
When reviewing PRs for DRWA, always ask:
*   **"Can this sink the shard?"** Are there any unbounded loops in the Go sync logic?
*   **"Is the mirror up to date?"** If you change a field in the Rust contract, did you update the `Common` library and the Go `drwa_sync_types.go`?
*   **"Does this break the roll-out?"** Is the new denial code backward compatible with old tokens?
*   **"Is the gate cheap?"** Every microsecond added to `drwa.go` slows down the entire blockchain. Keep logic to pure O(1) lookups.
*   **"What happens on Shard Split?"** If the token and the identity are on different shards, does the sync logic handle the cross-shard state correctly?
