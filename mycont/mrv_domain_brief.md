# Domain Brief: MRV (Measurement, Reporting, Verification)

**Target Audience:** Junior Developers / Security Auditors  
**Focus:** System behavior, data integrity, and credit lifecycle audit surface

---

## 1. Problem Definition (WHY)
### The Trust Gap
Carbon credits represent "avoided emissions" or "removed carbon"—things you cannot physically see or touch. This makes the market highly susceptible to fraud, double-counting, and "phantom credits."

### The MRV Solution
MRV provides the **Proof of Carbon** required to mint a credit.
*   **Trustless Verification:** Replaces human-only promises with multi-source data (IoT, Satellite) and cryptographic proof anchoring.
*   **Immutable Evidence:** Every credit is linked to a specific, unique data set that cannot be altered after the fact.
*   **Scientific Integrity:** Uses standardized models (like RothC) to calculate real carbon sequestration instead of using guesses.

---

## 2. Core Concepts
*   **Measurement:** Raw data collection from three sources: **Oracles** (IoT sensors), **Remote Sensing** (Satellite/GIS), and **Field Data** (Lab soil samples via mobile apps).
*   **Verification:** A rigorous audit process where a third party (VVB) validates the data against 8 institutional "Gates" (G1–G8).
*   **Reporting:** The process of capturing a snapshot of all evidence, hashing it, and "anchoring" that hash to the blockchain to prevent future tampering.

---

## 3. High-Level System Components
| Component | Responsibility |
| :--- | :--- |
| **Science Service** (Python) | The "Calculator." Runs soil models (RothC) and calculates uncertainty (VMD0053). |
| **Registry Contract** (Rust) | The "Ledger." Stores methodology, project metadata, and anchors verification reports. |
| **Aggregator Contract** (Rust) | The "Oracle." Reaches quorum across multiple data sources (IoT, satellite, lab). |
| **Carbon-Credit Contract** (Rust) | The "Minter." Manages the issuance, buffer pool deductions, and retirement. |
| **MRV Platform** (TS/Node) | The "Orchestrator." Manages the API gateway, worker queues, and mobile app sync. |

---

## 4. Key Flows
### Flow A: Data Ingestion & Anchoring
1.  **Input:** IoT readings, GPS-tagged photos, or Lab result CSVs.
2.  **Step:** Data is hashed and stored in S3/IPFS.
3.  **Step:** `Aggregator` contract receives a subset of readings + signatures.
4.  **Step:** `Registry` contract captures the final "Report Hash."
5.  **Output:** An anchored, immutable evidence manifest on-chain.

### Flow B: Verification & Issuance
1.  **Input:** Anchored Report + VVB (Auditor) Approval.
2.  **Step:** VVB signs the report via the `attestation` contract.
3.  **Step:** System passes the 8-Gate check (G1: Methodology, G2: Boundaries, G4: Science, etc.).
4.  **Step:** `Carbon-Credit` contract calculates `Net = Gross - Buffer (15%)`.
5.  **Output:** Tokenized Carbon Credits (DCDT) minted to the project holder.

---

## 5. Critical Invariants (The "Golden Rules")
1.  **No Double Issuance:** A single `report_id` can only trigger the `issueCredits` function exactly **once**. Attempting a second issuance must fail.
2.  **Evidence Binding:** The token's metadata must include the `reportHash`. If the token exists, the evidence must be unchangeable.
3.  **Buffer Integrity:** Credits cannot be issued without a mandatory deduction (usually 10–15%) being sent to the `buffer-pool` contract.
4.  **Authorized Minting:** Only the `platform_governance` multi-sig can call the final `issueCredits` endpoint.
5.  **Irreversible Retirement:** Once a credit is burned (retired), it cannot be re-minted or "un-retired."

---

## 6. Failure Scenarios
*   **Data Injection:** An attacker submits fake IoT readings to inflate carbon sequestered. *Prevention: Triple-source oracle quorum (IoT + Satellite + Lab).*
*   **Gate Bypass:** A bug allows issuance even if the Science Service returns high uncertainty (>15%). *Audit: Check the `uncertainty_pass_flag` logic.*
*   **Sync Lag:** The Science Service model completes, but the `Aggregator` hasn't "sealed" yet. *Result: Issuance reverts.*
*   **Double Counting:** A project registered on Verra is re-registered on Dharitri. *Prevention: Unique project boundary (PostGIS) overlap checks.*

---

## 7. Audit Relevance (How to Review)
When reviewing MRV-related changes, focus on:
*   **Precision Errors:** Are we using `BigUint` for carbon quantities? Floating-point math is banned on-chain and risky in Python science models.
*   **Access Control:** Does the `aggregator.submitReading` endpoint verify the sender is a registered IoT device?
*   **Boundary Validation:** When a project boundary is updated, does the system re-verify that it doesn't overlap with existing projects (G5 check)?
*   **Dependency Chains:** If the `Registry` contract is updated, does it break the `Carbon-Credit` contract's ability to verify anchored reports?
*   **Governance Gates:** Ensure that any function changing `social_contribution_pct` or `buffer_pct` requires a multi-sig proposal, not just a single admin key.
