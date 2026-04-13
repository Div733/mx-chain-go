# Change Audit Report Template (Junior Developer Edition)

**Auditor:** [Name]  
**Developer:** [Name]  
**Date:** [YYYY-MM-DD]

---

## 1. Change Scope
*   **What this means:** Define exactly where the code was changed and what "type" of work it was.
*   **Repository:** [e.g., mx-chain-go / mrv-platform]
*   **Feature/Domain:** [e.g., RWA / MRV / Core]
*   **Files Changed:** [List primary files]
*   **Change Type:** [Feature / Bug Fix / Cleanup]

> [!NOTE]
> **"State"** = Any stored data that stays in the system (database, contract storage, or variables that don't disappear when a function ends).

*   **Guiding Question:** Does this change create brand new stored data (State), or does it only update data that was already there?
*   *Example: "This adds a new `kyc_status` field to the User database table."*

---

## 2. Impacted System Flow
*   **What this means:** Every piece of data has a "path" it follows from the moment it enters the system until it is finished.
*   **Flow Name:** [e.g., User Login Flow]
*   **Entry Point:** [Where the data starts, e.g., `POST /login` API]
*   **Exit Point:** [Where the data ends, e.g., `Database: save_session()`]
*   **Short Description:** [2-3 sentences max]

> [!NOTE]
> **"Flow"** = The step-by-step path that data takes through the code.

*   **Guiding Question:** If you follow a piece of data from the start to the end of this change, what is the most complicated thing that happens to it?
*   *Example: "The data enters as a password string, gets hashed by Argon2, and ends as a stored hash in the DB."*

---

## 3. Invariant Analysis
*   **What this means:** A system "rule" that must never, ever be broken, no matter what.
*   **Relevant System Invariants:** [List the rules involved]
*   **Are invariants affected?** [Yes / No]
*   **Correctness Rationale:** [If Yes: How does your code prevent the rule from breaking?]

> [!NOTE]
> **"Invariant"** = A permanent rule that must never break (e.g., "A user cannot send more tokens than they have").

*   **Guiding Question:** What is the one major rule this system must never break? How does your code specifically make sure that rule stays safe?
*   *Example: "The rule is: `Total Credits Issued <= Verified Carbon`. My code adds a check to see if `amount_to_issue` is greater than `remaining_balance` before minting."*

---

## 4. Change Explanation
*   **What this means:** A "Before vs. After" comparison so the team knows why this work was done.
*   **Behavior BEFORE:** [What the system did before this PR]
*   **Behavior AFTER:** [What the system does now]
*   **Rationale:** [Why is the new way better?]

*   **Guiding Question:** Can you explain why this change is necessary without just saying "it's better"? What was actually wrong or missing?
*   *Example: "BEFORE: The system didn't check for expired KYC. AFTER: It now blocks transfers if `kyc_expiry` is in the past."*

---

## 5. Failure & Risk Analysis
*   **What this means:** Thinking about what might break if something goes wrong.
*   **Failure Modes:** [What's the first thing that will break if you give it bad input?]
*   **Edge Cases:** [e.g., input is zero, input is null, network is down]
*   **Silent Failure Risk:** [Can this fail without anyone getting an error message?]
*   **Risk Level:** [Low / Medium / High]

> [!NOTE]
> **"Edge Case"** = An unusual or extreme input (e.g., a withdrawal of $0.00001 or $100 Billion).  
> **"Silent Failure"** = The code stops working or does the wrong thing, but no error message or alert is sent.

*   **Guiding Question:** If the database goes offline or a user enters a negative number, what will the user see on their screen?
*   *Example: "If the API returns an error, the screen will just stay white (Silent Failure). I need to add an error message."*

---

## 6. Test Analysis
*   **What this means:** Proving that the code actually works as intended.
*   **Automated Coverage:** [Which tests did you run?]
*   **Uncovered Areas:** [Which parts of the code are NOT tested?]
*   **Manual Verification:** [Did you test it yourself in the browser or terminal?]

*   **Guiding Question:** How did you prove to yourself that the "Behavior BEFORE" mentioned in Section 4 is truly gone?
*   *Example: "I ran `npm test`. I didn't test what happens when the session expires mid-transfer."*

---

## 7. Cross-System Impact (Integrated Check)
*   **What this means:** Checking if a change in one place breaks something else somewhere else.
*   **Downstream Affects:** [Does this change the data format that other services expect?]
*   **Dependency Assumptions:** [Does this require a specific version of another repo?]

*   **Guiding Question:** If you deploy this code right now, will the other parts of the system (like the Mobile App or the Go Node) still understand the data you are sending?
*   *Example: "The Go Node expects the date as `YYYY-MM-DD`, but I changed it to `ISO-8601`. I need to update the Go Node too."*

---

## 8. Final Decision
*   **Status:** [APPROVE / REJECT / HOLD]
*   **Reasoning:** [Why did you make this choice?]

*   **Guiding Question:** Are you confident enough in this change that you would be willing to stay awake to fix it if it breaks tonight?
*   *Example: "REJECT: Missing edge case handling for negative amounts in Section 5."*
