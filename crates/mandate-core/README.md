# mandate-core

**A human signs a bounded, cart-bound mandate that their AI agent can carry but never forge.**

Two documents, each with its own signer:

| Document | Who writes it | Who signs it | What it says |
|---|---|---|---|
| `IntentMandate` | the agent drafts it | **the human** (passkey in phase 2) | "Agent X may spend ₹500 per order, ₹2,000 in total, at these merchants, until tomorrow" |
| `CartMandate` | the agent | **the agent's own key** | "These exact items, for this total, under that intent" |

`verify_checkout()` is one pure function with no HTTP, no database, and no clock of its own. It refuses the request if any of these is true:

- The human did not approve this exact intent. Changing the cap or adding a merchant afterwards breaks the approval.
- The cart points to a different intent, or was signed by anyone other than that intent's agent.
- The merchant is not in the approved list.
- The cart total does not add up from its items, or the arithmetic overflows.
- The total is over the per-order cap.
- `spent + total` is over the **rupee budget**. The budget counts money, not requests.
- The intent has expired or is not yet valid, or the version or currency is wrong.

Error messages are generic, so a caller can't use them to probe caps, budgets or merchant lists.

## The caller's job
After an `Ok`, claim `cart_nonce` and add the amount to the intent's spent total **in one transaction** (for example, SQLite with a `PRIMARY KEY` on the nonce). That gives replay protection and at-most-once charging.

## Threat model (short)
- **Stolen agent key:** the attacker can sign carts, but only inside an intent the human already approved.
- **Prompt-injected agent:** same limit. It can't raise the cap, add a merchant, or overspend the budget.
- **Compromised server:** it holds only the human's *public* key, so it can't approve anything.
- **Replay:** blocked by the caller's nonce claim.

## Status
Phase 1 of the rebuild. Phase 2 adds a WebAuthn `ApprovalVerifier`, where the passkey challenge is `intent_hash(intent)`.

```bash
cargo test   # 21 tests, one per attack or mistake
```
