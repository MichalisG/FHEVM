# SecretSocialRecovery

A Solidity contract for **secure encrypted secret storage** with **social recovery** using [Zama's fhEVM](https://github.com/zama-ai/fhevm).

---

## Features
- **Encrypted Secret Storage** – Stores secret in 4 × `euint64` chunks.
- **Guardian-based Recovery** – Trusted guardians approve recovery addresses.
- **Threshold Approvals** – Recovery granted only when enough guardians approve.
- **Secret Rotation** – Replace secret and reset pending recovery requests.
- **FHE ACL Control** – Access rights managed securely via fhEVM.

---

## Basic Flow
1. **Owner stores secret** (encrypted off-chain into 4 chunks + proofs).
2. **Guardian proposes recovery** address.
3. **Other guardians approve** until `THRESHOLD` reached.
4. **Recovery address granted decrypt rights** via FHE ACL.
5. **Recovery address decrypts off-chain**.

---

## Key Functions
- `storeSecret(chunks, proofs)` → Store/overwrite secret.
- `rotateSecret(chunks, proofs)` → Replace secret & reset recovery.
- `grantDecryptionRights(addr)` → Manually grant access.
- `proposeRecovery(addr)` → Guardian proposes recovery address.
- `approveRecovery(id)` → Guardian approves recovery request.

---

## Events
- `SecretStored`, `SecretRotated`
- `RecoveryProposed`, `RecoveryApproved`, `RecoveryGranted`
- `ResetRecovery`

---

## Security
- Secrets remain **encrypted** on-chain.
- Only FHE ACL-approved addresses can decrypt.
- Max 256 guardians, threshold enforced.

---

**License:** MIT © 2025
