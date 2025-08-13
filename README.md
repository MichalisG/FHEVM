README (drop into your repo)
Overview
This project shows a privacy-preserving social recovery mechanism for secrets using Zama’s fhEVM. The secret (a 32-byte private key) is stored on-chain as an encrypted euint256. Guardians run n-out-of-m approvals; when the threshold is met, the contract grants decrypt rights to the selected recovery address via fhEVM ACL.

Ciphertext storage & compute: euint256

Certified inputs: einput + inputProof → TFHE.asEuint256(...)

ACL to decrypt: TFHE.allow(ciphertext, address) (persistent)
References: ACL & allow/allowTransient, certified input patterns, decryption details. 
zama.ai
Zama Documentation
+1
Zama Documentation
+1
docs.z1labs.ai

Prereqs
Node 18+, pnpm or yarn

Hardhat

fhEVM dev tooling:

Install @fhevm/solidity (or use the fhEVM Hardhat template)

Run against an fhEVM-enabled local chain or testnet (Zama provides templates/gateway) 
Zama Documentation
npm

bash
Copy
pnpm add -D hardhat @nomicfoundation/hardhat-toolbox
pnpm add @fhevm/solidity @openzeppelin/contracts
Import path used by examples: import "fhevm/lib/TFHE.sol";
If you use the npm package, ensure your Hardhat remappings (or paths) resolve fhevm/lib/TFHE.sol. Zama’s examples follow this layout. 
zama.ai

Files
css
Copy
contracts/SecretSocialRecovery.sol
scripts/01-deploy.ts
scripts/02-flow.ts
hardhat.config.ts (sketch)
Point to your fhEVM chain RPC + accounts. If using Zama’s template/devnet, copy its config and add this contract. 
Zama Documentation

Minimal test flow
This is a straight-line demo of: store secret → guardians approve → recovery decrypts.

Note: “decrypt” happens off-chain using fhEVM’s client SDK + the chain’s gateway / KMS. The chain grants permission via TFHE.allow; the recovery address then calls the SDK to decrypt the ciphertext they have access to. 
Zama Documentation
zama.ai

1) Deploy
ts
Copy
// scripts/01-deploy.ts
import { ethers } from "hardhat";

async function main() {
  const [deployer, g1, g2, g3] = await ethers.getSigners();
  const guardians = [g1.address, g2.address, g3.address];
  const threshold = 2;

  const Factory = await ethers.getContractFactory("SecretSocialRecovery");
  const c = await Factory.deploy(guardians, threshold, deployer.address);
  await c.waitForDeployment();

  console.log("Contract:", await c.getAddress());
}

main().catch((e) => { console.error(e); process.exit(1); });
2) Store the secret (encrypted)
Use fhevm-js (or the SDK your chain exposes) to:

encrypt your 32-byte key (Uint8Array → bigint) to an einput

produce an inputProof

submit to storeSecret(encryptedKey, proof)

In pseudocode (SDKs vary slightly by chain):

ts
Copy
// scripts/02-flow.ts (excerpt)
import { ethers } from "hardhat";
// import { encrypt, proveInput } from "fhevm-js"; // adjust to your SDK

// const secretHex = "0x<32 bytes>";
// const secretBig = BigInt(secretHex);
// const { einput, proof } = await encryptAndProve(secretBig);

const c = await ethers.getContractAt("SecretSocialRecovery", process.env.CONTRACT!);

// owner stores ciphertext
// await c.storeSecret(einput, proof);
The pattern matches fhEVM’s “certified input → TFHE.asEuint* inside the contract”, as shown in Zama docs/excerpts. 
docs.z1labs.ai
zama.ai

3) Guardians propose + approve
ts
Copy
// propose (guardian or owner)
await c.connect(g1).propose(recovery.address);

// approvals
await c.connect(g1).approve();
await c.connect(g2).approve();
// threshold reached → contract calls TFHE.allow(ciphertext, recovery)
ACL calls grant persistent decrypt rights to recovery. If you prefer one-shot sessions, you could use TFHE.allowTransient, but this project intentionally does not (multiple off-chain decrypts allowed). 
Zama Documentation
zama.ai

4) Recovery decrypts (off-chain)
With permission in place, recovery can use the SDK to request decryption of the stored ciphertext handled by the fhEVM gateway/KMS. Exact code depends on the SDK/network, but the flow follows Zama’s “decryption in depth” guide. 
Zama Documentation

Gas & structure notes
Bitmap approvals: uint256 bitmap → O(1) duplicate checks and storage frugality.

Single active request: keeps storage simple; creating a new proposal resets the pending one.

m ≤ 256: enforced once; threshold validated at deploy time.

Chunking option: if you ever want different key sizes, store [euint64;4] (or euint8[32]) and allow() each chunk to the recovery address.

Security considerations

The contract never sees plaintext; the fhEVM gateway validates certified inputs (einput + proof) and decryption permissions. Don’t try to “read the key” on-chain—there’s no API to do that. 
Zama Documentation

Approver privacy: approvals are transactions, so the set of approvers is visible (the values aren’t).

Revocation: you can add an owner-only helper to re-propose a new recovery at any time (already supported), and optionally add a time-boxed validity to current (check createdAt).

Operational grant: grantDecrypt() is provided for break-glass or custodial setups.


