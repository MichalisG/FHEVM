import {expect} from "chai";
import {ethers, fhevm} from "hardhat";
import {HardhatEthersSigner} from "@nomicfoundation/hardhat-ethers/signers";
import {FhevmType} from "@fhevm/hardhat-plugin";
import {
  SecretSocialRecovery,
  SecretSocialRecovery__factory
} from "../types";

type Signers = {
  owner: HardhatEthersSigner;
  guardian1: HardhatEthersSigner;
  guardian2: HardhatEthersSigner;
  guardian3: HardhatEthersSigner;
  recovery: HardhatEthersSigner;
};

const examplePrivKey =
  "0x0123456789abcdeffedcba9876543210ffeeddccbbaa99887766554433221100";


async function deployFixture(threshold = 2) {
  const [owner, guardian1, guardian2, guardian3, recovery] = await ethers.getSigners();

  const guardians = [guardian1.address, guardian2.address, guardian3.address];
  const Factory = (await ethers.getContractFactory(
    "SecretSocialRecovery"
  )) as SecretSocialRecovery__factory;

  const contract = (await Factory.deploy(guardians, threshold, owner.address)) as SecretSocialRecovery;
  const addr = await contract.getAddress();

  return {contract, addr, owner, guardian1, guardian2, guardian3, recovery};
}


/**
 * Split a 32-byte private key into 4 x 64-bit unsigned integers (big-endian).
 * Example: 0x[ 8B ][ 8B ][ 8B ][ 8B ]  -> [chunk0, chunk1, chunk2, chunk3]
 */
function chunkPrivateKeyToUint64BE(privKeyHex: string): bigint[] {
  let hex = privKeyHex.toLowerCase();
  if(hex.startsWith("0x")) hex = hex.slice(2);
  if(hex.length > 64) throw new Error("Private key longer than 32 bytes");
  // left-pad to 32 bytes
  hex = hex.padStart(64, "0");

  const chunks: bigint[] = [];
  for(let i = 0; i < 4; i++) {
    const start = i * 16;         // 16 hex chars == 8 bytes
    const end = start + 16;
    const slice = hex.slice(start, end);
    chunks.push(BigInt("0x" + slice));
  }
  return chunks;
}

function assemblePrivateKeyFromUint64BE(chunks: bigint[]): string {
  let hex = "";
  for(const chunk of chunks) {
    hex += chunk.toString(16).padStart(16, "0");
  }
  return "0x" + hex;
}

async function encrypt64Chunk(
  contractAddress: string,
  sender: HardhatEthersSigner,
  clearValue: bigint | number
) {
  const builder = fhevm.createEncryptedInput(contractAddress, sender.address);
  const enc = await builder.add64(typeof clearValue === "number" ? BigInt(clearValue) : clearValue).encrypt();
  return {handle: enc.handles[0], proof: enc.inputProof};
}

describe("SecretSocialRecovery", function () {
  let signers: Signers;
  let contract: SecretSocialRecovery;
  let addr: string;

  before(async function () {
    const ethSigners: HardhatEthersSigner[] = await ethers.getSigners();
    signers = {owner: ethSigners[0], guardian1: ethSigners[1], guardian2: ethSigners[2], guardian3: ethSigners[3], recovery: ethSigners[4]};
  });

  beforeEach(async function () {
    if(!fhevm.isMock) {
      console.warn("This Hardhat test suite runs only on fhEVM mock (not on Sepolia).");
      this.skip();
    }

    // 2-of-3 guardians approve → recovery gains decrypt rights for all chunks
    ({contract, addr} = await deployFixture(2));
  });

  it("initial state: empty ciphertext and version == 0", async function () {
    const secret = await contract.getSecret();
    expect(secret[0]).to.eq(ethers.ZeroHash);
    expect(secret[1]).to.eq(ethers.ZeroHash);
    expect(secret[2]).to.eq(ethers.ZeroHash);
    expect(secret[3]).to.eq(ethers.ZeroHash);

    const version = await contract.secretVersion();
    expect(version).to.eq(0);
  });

  it("owner can store secret (4 chunks) → version increments", async function () {
    const clearChunks = chunkPrivateKeyToUint64BE(examplePrivKey);
    const chunks = await Promise.all(clearChunks.map(v => encrypt64Chunk(addr, signers.owner, v)));

    await (await contract.connect(signers.owner).storeSecret(
      [chunks[0].handle, chunks[1].handle, chunks[2].handle, chunks[3].handle],
      [chunks[0].proof, chunks[1].proof, chunks[2].proof, chunks[3].proof]
    )).wait();

    const version = await contract.secretVersion();
    expect(version).to.eq(1);

    const secret = await contract.getSecret();
    secret.forEach(chunk => expect(chunk).to.not.eq(ethers.ZeroHash));
  });

  it("2-of-3 guardians approve → recovery gains decrypt rights for all chunks", async function () {
    const clearChunks = chunkPrivateKeyToUint64BE(examplePrivKey);
    const chunks = await Promise.all(clearChunks.map(v => encrypt64Chunk(addr, signers.owner, v)));
    await (await contract.connect(signers.owner).storeSecret(
      [chunks[0].handle, chunks[1].handle, chunks[2].handle, chunks[3].handle],
      [chunks[0].proof, chunks[1].proof, chunks[2].proof, chunks[3].proof]
    )).wait();

    await (await contract.connect(signers.guardian1).proposeRecovery(signers.recovery.address)).wait();
    await (await contract.connect(signers.guardian1).approveRecovery(1)).wait();
    await (await contract.connect(signers.guardian2).approveRecovery(1)).wait();

    const secret = await contract.getSecret();

    const dec0 = await fhevm.userDecryptEuint(FhevmType.euint64, secret[0], addr, signers.recovery);
    const dec1 = await fhevm.userDecryptEuint(FhevmType.euint64, secret[1], addr, signers.recovery);
    const dec2 = await fhevm.userDecryptEuint(FhevmType.euint64, secret[2], addr, signers.recovery);
    const dec3 = await fhevm.userDecryptEuint(FhevmType.euint64, secret[3], addr, signers.recovery);

    expect(BigInt(dec0)).to.eq(clearChunks[0]);
    expect(BigInt(dec1)).to.eq(clearChunks[1]);
    expect(BigInt(dec2)).to.eq(clearChunks[2]);
    expect(BigInt(dec3)).to.eq(clearChunks[3]);

    const recoveredPrivateKey = assemblePrivateKeyFromUint64BE([dec0, dec1, dec2, dec3]);
    expect(recoveredPrivateKey).to.eq(examplePrivKey);
  });

  it("before approvals, recovery cannot decrypt", async function () {
    const clearChunks = chunkPrivateKeyToUint64BE(examplePrivKey);
    const chunks = await Promise.all(clearChunks.map(v => encrypt64Chunk(addr, signers.owner, v)));
    await (await contract.connect(signers.owner).storeSecret(
      [chunks[0].handle, chunks[1].handle, chunks[2].handle, chunks[3].handle],
      [chunks[0].proof, chunks[1].proof, chunks[2].proof, chunks[3].proof]
    )).wait();

    const secret = await contract.getSecret();
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint64, secret[0], addr, signers.recovery)
    ).to.be.rejected;
  });

  it("rotation increments version, clears pending request, and revokes rights", async function () {
    const clearChunks = chunkPrivateKeyToUint64BE(examplePrivKey);
    const inV1 = await Promise.all(clearChunks.map(v => encrypt64Chunk(addr, signers.owner, v)));
    await (await contract.connect(signers.owner).storeSecret(
      [inV1[0].handle, inV1[1].handle, inV1[2].handle, inV1[3].handle],
      [inV1[0].proof, inV1[1].proof, inV1[2].proof, inV1[3].proof]
    )).wait();

    await (await contract.connect(signers.guardian1).proposeRecovery(signers.recovery.address)).wait();
    await (await contract.connect(signers.guardian1).approveRecovery(1)).wait();
    await (await contract.connect(signers.guardian2).approveRecovery(1)).wait();

    const secretV1 = await contract.getSecret();
    const d0 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV1[0], addr, signers.recovery);
    const d1 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV1[1], addr, signers.recovery);
    const d2 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV1[2], addr, signers.recovery);
    const d3 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV1[3], addr, signers.recovery);

    expect(BigInt(d0)).to.eq(clearChunks[0]);
    expect(BigInt(d1)).to.eq(clearChunks[1]);
    expect(BigInt(d2)).to.eq(clearChunks[2]);
    expect(BigInt(d3)).to.eq(clearChunks[3]);

    const recoveredPrivateKey = assemblePrivateKeyFromUint64BE([d0, d1, d2, d3]);
    expect(recoveredPrivateKey).to.eq(examplePrivKey);

    const inV2 = await Promise.all(clearChunks.map(v => encrypt64Chunk(addr, signers.owner, v)));
    await (await contract.connect(signers.owner).rotateSecret(
      [inV2[0].handle, inV2[1].handle, inV2[2].handle, inV2[3].handle],
      [inV2[0].proof, inV2[1].proof, inV2[2].proof, inV2[3].proof]
    )).wait();

    const version = await contract.secretVersion();
    expect(version).to.eq(2);

    const proposed = await contract.proposedRecovery();
    expect(proposed).to.eq(ethers.ZeroAddress);

    const secretV2 = await contract.getSecret();
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint64, secretV2[0], addr, signers.recovery)
    ).to.be.rejected;

    await (await contract.connect(signers.guardian1).proposeRecovery(signers.recovery.address)).wait();

    // The id has increased to 2 after the second proposeRecovery
    await (await contract.connect(signers.guardian1).approveRecovery(2)).wait();
    await (await contract.connect(signers.guardian2).approveRecovery(2)).wait();

    const d0v2 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV2[0], addr, signers.recovery);
    const d1v2 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV2[1], addr, signers.recovery);
    const d2v2 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV2[2], addr, signers.recovery);
    const d3v2 = await fhevm.userDecryptEuint(FhevmType.euint64, secretV2[3], addr, signers.recovery);

    expect(BigInt(d0v2)).to.eq(clearChunks[0]);
    expect(BigInt(d1v2)).to.eq(clearChunks[1]);
    expect(BigInt(d2v2)).to.eq(clearChunks[2]);
    expect(BigInt(d3v2)).to.eq(clearChunks[3]);

    const recoveredPrivateKeyV2 = assemblePrivateKeyFromUint64BE([d0v2, d1v2, d2v2, d3v2]);
    expect(recoveredPrivateKeyV2).to.eq(examplePrivKey);
  });

  it("hasApproved reflects guardian vote and prevents double-approve", async function () {
    const chunks = [1n, 1n, 1n, 1n];
    const ins = await Promise.all(chunks.map(v => encrypt64Chunk(addr, signers.owner, v)));
    await (await contract.connect(signers.owner).storeSecret(
      [ins[0].handle, ins[1].handle, ins[2].handle, ins[3].handle],
      [ins[0].proof, ins[1].proof, ins[2].proof, ins[3].proof]
    )).wait();

    await (await contract.connect(signers.guardian1).proposeRecovery(signers.recovery.address)).wait();
    expect(await contract.hasApproved(signers.guardian1.address)).to.eq(false);

    await (await contract.connect(signers.guardian1).approveRecovery(1)).wait();
    expect(await contract.hasApproved(signers.guardian1.address)).to.eq(true);

    await expect(contract.connect(signers.guardian1).approveRecovery(1)).to.be.revertedWithCustomError(
      contract,
      "AlreadyApproved"
    );
  });
});
