// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FHE, euint64, externalEuint64} from "@fhevm/solidity/lib/FHE.sol";
import {SepoliaConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title SecretSocialRecovery
 * @notice A simple social recovery contract that allows guardians to approve recovery of a private key.
 */
contract SecretSocialRecovery is SepoliaConfig, Ownable2Step {

  /// @notice The private key is stored as a 4-element array of 64-bit encrypted integers.
  euint64[4] private _privateKey;
  uint64 public secretVersion;

  /// @notice Guardian addresses (max 256).
  address[] public guardians;

  /// @notice Maps guardian address to 1-based index (0 == not a guardian).
  mapping(address guardian => uint256 index) public guardianIndexMapping;

  /// @notice Number of approvals required to grant decryption rights.
  uint256 public immutable THRESHOLD;

  /// @notice Total number of guardians.
  uint256 public immutable NUM_GUARDIANS;

  // ========= Single active recovery request =========

  /**
   * @dev Storage-packed request:
   * - `bitmap` occupies its own slot.
   * - `proposed` + `createdAt` + `approvals` + `executed` pack together.
   * - `id` sits in a separate slot.
   */
  struct Request {
    /// @notice Bitmap of approvals; bit i indicates guardian i approved (0-based).
    uint256 bitmap;
    /// @notice Candidate address to be granted decrypt rights on threshold.
    address proposed;
    /// @notice Proposal creation timestamp (for UI / auditing).
    uint64 createdAt;
    /// @notice Count of approvals so far (≤ NUM_GUARDIANS).
    uint16 approvals;
    /// @notice Whether this request already granted permissions.
    bool executed;
    /// @notice Monotonic identifier for proposals (increments per new request).
    uint64 id;
  }

  /// @notice Current active recovery request (if any).
  Request public current;

  /// @notice Monotonic counter for proposal IDs.
  uint64 private nonce;

  // ========= Events =========

  /// @notice Emitted when the secret is written (store/rotate).
  /// @param version The new secret version.
  event SecretStored(uint64 version);

  /// @notice Emitted when the recovery request is proposed.
  /// @param id The proposal ID.
  /// @param guardian The guardian who proposed the recovery.
  /// @param recoveryAddress The address to be granted decrypt rights.
  event RecoveryProposed(uint64 id, address indexed guardian, address indexed recoveryAddress);

  /// @notice Emitted when the recovery request is approved.
  /// @param id The proposal ID.
  /// @param guardian The guardian who approved the recovery.
  /// @param approvals The number of approvals so far.
  event RecoveryApproved(uint64 id, address indexed guardian, uint256 approvals);

  /// @notice Emitted when the recovery request is granted.
  /// @param id The proposal ID.
  /// @param recoveryAddress The address to be granted decrypt rights.
  event RecoveryGranted(uint64 id, address indexed recoveryAddress);

  /// @notice Emitted when the secret is rotated.
  /// @param version The new secret version.
  event SecretRotated(uint64 version);

  /// @notice Emitted when the recovery request is reset.
  /// @param id The proposal ID.
  event ResetRecovery(uint64 id);

  // ========= Errors =========

  /// @notice Guardians array must be non-empty.
  error InvalidGuardiansLength();

  /// @notice Max 256 guardians (bitmap uses uint256).
  error TooManyGuardians();

  /// @notice Threshold must be at least 1 and at most the number of guardians.
  error InvalidThreshold();

  /// @notice Invalid proofs.
  error InvalidProofs();

  /// @notice Zero address is not allowed where a valid address is required.
  error ZeroAddress();

  /// @notice Duplicate guardian address detected.
  error GuardianCountMismatch();

  /// @notice The caller is not a guardian.
  error NotAGuardian();

  /// @notice The recovery address is the same as the current proposed recovery address.
  error SameRecovery();

  /// @notice The recovery request has already been executed.
  error RequestAlreadyExecuted();

  /// @notice The request ID is invalid.
  error InvalidRequest();

  /// @notice There is no active recovery request.
  error NoActiveRequest();

  /// @notice The guardian has already approved the recovery request.
  error AlreadyApproved();


  /**
   * @notice Initializes guardians and threshold.
   * @param _guardians Guardian addresses (unique, non-zero). Max 256.
   * @param _threshold Number of approvals required (1.._guardians.length).
   * @param _owner Initial contract owner (Ownable).
   */
  constructor(address[] memory _guardians, uint256 _threshold, address _owner) Ownable(_owner) {
    uint256 len = _guardians.length;
    if (len == 0) revert InvalidGuardiansLength();
    if (_threshold == 0 || _threshold > len) revert InvalidThreshold();
    if (len > 256) revert TooManyGuardians();

    guardians = _guardians;
    for (uint256 i = 0; i < len; ++i) {
      address g = _guardians[i];
      if (g == address(0)) revert ZeroAddress();
      if (guardianIndexMapping[g] != 0) revert GuardianCountMismatch();
      guardianIndexMapping[g] = i + 1;
    }

    THRESHOLD = _threshold;
    NUM_GUARDIANS = len;
  }

  /**
   * @notice Ingests four certified ciphertexts (order-sensitive: chunk 0..3).
   * @dev Converts four certified external ciphertexts into on-chain encrypted chunks,
   *      increments version. Proofs are validated by FHE gateway/precompiles.
   * @param chunks The 4 encrypted secret chunks provided as external ciphertext carriers.
   * @param proofs The corresponding 4 proofs for certified input ingestion.
   */
  function _ingestSecret(externalEuint64[4] memory chunks, bytes[] calldata proofs) internal {
    if (proofs.length != 4) revert InvalidProofs();
    for (uint256 i = 0; i < 4; i++) {
      _privateKey[i] = FHE.fromExternal(chunks[i], proofs[i]);
      FHE.allowThis(_privateKey[i]);
    }
    unchecked { secretVersion++; }
}

  // ========= Secret management =========

  /**
   * @notice Stores (or overwrites) the encrypted secret.
   * @dev Increments `secretVersion` and emits `SecretStored`.
   * @param _secretChunks External ciphertexts for the four chunks.
   * @param _proofs Certified input proofs (one per chunk).
   */
  function storeSecret(externalEuint64[4] memory _secretChunks, bytes[] calldata _proofs) external onlyOwner {
    _ingestSecret(_secretChunks, _proofs);
    emit SecretStored(secretVersion);
  }

  /**
   * @notice Grants persistent decryption rights on the **current** ciphertext to `recoveryAddress`.
   * @dev Uses FHE ACL per chunk. Call again after a rotation if you want rights on the new version.
   * @param recoveryAddress Address to allow.
   */
  function grantDecryptionRights(address recoveryAddress) external onlyOwner {
    if (recoveryAddress == address(0)) revert ZeroAddress();
    for (uint256 i = 0; i < 4; i++) {
      FHE.allow(_privateKey[i], recoveryAddress);
    }
  }

  // ========= Modifiers =========

  /// @dev Restricts caller to registered guardians.
  modifier onlyGuardian() {
    if (guardianIndexMapping[msg.sender] == 0) revert NotAGuardian();
    _;
  }

  // ========= Social recovery flow =========

  /**
   * @notice Propose a recovery address to receive decrypt rights upon threshold approvals.
   * @dev Resets any non-executed pending request.
   * @param recoveryAddress Proposed address to allow on the secret.
   */
  function proposeRecovery(address recoveryAddress) external onlyGuardian {
    if (recoveryAddress == address(0)) revert ZeroAddress();
    if (recoveryAddress == current.proposed && !current.executed) revert SameRecovery();

    if (current.id != 0 && !current.executed) {
      emit ResetRecovery(current.id);
    }

    nonce++;
    current = Request({
      proposed: recoveryAddress,
      approvals: 0,
      bitmap: 0,
      executed: false,
      createdAt: uint64(block.timestamp),
      id: nonce
    });

    emit RecoveryProposed(nonce, msg.sender, recoveryAddress);
  }

  /**
   * @notice Approve the active recovery request.
   * @dev Sets the caller's bit in the approval bitmap; when approvals reach threshold,
   *      grants FHE ACL on all four chunks and marks the request executed.
   * @param id The active request ID (must match `current.id`).
   */
  function approveRecovery(uint64 id) external onlyGuardian {
    if (current.id == 0) revert NoActiveRequest();
    if (id != current.id) revert InvalidRequest();
    if (current.executed) revert RequestAlreadyExecuted();

    uint256 idx0 = guardianIndexMapping[msg.sender] - 1;
    uint256 mask = (1 << idx0);

    if ((current.bitmap & mask) != 0) revert AlreadyApproved();

    current.bitmap |= mask;
    unchecked { current.approvals++; }

    emit RecoveryApproved(id, msg.sender, current.approvals);

    if (current.approvals >= THRESHOLD) {
      for (uint256 i = 0; i < 4; i++) {
        FHE.allow(_privateKey[i], current.proposed);
      }
      current.executed = true;
      emit RecoveryGranted(id, current.proposed);
    }
  }

  /**
   * @notice Rotate (replace) the encrypted secret with new ciphertext.
   * @dev Increments `secretVersion`, clears any active request (to avoid carry-over approvals),
   *      and emits `SecretRotated`.
   * @param _secretChunks External ciphertexts for the four chunks.
   * @param _proofs Certified input proofs (one per chunk).
   */
  function rotateSecret(externalEuint64[4] memory _secretChunks, bytes[] calldata _proofs) external onlyOwner {
    _ingestSecret(_secretChunks, _proofs);

    if (current.id != 0) {
      emit ResetRecovery(current.id);
      delete current;
    }

    emit SecretRotated(secretVersion);
  }

  // ========= Views =========


  /**
   * @notice Return the full encrypted secret (4 chunks).
   * @return out The four encrypted `euint64` chunks.
   */
  function getSecret() external view returns (euint64[4] memory out) {
    out = _privateKey;
  }

  /**
   * @notice Whether an address is a guardian.
   * @param guardian The address to check.
   * @return True if the address is a guardian.
   */
  function isGuardian(address guardian) public view returns (bool) {
    return guardianIndexMapping[guardian] != 0;
  }

  /**
   * @notice Whether the given guardian has already approved the active request.
   * @param guardian Guardian address to check.
   * @return True if approved; false otherwise (or if not a guardian).
   */
  function hasApproved(address guardian) external view returns (bool) {
    uint256 idx = guardianIndexMapping[guardian];
    if (idx == 0) return false;
    return (current.bitmap & (1 << (idx - 1))) != 0;
  }

  /**
   * @notice Return the number of approvals so far.
   * @return The number of approvals so far.
   */
  function approvals() external view returns (uint256) {
    return current.approvals;
  }

  /**
   * @notice Return the proposed recovery address.
   * @return The proposed recovery address.
   */
  function proposedRecovery() external view returns (address) {
    return current.proposed;
  }
}