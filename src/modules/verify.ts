// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { assert, create, StructError } from 'superstruct'
import { Tree } from '@truestamp/tree'
import { decodeUnsafely, IdV1DecodeUnsafely } from '@truestamp/id'
import { decode as hexDecode } from '@stablelib/hex'
import { decode as base64Decode } from '@stablelib/base64'
import { verify as verifyEd25519 } from '@stablelib/ed25519'

import {
  CanonicalHash,
  Commitment,
  CommitmentStruct,
  CommitProof,
  CommitTransaction,
  CommitmentVerification,
  CommitmentVerificationStruct,
  Item,
  SignedKey,
  VerificationProof,
  VerificationTransaction,
  VerificationTransactionStruct,
  SignedKeys,
  EntropyResponse,
} from './types'

import { canonicalizeAndHashData, getEntropyFromHash, publicKeyMatchesKnownPublicKey, timestampMicrosecondsToISO } from './utils'

import { verifyStellar } from './verifyStellar'

async function doVerification(
  commitment: Commitment,
  keys: SignedKeys | undefined,
  offline = false,
  entropyFromHashFunction: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined = undefined,
): Promise<CommitmentVerification> {
  const { commitmentData, commitmentDataSignatures } = commitment
  const { id, itemData, itemDataSignatures, itemSignals, proofs, transactions } = commitmentData

  // //////////////////////////////////////////////////////////////////////////////
  // Verify Id Validity
  // //////////////////////////////////////////////////////////////////////////////

  // Decode the commitment's Id ('unsafely', since we can't validate HMAC here).
  const decodedId: IdV1DecodeUnsafely = decodeUnsafely({
    id: id,
  })

  // Use this timestamp in the commitsTo field of the commitment verification output
  // as it represents the `submittedAt` timestamp.
  const decodedIdTimestampISO8601: string = timestampMicrosecondsToISO(decodedId.timestamp)

  // //////////////////////////////////////////////////////////////////////////////
  // Verify ItemData Signature(s)
  // //////////////////////////////////////////////////////////////////////////////

  // Canonicalize the Item data for signature verification.
  const canonicalItemDataHash: CanonicalHash = canonicalizeAndHashData(itemData)

  let itemDataSignaturesVerified = true

  // Verify each ed25519 signature.
  for (const sig of itemDataSignatures ?? []) {
    const { publicKey, signature } = sig
    const publicKeyDecoded: Uint8Array = base64Decode(publicKey)
    itemDataSignaturesVerified = verifyEd25519(publicKeyDecoded, canonicalItemDataHash.hash, base64Decode(signature))
  }

  // Create an Array of the itemData hashes collected from each itemData entry
  // to be listed in the hashes that the commitment 'commitsTo'.
  const itemDataHashes: string[] = []
  for (const element of itemData ?? []) {
    const { hash } = element
    if (hash !== undefined) {
      itemDataHashes.push(hash)
    }
  }

  // //////////////////////////////////////////////////////////////////////////////
  // Construct Item Hash to verify against first proof later
  // //////////////////////////////////////////////////////////////////////////////

  const item: Item = {
    itemData: itemData,
    itemDataSignatures: itemDataSignatures,
    itemSignals: itemSignals,
  }

  const canonicalItemHash: CanonicalHash = canonicalizeAndHashData(item)

  // //////////////////////////////////////////////////////////////////////////////
  // Fetch timestamp associated with the item.observableEntropy hash
  // //////////////////////////////////////////////////////////////////////////////

  let observableEntropyCreatedAt: Date | undefined = undefined
  if (!offline && itemSignals?.observableEntropy) {
    let entropy: EntropyResponse | undefined

    if (entropyFromHashFunction) {
      // external fetch function
      entropy = await entropyFromHashFunction(itemSignals?.observableEntropy)
    } else {
      entropy = await getEntropyFromHash(itemSignals?.observableEntropy)
    }

    if (entropy) {
      observableEntropyCreatedAt = new Date(entropy.createdAt)
    }
  }

  // //////////////////////////////////////////////////////////////////////////////
  // Verify CommitmentData Signature(s)
  // //////////////////////////////////////////////////////////////////////////////

  // Canonicalize the Commitment data for signature verification.
  const canonicalCommitmentDataHash: CanonicalHash = canonicalizeAndHashData(commitmentData)

  let commitmentDataSignaturesVerified = false
  let commitmentDataSignaturesVerifiedPublicKey = false

  // Verify each ed25519 signature.
  for (const sig of commitmentDataSignatures) {
    const { publicKey, signature } = sig
    const publicKeyDecoded: Uint8Array = base64Decode(publicKey)
    commitmentDataSignaturesVerified = verifyEd25519(publicKeyDecoded, canonicalCommitmentDataHash.hash, base64Decode(signature))

    // Verify that the public key used for the signature matches one
    // of the known authoritative public keys and is validly self-signed.
    commitmentDataSignaturesVerifiedPublicKey = await publicKeyMatchesKnownPublicKey(publicKeyDecoded, keys, offline)
  }

  // //////////////////////////////////////////////////////////////////////////////
  // Verify Merkle Inclusion Proofs
  // //////////////////////////////////////////////////////////////////////////////

  const verificationProofs: VerificationProof[] = []

  // Verify that each proof is chained correctly and that each
  // is provable using the Merkle tree inclusion proof and Merkle root.
  for (let i = 0; i < proofs.length; i++) {
    const proof: CommitProof = proofs[i]

    // Also accepts an optional 'error' property.
    const vp: VerificationProof = {
      ok: false,
      inputHash: proof.inputHash,
      merkleRoot: proof.merkleRoot,
    }

    // Verify that the inputHash of the first proof matches the
    // canonical hash of the Item data.
    if (i === 0) {
      if (proof.inputHash !== canonicalItemHash.hashHex) {
        vp.error = `Proof [${i}] inputHash '${proof.inputHash}' must match hash of canonical itemData, itemSignatures, itemSignals [${canonicalItemHash.hashHex}]`
        verificationProofs.push(vp)
      }
    }

    // Proof 2..n inputHash must match the Merkle root of the previous proof
    // and must be an independently verifiable proof.
    if (i >= 1) {
      const previousProofIndex = i - 1
      const previousProof: CommitProof = proofs[previousProofIndex]
      if (proof.inputHash !== previousProof.merkleRoot) {
        vp.error = `Proof [${i}] inputHash '${proof.inputHash}' must match previous proof [${previousProofIndex}] merkleRoot '${previousProof.merkleRoot}'`
      }
    }

    if (vp.error) {
      verificationProofs.push(vp)
      continue
    }

    // Verify that the proof is valid for the given data, inclusion proof, and Merkle root.
    try {
      const isTreeVerified = Tree.verify(hexDecode(proof.merkleRoot), proof.inclusionProof, hexDecode(proof.inputHash))
      if (isTreeVerified) {
        vp.ok = true
      } else {
        throw new Error('Tree verification failed')
      }
    } catch (error) {
      if (error instanceof Error) {
        vp.error = `Proof [${i}] failed to verify: ${error.message}`
      } else {
        vp.error = `Proof [${i}] failed to verify`
      }
    }

    verificationProofs.push(vp)
  }

  // Check if the 'verified' attribute is set to true for every transaction.
  const allProofsVerified = verificationProofs.every((v: VerificationProof) => {
    return v.ok
  })

  const proofMerkleRoots: string[] = proofs.map((proof: CommitProof): string => {
    return proof.merkleRoot
  })

  // //////////////////////////////////////////////////////////////////////////////
  // Verify Commitment Transactions
  // //////////////////////////////////////////////////////////////////////////////

  const verificationTransactions: VerificationTransaction[] = []

  for (const merkleRoot of proofMerkleRoots) {
    const transactionsForMerkleRoot: CommitTransaction[] = transactions[merkleRoot] || []

    for (let i = 0; i < transactionsForMerkleRoot.length; i++) {
      try {
        let verificationResult
        switch (transactionsForMerkleRoot[i].intent) {
          case 'xlm':
            if (offline === true) {
              verificationResult = create(
                {
                  ok: true,
                  offline: true,
                  intent: 'xlm',
                  inputHash: transactionsForMerkleRoot[i].inputHash,
                  transactionId: transactionsForMerkleRoot[i].transactionId,
                  blockId: transactionsForMerkleRoot[i].blockId,
                },
                VerificationTransactionStruct,
              )
            } else {
              verificationResult = await verifyStellar(
                transactionsForMerkleRoot[i],
                decodedId.test, // verify against a test network?
              )
            }
            break

          case 'twitter':
            if (offline === true) {
              verificationResult = create(
                {
                  ok: true,
                  offline: true,
                  intent: 'twitter',
                  inputHash: transactionsForMerkleRoot[i].inputHash,
                  transactionId: transactionsForMerkleRoot[i].transactionId,
                  blockId: transactionsForMerkleRoot[i].blockId,
                },
                VerificationTransactionStruct,
              )
            } else {
              // TODO: verify twitter
            }
            break

          case 'btc':
            if (offline === true) {
              verificationResult = create(
                {
                  ok: true,
                  offline: true,
                  intent: 'btc',
                  inputHash: transactionsForMerkleRoot[i].inputHash,
                  transactionId: transactionsForMerkleRoot[i].transactionId,
                  blockId: transactionsForMerkleRoot[i].blockId,
                },
                VerificationTransactionStruct,
              )
            } else {
              // TODO: verify btc
            }
            break

          case 'eth':
            if (offline === true) {
              verificationResult = create(
                {
                  ok: true,
                  offline: true,
                  intent: 'eth',
                  inputHash: transactionsForMerkleRoot[i].inputHash,
                  transactionId: transactionsForMerkleRoot[i].transactionId,
                  blockId: transactionsForMerkleRoot[i].blockId,
                },
                VerificationTransactionStruct,
              )
            } else {
              // TODO: verify eth
            }
            break

          default:
            break
        }

        assert(verificationResult, VerificationTransactionStruct)
        verificationTransactions.push(verificationResult)
      } catch (error) {
        if (error instanceof Error) {
          // Return an error object with the transaction's info and the error message.
          const v: VerificationTransaction = {
            ok: false,
            offline: offline ? true : false,
            intent: transactionsForMerkleRoot[i].intent,
            inputHash: transactionsForMerkleRoot[i].inputHash,
            transactionId: transactionsForMerkleRoot[i].transactionId,
            blockId: transactionsForMerkleRoot[i].blockId,
            error: `Transaction verification for '${transactionsForMerkleRoot[0].intent}' inputHash '${transactionsForMerkleRoot[i].inputHash}' failed : ${error.message}`,
          }
          verificationTransactions.push(v)
        }
      }
    }
  }

  // Check if every transaction was ok, offline or not.
  const allTransactionsVerifiedOrSkipped = verificationTransactions.every((v: VerificationTransaction) => {
    return v.ok
  })

  // Collect all of the timestamps from the verified transactions. The timestamps
  // are retrieved from the transaction's block/ledger.
  const allVerifiedTransactionTimestamps: Date[] = []
  verificationTransactions.forEach(tx => {
    if (tx.timestamp instanceof Date) {
      allVerifiedTransactionTimestamps.push(tx.timestamp)
    }
  })

  // TypeScript forced to add '+' (Unary operator) to each of the Date objects being compared
  // to coerce them to numbers. :-(
  // See : https://github.com/Microsoft/TypeScript/issues/5710
  const allVerifiedTransactionTimestampsSorted: Date[] = allVerifiedTransactionTimestamps.sort((a: Date, b: Date): number => +a - +b)

  // //////////////////////////////////////////////////////////////////////////////
  // Construct Commitment Verification Result
  // //////////////////////////////////////////////////////////////////////////////

  const isVerified: boolean =
    itemDataSignaturesVerified &&
    commitmentDataSignaturesVerified &&
    commitmentDataSignaturesVerifiedPublicKey &&
    allProofsVerified &&
    allTransactionsVerifiedOrSkipped

  const verificationResult: CommitmentVerification = {
    ok: isVerified,
    id: id,
    offline: offline ? true : false,
    testEnv: decodedId.test,
    itemData: {
      hash: canonicalItemDataHash.hashHex,
      signaturesCount: itemDataSignatures ? itemDataSignatures.length : 0,
      signaturesVerified: itemDataSignaturesVerified,
    },
    item: {
      hash: canonicalItemHash.hashHex,
    },
    commitmentData: {
      hash: canonicalCommitmentDataHash.hashHex,
      signaturesCount: commitmentDataSignatures ? commitmentDataSignatures.length : 0,
      signaturesVerified: commitmentDataSignaturesVerified,
      signaturesPublicKeyVerified: commitmentDataSignaturesVerifiedPublicKey,
    },
    proofs: verificationProofs,
    transactions: verificationTransactions,
  }

  // Include the attributes the commitment verifiably commits to only if
  // the commitment is known to be fully verified.
  if (isVerified) {
    verificationResult.commitsTo = {
      hashes: itemDataHashes,
      timestamps: {
        submittedAfter: observableEntropyCreatedAt?.toISOString(),
        submittedAt: decodedIdTimestampISO8601,
        submittedBefore: allVerifiedTransactionTimestampsSorted[0]?.toISOString(),
        submitWindowMilliseconds:
          observableEntropyCreatedAt && allVerifiedTransactionTimestampsSorted[0]
            ? +allVerifiedTransactionTimestampsSorted[0] - +observableEntropyCreatedAt
            : undefined,
      },
    }
  }

  assert(verificationResult, CommitmentVerificationStruct)
  return verificationResult
}

async function verifier(
  commitment: Commitment,
  keys: SignedKeys | undefined,
  offline = false,
  entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined,
): Promise<CommitmentVerification> {
  try {
    // Verify the structure of the incoming commitment and
    // construct a stub response CommitmentStruct if it is invalid.
    assert(commitment, CommitmentStruct)
    return await doVerification(commitment, keys, offline, entropyFromHashFunction)
  } catch (error) {
    const errorStub: CommitmentVerification = {
      ok: false,
      id: commitment.commitmentData.id,
      offline: offline,
    }

    const prefix = 'Commitment invalid :'

    if (error instanceof StructError) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const { key, value, type } = error

      if (value === undefined) {
        errorStub.error = `${prefix} missing attribute '${key as string}'`
      } else if (type === 'never') {
        errorStub.error = `${prefix} unknown attribute '${key as string}'`
      } else {
        errorStub.error = `${prefix} invalid attribute for '${key as string}'`
      }
    } else if (error instanceof Error) {
      errorStub.error = `${prefix} ${error.message}`
    }

    return errorStub
  }
}

/**
 * A function to check if a commitment is valid. If there are any errors,
 * the appropriate 'ok' property will be set to 'false' but no error will be
 * thrown.
 *
 * You can provide a list of signed keys from https://keys.truestamp.com that were
 * previously saved.
 *
 * @param commitment A commitment object to verify.
 * @param options.keys Force use of a set of keys.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to an Object. The top-level `ok` property will be 'true' if the entire proof is verified.
 */
export async function verify(
  commitment: Commitment,
  options: { keys?: SignedKey[]; entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined } = {
    keys: undefined,
    entropyFromHashFunction: undefined,
  },
): Promise<CommitmentVerification> {
  return await verifier(commitment, options.keys, false, options.entropyFromHashFunction)
}

/**
 * Offline version of `verify()`.
 *
 * In offline mode, if no keys are provided, the library will attempt to
 * use a backup copy of the keys stored in this library. These backup keys
 * are not guaranteed to be current, but they are the best available option.
 *
 * In offline mode, the library will **not** attempt to verify transactions
 * against the actual on-chain state. It will only verify that the commitment
 * is internally cryptographically sound. Since it does not have access to the
 * on-chain state, it cannot verify or display a timestamp attested to by
 * any transactions in this commitment. You can still use the transaction
 * information provided to manually (with your eyes) verify the transaction
 * against the on-chain state using, for example, a block explorer.

 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys offline.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to an Object. The top-level `ok` property will be 'true' if the entire proof is verified offline.
 *
 */
export async function verifyUnsafelyOffline(
  commitment: Commitment,
  options: { keys?: SignedKey[]; entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined } = {
    keys: undefined,
    entropyFromHashFunction: undefined,
  },
): Promise<CommitmentVerification> {
  return await verifier(commitment, options.keys, true, options.entropyFromHashFunction)
}

/**
 * Predicate function to check if a commitment is valid and returning true|false. Throws no Errors.
 * @param commitment A commitment object to verify.
 * @param options.keys Force use of a set of keys.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerified(
  commitment: Commitment,
  options: { keys?: SignedKey[]; entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined } = {
    keys: undefined,
    entropyFromHashFunction: undefined,
  },
): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verifier(commitment, options.keys, false, options.entropyFromHashFunction)

    return verification.ok
  } catch (error) {
    return false
  }
}

/**
 * Predicate function to check if a commitment is valid and returning true|false offline. Throws no Errors.
 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys offline.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerifiedUnsafelyOffline(
  commitment: Commitment,
  options: { keys?: SignedKey[]; entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined } = {
    keys: undefined,
    entropyFromHashFunction: undefined,
  },
): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verifier(commitment, options.keys, true, options.entropyFromHashFunction)

    return verification.ok && verification.offline
  } catch (error) {
    return false
  }
}

/**
 * Helper function. Returns nothing if verification is clean, otherwise throws an Error.
 * @param commitment A commitment object to verify.
 * @param keys Force use of a set of keys.
 * @param offline Whether to use offline verification.
 * @param entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to void.
 */
async function asserter(
  commitment: Commitment,
  keys: SignedKeys | undefined,
  offline: boolean,
  entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined,
): Promise<void> {
  const verification: CommitmentVerification = await verifier(commitment, keys, offline, entropyFromHashFunction)

  // The verify() function should always return a commitment and
  // never throw an error. So we just need to check if the commitment
  // is ok and throw if not.
  if (!verification.ok) {
    throw new Error(verification.error)
  }
}

/**
 * Assert that the commitment is valid. If not, throw an Error.
 * @param commitment A commitment object to verify.
 * @param options.keys Force use of a set of keys.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerified(
  commitment: Commitment,
  options: { keys?: SignedKey[]; entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined } = {
    keys: undefined,
    entropyFromHashFunction: undefined,
  },
): Promise<void> {
  await asserter(commitment, options.keys, false, options.entropyFromHashFunction)
}

/**
 * Assert that the commitment is valid offline. If not, throw an Error.
 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys offline.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerifiedUnsafelyOffline(
  commitment: Commitment,
  options: { keys?: SignedKey[]; entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined } = {
    keys: undefined,
    entropyFromHashFunction: undefined,
  },
): Promise<void> {
  await asserter(commitment, options.keys, true, options.entropyFromHashFunction)
}
