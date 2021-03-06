// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { z } from 'zod'
import { Tree } from '@truestamp/tree'
import { decodeUnsafely, IdV1DecodeUnsafely } from '@truestamp/id'
import { decode as hexDecode } from '@stablelib/hex'
import { decode as base64Decode } from '@stablelib/base64'
import { verify as verifyEd25519 } from '@stablelib/ed25519'

import {
  CanonicalHash,
  Commitment,
  CommitmentVerification,
  CommitProof,
  CommitTransaction,
  EntropyResponse,
  Item,
  SignedKey,
  SignedKeys,
  VerificationProof,
  VerificationTransaction,
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
  const decodedId: IdV1DecodeUnsafely = decodeUnsafely({ id: id })

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
      success: false,
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
        vp.success = true
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
    return v.success
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
        const transaction: CommitTransaction = transactionsForMerkleRoot[i]
        let verificationResult

        // discriminate which union type to verify
        switch (transaction.intent) {
          case 'bitcoin':
            if (offline === true) {
              const vt: VerificationTransaction = {
                success: true,
                offline: true,
                intent: transaction.intent,
                transaction: transaction,
              }

              verificationResult = VerificationTransaction.parse(vt)
            } else {
              // TODO: verify bitcoin
            }
            break

          case 'ethereum':
            if (offline === true) {
              const vt: VerificationTransaction = {
                success: true,
                offline: true,
                intent: transaction.intent,
                transaction: transaction,
              }

              verificationResult = VerificationTransaction.parse(vt)
            } else {
              // TODO: verify ethereum
            }
            break

          case 'stellar':
            if (offline === true) {
              const vt: VerificationTransaction = {
                success: true,
                offline: true,
                intent: transaction.intent,
                transaction: transaction,
              }

              verificationResult = VerificationTransaction.parse(vt)
            } else {
              verificationResult = await verifyStellar(
                transaction,
                decodedId.test, // verify against a test network?
              )
            }
            break

          case 'twitter':
            if (offline === true) {
              const vt: VerificationTransaction = {
                success: true,
                offline: true,
                intent: transaction.intent,
                transaction: transaction,
              }

              verificationResult = VerificationTransaction.parse(vt)
            } else {
              // TODO: verify twitter
            }
            break

          default:
            // Ensure exhaustive checking of all union types.
            // See : https://medium.com/@ahsan.ayaz/understanding-discriminated-unions-in-typescript-1ccc0e053cf5
            // eslint-disable-next-line no-case-declarations ,@typescript-eslint/no-unused-vars
            const invalidCommitTransaction: never = transaction
            throw new Error(`Unknown transaction discriminant`)
        }

        verificationTransactions.push(VerificationTransaction.parse(verificationResult))
      } catch (error) {
        if (error instanceof Error) {
          // Return an error object with the transaction's info and the error message.
          const v: VerificationTransaction = {
            success: false,
            offline: offline ? true : false,
            intent: transactionsForMerkleRoot[i].intent,
            transaction: transactionsForMerkleRoot[0],
            error: `Transaction verification for '${transactionsForMerkleRoot[0].intent}' inputHash '${transactionsForMerkleRoot[i].inputHash}' failed : ${error.message}`,
          }
          verificationTransactions.push(v)
        }
      }
    }
  }

  // Check if every transaction was successful, offline or not.
  const allTransactionsVerifiedOrSkipped = verificationTransactions.every((v: VerificationTransaction) => {
    return v.success
  })

  // Collect all of the timestamps from the verified transactions. The timestamps
  // are retrieved from the transaction's block/ledger.
  const allVerifiedTransactionTimestamps: string[] = []
  verificationTransactions.forEach(tx => {
    if (tx.timestamp) {
      allVerifiedTransactionTimestamps.push(tx.timestamp)
    }
  })

  // Check if the timestamps are in ascending order. Need to convert them to Date objects for proper comparison.
  // String comparison is not enough, as the timestamps are in ISO 8601 format and may have differing end-of-string forms.
  // TypeScript forced to add '+' (Unary operator) to each of the Date objects being compared to coerce them to numbers. :-(
  // See : https://github.com/Microsoft/TypeScript/issues/5710
  const allVerifiedTransactionTimestampsSorted: string[] = allVerifiedTransactionTimestamps.sort((a: string, b: string): number => +new Date(a) - +new Date(b))

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
    success: isVerified,
    id: id,
    offline: offline ? true : false,
    testnet: decodedId.test,
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
      observableEntropy: observableEntropyCreatedAt ? item.itemSignals?.observableEntropy : undefined,
      timestamps: {
        submittedAfter: observableEntropyCreatedAt?.toISOString(),
        submittedAt: decodedIdTimestampISO8601,
        submittedBefore: allVerifiedTransactionTimestampsSorted[0],
        submitWindowMilliseconds:
          observableEntropyCreatedAt && allVerifiedTransactionTimestampsSorted[0]
            ? +new Date(allVerifiedTransactionTimestampsSorted[0]) - +new Date(observableEntropyCreatedAt)
            : undefined,
      },
    }
  }

  return CommitmentVerification.parse(verificationResult)
}

async function verifier(
  commitment: Commitment,
  keys: SignedKeys | undefined,
  offline = false,
  entropyFromHashFunction?: ((hash: string) => Promise<EntropyResponse | undefined>) | undefined,
): Promise<CommitmentVerification> {
  try {
    // Verify the structure of the incoming Commitment and
    // construct a stub response CommitmentStruct if it is invalid.
    Commitment.parse(commitment)
    return await doVerification(commitment, keys, offline, entropyFromHashFunction)
  } catch (error) {
    const errorStub: CommitmentVerification = {
      success: false,
      id: commitment.commitmentData.id,
      offline: offline,
    }

    const prefix = 'Commitment invalid :'

    if (error instanceof z.ZodError) {
      const joinedIssues: string = error.issues
        .map((issue: z.ZodIssue) => {
          return `${issue.code} : [${issue.path.join(', ')}] : ${issue.message}`
        })
        .join('; ')
      errorStub.error = `${prefix} ${joinedIssues}`
    } else if (error instanceof Error) {
      errorStub.error = `${prefix} ${error.message}`
    }

    return errorStub
  }
}

/**
 * A function to check if a commitment is valid. If there are any errors,
 * the appropriate 'success' property will be set to 'false' but no error will be
 * thrown.
 *
 * You can provide a list of signed keys from https://keys.truestamp.com that were
 * previously saved.
 *
 * @param commitment A commitment object to verify.
 * @param options.keys Force use of a set of keys.
 * @param options.entropyFromHashFunction A function that returns the entropy for a given hash. Useful to pass when using Cloudflare workers service bindings.
 * @returns A promise that resolves to an Object. The top-level `success` property will be 'true' if the entire proof is verified.
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
 * @returns A promise that resolves to an Object. The top-level `success` property will be 'true' if the entire proof is verified offline.
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

    return verification.success
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

    return verification.success && verification.offline
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
  // is successful and throw if not.
  if (!verification.success) {
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
