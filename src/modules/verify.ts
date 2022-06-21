// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { assert, create, is, StructError } from 'superstruct'
import { sha256, Tree } from '@truestamp/tree'
import { decodeUnsafely, IdV1DecodeUnsafely } from '@truestamp/id'
import { canonify } from '@truestamp/canonify'
import { encode as hexEncode, decode as hexDecode } from '@stablelib/hex'
import { decode as base64Decode } from '@stablelib/base64'
import { verify as verifyEd25519 } from '@stablelib/ed25519'
import { hash as stableSHA256 } from '@stablelib/sha256'
import { equal } from '@stablelib/constant-time'

import {
  CanonicalHash,
  CommitmentData,
  Commitment,
  CommitmentStruct,
  CommitProof,
  CommitTransaction,
  CommitmentVerification,
  CommitmentVerificationStruct,
  Item,
  ItemData,
  SignedKey,
  SignedKeyStruct,
  SignedKeysStruct,
  UnsignedKey,
  VerificationProof,
  VerificationTransaction,
  VerificationTransactionStruct,
  SignedKeys,
} from './types'

import { verifyStellar } from './verifyStellar'

const KEY_SERVER_BASE_URL = 'https://keys.truestamp.com'

// Last updated: 2022-05-24
const BACKUP_PUBLIC_KEYS: SignedKey[] = [
  {
    handle: 'a56faa2b',
    type: 'ed25519',
    publicKey: 'K546EiGp4vsAvvOLYA1m0XKyqc4RoJ+7qPoXZs4Z+NU=',
    environment: 'development',
    expired: false,
    selfSignature: 'Vj0A4kNa2a4tRLxOEPFwV7irNIGUoe7Q8SX1JfkRHeNea9M+3Q3vT+9n640mMJhm2nUIDvbCtmtB2xqGoqpmCQ==',
  },
  {
    handle: 'f36947d3',
    type: 'ed25519',
    publicKey: '2/N8KtnOq46WOvQay/cun/3vin7dYU0jtwliVf6g83s=',
    environment: 'staging',
    expired: false,
    selfSignature: 'lWxD/ujp9UdGkk2MsUUla1oAR3FopK8jCeE4eNfeS6HS/ue6dUk+vhoNI3zUNsGFlNXUzwskET/VtS8i5KgQCA==',
  },
  {
    handle: 'b3395500',
    type: 'ed25519',
    publicKey: 'BnE/2AYhgMd0KY7tXdMfmRJPoPY4I5h7rhQf+9nswAQ=',
    environment: 'production',
    expired: false,
    selfSignature: 'yZG0mJUpeWdaayZMF70bHrBnjIYihmoZoiEbfciGxARvocmLp0JlKXaP5MtQGCd73yqjOHX1aZqHGOPise7fAw==',
  },
]

/**
 * For a given public key, calculate its handle.
 * @param publicKey The public key to calculate the handle for
 * @return The public key's handle
 */
function getHandleForPublicKey(publicKey: Uint8Array): string {
  return hexEncode(sha256(publicKey)).slice(0, 8).toLowerCase()
}

/**
 * Attempt to receive a single key from a public key server identified by a handle.
 * If operating in offline mode, the keys parameter can be used to override the
 * default public keys baked into this library.
 * @param handle The handle of the key to retrieve
 * @param keys An optional array of keys to use when offline.
 * @param offline Whether to attempt to verify the commitment offline.
 * @return The key associated with the handle, or undefined if not found
 */
async function getKeyByHandle(handle: string, keys?: SignedKey[], offline?: boolean): Promise<SignedKey | undefined> {
  // If an array of keys was provided, use them to the exclusion of any other.
  if (is(keys, SignedKeysStruct)) {
    return keys.find((key: SignedKey): boolean => key.handle === handle)
  }

  // No keys were provided for offline, so we'll use the baked public keys
  if (offline) {
    return BACKUP_PUBLIC_KEYS.find((key: SignedKey): boolean => key.handle === handle)
  }

  // Not operating offline, try to fetch the key from the key server
  try {
    const response: Response = await fetch(`${KEY_SERVER_BASE_URL}/${handle}`)

    if (response.ok) {
      const key: SignedKey = create(await response.json(), SignedKeyStruct)
      return is(key, SignedKeyStruct) ? key : undefined
    }

    return undefined
  } catch (error) {
    return undefined
  }
}

/**
 * For a given public key, calculate its handle, look it up on a public key server
 * and verify that the key associated with the handle matches the public key passed in.
 * @param publicKey The public key to verify is authoritatively published
 * @param keys An optional array of keys to use when offline.
 * @param offline Whether to attempt to verify the commitment offline.
 * @return A boolean indicating whether the public key is known and authentic.
 */
async function publicKeyMatchesKnownPublicKey(publicKey: Uint8Array, keys?: SignedKey[], offline?: boolean): Promise<boolean> {
  try {
    const handle = getHandleForPublicKey(publicKey)

    let key: SignedKey | undefined = undefined

    key = await getKeyByHandle(handle, keys, offline)

    if (key === undefined) {
      return false
    }

    const foundPublicKey: Uint8Array = base64Decode(key.publicKey)
    if (!equal(foundPublicKey, publicKey)) {
      return false
    }

    // Ensure that the handle of the found key resolves to match the handle we calculated
    if (handle !== getHandleForPublicKey(foundPublicKey) || handle !== key.handle) {
      return false
    }

    // Verify that the self-signed signature on the published key is valid
    // Do this last as it is the most expensive step.
    const foundKeySelfSignature: Uint8Array = base64Decode(key.selfSignature)

    // A key without the self-signature component to verify against.
    const unsignedKey: UnsignedKey = {
      environment: key.environment,
      expired: key.expired,
      handle: key.handle,
      publicKey: key.publicKey,
      type: key.type,
    }

    const canonicalHashedUnsignedKey: CanonicalHash = canonicalizeAndHashData(unsignedKey)

    const isKeySelfSignatureVerified = verifyEd25519(foundPublicKey, canonicalHashedUnsignedKey.hash, foundKeySelfSignature)

    if (!isKeySelfSignatureVerified) {
      return false
    }

    return true
  } catch (error) {
    return false
  }
}

/**
 * Canonicalize a Struct and return the sha-256 'hash' and 'hashType' of the canonicalized Struct
 * @param data The data to canonicalize
 * @return The canonicalized data
 */
function canonicalizeAndHashData(data: Item | ItemData[] | CommitmentData | UnsignedKey): CanonicalHash {
  const canonicalData = canonify(data)

  const canonicalDataUint8Array = new TextEncoder().encode(canonicalData)
  const hash: Uint8Array = stableSHA256(canonicalDataUint8Array)
  const hashUint8Array: Uint8Array = new Uint8Array(hash)
  const hashHex: string = hexEncode(hashUint8Array, true) // true = lowercase
  return {
    hash: hashUint8Array,
    hashHex: hashHex,
    hashType: 'sha-256',
    canonicalData: canonicalData,
  }
}

async function doVerification(commitment: Commitment, keys: SignedKeys | undefined, offline = false): Promise<CommitmentVerification> {
  const { commitmentData, commitmentDataSignatures } = commitment
  const { id, itemData, itemDataSignatures, itemSignals, proofs, transactions } = commitmentData

  // Decode the commitment's Id ('unsafely', since we can't validate HMAC here).
  const decodedId: IdV1DecodeUnsafely = decodeUnsafely({
    id: id,
  })

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

  assert(verificationResult, CommitmentVerificationStruct)
  return verificationResult
}

async function verifier(commitment: Commitment, keys: SignedKeys | undefined, offline = false): Promise<CommitmentVerification> {
  try {
    // Verify the structure of the incoming commitment and
    // construct a stub response CommitmentStruct if it is invalid.
    assert(commitment, CommitmentStruct)
    return await doVerification(commitment, keys, offline)
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
 * @returns A promise that resolves to an Object. The top-level `ok` property will be 'true' if the entire proof is verified.
 *
 * @example Sample output:
 * *
 * * ```typescript
 * {
 *   ok: true,
 *   id: 'T11_01G63P5WPW0CWJ7N6WGAXEXGJH_1655833818400000_A6D3501894C9D27D3A626B6E1ACFCD1B',
 *   offline: false,
 *   testEnv: true,
 *   itemData: {
 *     hash: 'c15fbfedf73881e7264ccefbabdcb679d247348e35dea14eba1d906c174c3e8e',
 *     signaturesCount: 1,
 *     signaturesVerified: true,
 *   },
 *   item: {
 *     hash: '7901019d4f28788058e5e661e756d33049ad40f69dbf3057c8260f1dde8dfeb8',
 *   },
 *   commitmentData: {
 *     hash: 'bf58d1780fe8a5fb30be1599781e96857bc21e3eb0a530f1c3d75b72d51833c9',
 *     signaturesCount: 1,
 *     signaturesVerified: true,
 *     signaturesPublicKeyVerified: true,
 *   },
 *   proofs: [
 *     {
 *       ok: true,
 *       inputHash: '7901019d4f28788058e5e661e756d33049ad40f69dbf3057c8260f1dde8dfeb8',
 *       merkleRoot: '7d371488a002714c9d2efb7f86da7c289bd865d0b359a1dadd13966078f7abce',
 *     },
 *   ],
 *   transactions: [
 *     {
 *       ok: true,
 *       offline: false,
 *       intent: 'xlm',
 *       inputHash: '7d371488a002714c9d2efb7f86da7c289bd865d0b359a1dadd13966078f7abce',
 *       transactionId: '09f0c766b0d393f27a7eddfceea46167106cd8fd4f21756196117876d5880503',
 *       blockId: '1600114',
 *       timestamp: '2022-06-21T17:52:06Z',
 *       urlApi: 'https://horizon-testnet.stellar.org/transactions/09f0c766b0d393f27a7eddfceea46167106cd8fd4f21756196117876d5880503',
 *       urlWeb: 'https://stellar.expert/explorer/testnet/tx/09f0c766b0d393f27a7eddfceea46167106cd8fd4f21756196117876d5880503',
 *     },
 *   ],
 * }
 * ```
 */

export async function verify(
  commitment: Commitment,
  options: { keys?: SignedKey[] } = {
    keys: undefined,
  },
): Promise<CommitmentVerification> {
  return await verifier(commitment, options.keys, false)
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
 * @returns A promise that resolves to an Object. The top-level `ok` property will be 'true' if the entire proof is verified offline.
 *
 */
export async function verifyUnsafelyOffline(
  commitment: Commitment,
  options: { keys?: SignedKey[] } = {
    keys: undefined,
  },
): Promise<CommitmentVerification> {
  return await verifier(commitment, options.keys, true)
}

/**
 * Predicate function to check if a commitment is valid and returning true|false. Throws no Errors.
 * @param commitment A commitment object to verify.
 * @param options.keys Force use of a set of keys.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerified(
  commitment: Commitment,
  options: { keys?: SignedKey[] } = {
    keys: undefined,
  },
): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verifier(commitment, options.keys, false)

    return verification.ok
  } catch (error) {
    return false
  }
}

/**
 * Predicate function to check if a commitment is valid and returning true|false offline. Throws no Errors.
 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys offline.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerifiedUnsafelyOffline(
  commitment: Commitment,
  options: { keys?: SignedKey[] } = {
    keys: undefined,
  },
): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verifier(commitment, options.keys, true)

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
 * @returns A promise that resolves to void.
 */
async function asserter(commitment: Commitment, keys: SignedKeys | undefined, offline: boolean): Promise<void> {
  const verification: CommitmentVerification = await verifier(commitment, keys, offline)

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
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerified(
  commitment: Commitment,
  options: { keys?: SignedKey[] } = {
    keys: undefined,
  },
): Promise<void> {
  await asserter(commitment, options.keys, false)
}

/**
 * Assert that the commitment is valid offline. If not, throw an Error.
 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys offline.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerifiedUnsafelyOffline(
  commitment: Commitment,
  options: { keys?: SignedKey[] } = {
    keys: undefined,
  },
): Promise<void> {
  await asserter(commitment, options.keys, true)
}
