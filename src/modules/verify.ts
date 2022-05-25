// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { assert, create, is, StructError } from 'superstruct'
import { sha256, Tree } from '@truestamp/tree'
import { decodeUnsafely, IdV1DecodeUnsafely } from '@truestamp/truestamp-id'
import { canonify } from '@truestamp/canonify'
import { encode as hexEncode, decode as hexDecode } from '@stablelib/hex'
import { decode as base64Decode } from '@stablelib/base64'
import { verify as verifyEd25519 } from '@stablelib/ed25519'
import { hash as stableSHA256 } from '@stablelib/sha256'
import { equal } from '@stablelib/constant-time'

import {
  CanonicalHash,
  CommitmentData,
  CommitmentDataStruct,
  Commitment,
  CommitmentStruct,
  CommitProof,
  CommitTransaction,
  CommitmentVerification,
  CommitmentVerificationStruct,
  SignedKey,
  SignedKeyStruct,
  SignedKeys,
  SignedKeysStruct,
  UnsignedKey,
  UnsignedKeyStruct,
  VerificationProof,
  VerificationTransaction,
  VerificationTransactionStruct,
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
    selfSignature:
      'Vj0A4kNa2a4tRLxOEPFwV7irNIGUoe7Q8SX1JfkRHeNea9M+3Q3vT+9n640mMJhm2nUIDvbCtmtB2xqGoqpmCQ==',
  },
  {
    handle: 'f36947d3',
    type: 'ed25519',
    publicKey: '2/N8KtnOq46WOvQay/cun/3vin7dYU0jtwliVf6g83s=',
    environment: 'staging',
    expired: false,
    selfSignature:
      'lWxD/ujp9UdGkk2MsUUla1oAR3FopK8jCeE4eNfeS6HS/ue6dUk+vhoNI3zUNsGFlNXUzwskET/VtS8i5KgQCA==',
  },
  {
    handle: 'b3395500',
    type: 'ed25519',
    publicKey: 'BnE/2AYhgMd0KY7tXdMfmRJPoPY4I5h7rhQf+9nswAQ=',
    environment: 'production',
    expired: false,
    selfSignature:
      'yZG0mJUpeWdaayZMF70bHrBnjIYihmoZoiEbfciGxARvocmLp0JlKXaP5MtQGCd73yqjOHX1aZqHGOPise7fAw==',
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
async function getKeyByHandle(
  handle: string,
  keys?: SignedKey[],
  offline?: boolean,
): Promise<SignedKey | undefined> {
  // If an array of keys was provided, use them to the exclusion of any other.
  if (is(keys, SignedKeysStruct)) {
    return keys.find((key: SignedKey): boolean => key.handle === handle)
  }

  // No keys were provided for offline, so we'll use the baked public keys
  if (offline) {
    return BACKUP_PUBLIC_KEYS.find(
      (key: SignedKey): boolean => key.handle === handle,
    )
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
async function publicKeyMatchesKnownPublicKey(
  publicKey: Uint8Array,
  keys?: SignedKey[],
  offline?: boolean,
): Promise<boolean> {
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
    if (
      handle !== getHandleForPublicKey(foundPublicKey) ||
      handle !== key.handle
    ) {
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

    const canonicalHashedUnsignedKey: CanonicalHash =
      canonicalizeAndHashData(unsignedKey)

    const isKeySelfSignatureVerified = verifyEd25519(
      foundPublicKey,
      canonicalHashedUnsignedKey.hash,
      foundKeySelfSignature,
    )

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
function canonicalizeAndHashData(
  data: CommitmentData | UnsignedKey,
): CanonicalHash {
  if (is(data, CommitmentDataStruct) || is(data, UnsignedKeyStruct)) {
    const canonicalData = canonify(data)

    const canonicalDataUint8Array = new TextEncoder().encode(canonicalData)
    const hash: Uint8Array = stableSHA256(canonicalDataUint8Array)
    const hashUint8Array: Uint8Array = new Uint8Array(hash)
    const hashHex: string = hexEncode(hashUint8Array, true) // true = lowercase
    return {
      hash: hashUint8Array,
      hashHex: hashHex,
      hashType: 'sha-256',
    }
  }

  throw new Error('Unsupported data type')
}

/**
 * A function to check if a commitment is valid. If there are any errors,
 * the appropriate 'ok' property will be set to 'false'.
 *
 * You can provide a list of signed keys from https://keys.truestamp.com that were
 * previously saved. Keys can be provided in offline or online mode.
 *
 * In offline mode, if no keys are provided, the library will attempt to
 * use a backup copy of the keys stored in this library. These backup keys
 * are not guaranteed to be current, but they are the best available option.
 *
 * In offline mode, the library will **not** attempt to verify transactions
 * against the actual on-chain state. It will only verify that the commitment
 * is internally cryptographically sound. Since it does not have access to the
 * on-chain state, it cannot verify a timestamp attested to by this commitment.
 *
 * @param commitment A commitment object to verify.
 * @param options.keys Force use of a set of keys.
 * @param options.offline Whether to attempt to verify the commitment offline.
 * @returns A promise that resolves to an Object. The top-level `ok` property will be 'true' if the entire proof is verified.
 *
 * @example Sample output:
 * *
 * * ```typescript
 *{
 *  type: 'commitment-verification',
 *  ok: true,
 *  offline: false,
 *  testEnv: true,
 *  signature: { hash: true, publicKey: true, verified: true },
 *  proofs: [
 *    {
 *      ok: true,
 *      inputHash: 'b1fc469deae708277eb87b089800731a57f61ddbddf0c71332288397daffa8fa',
 *      merkleRoot: 'ebbe387c731b1fdcee412b4fc7c82d966cd0276e79c6a9c319e304dd78dedac4'
 *    },
 *    {
 *      ok: true,
 *      inputHash: 'ebbe387c731b1fdcee412b4fc7c82d966cd0276e79c6a9c319e304dd78dedac4',
 *      merkleRoot: '93c5277c0135e85b61a9798345e8c3ea21b17c0f85defe45e390b4758cf1b16b'
 *    },
 *    {
 *      ok: true,
 *      inputHash: '93c5277c0135e85b61a9798345e8c3ea21b17c0f85defe45e390b4758cf1b16b',
 *      merkleRoot: '333e65c8b3ee8c4a095dfb97890d295a0d36097cf03e391118f4a214e8c171a2'
 *    },
 *    {
 *      ok: true,
 *      inputHash: '333e65c8b3ee8c4a095dfb97890d295a0d36097cf03e391118f4a214e8c171a2',
 *      merkleRoot: '37aea4f6c62d1fb647fca9e13f90a474033fdd0102df00c80623ab8e6dd9aefe'
 *    }
 *  ],
 *  transactions: [
 *    {
 *      ok: true,
 *      offline: false,
 *      intent: 'xlm',
 *      inputHash: 'ebbe387c731b1fdcee412b4fc7c82d966cd0276e79c6a9c319e304dd78dedac4',
 *      transactionId: '3c702c91598c7ae69d80d6cebe4faf329680ddadb6c2621ad8235f0f999e37a9',
 *      blockId: '1071745',
 *      timestamp: '2022-05-20T14:33:03Z',
 *      urlApi: 'https://horizon-testnet.stellar.org/transactions/3c702c91598c7ae69d80d6cebe4faf329680ddadb6c2621ad8235f0f999e37a9',
 *      urlWeb: 'https://stellar.expert/explorer/testnet/tx/3c702c91598c7ae69d80d6cebe4faf329680ddadb6c2621ad8235f0f999e37a9'
 *    }
 *  ]
 *}
 * ```
 */
export async function verify(
  commitment: Commitment,
  options: { keys?: SignedKey[]; offline?: boolean } = {
    keys: undefined,
    offline: false,
  },
): Promise<CommitmentVerification> {
  try {
    // Verify the entire structure of the incoming commitment
    assert(commitment, CommitmentStruct)
  } catch (error) {
    const commitmentResponse: CommitmentVerification = {
      type: 'commitment-verification',
      ok: false,
      offline: options.offline ? true : false,
    }

    if (error instanceof StructError) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const { key, value, type } = error

      if (value === undefined) {
        // prettier-ignore
        commitmentResponse.error = `missing required attribute '${key as string}'`
      } else if (type === 'never') {
        commitmentResponse.error = `unknown attribute '${key as string}'`
      } else {
        commitmentResponse.error = `invalid attribute for '${key as string}'`
      }
    } else if (error instanceof Error) {
      commitmentResponse.error = `${error.message}`
    }

    assert(commitmentResponse, CommitmentVerificationStruct)
    return commitmentResponse
  }

  const { data: commitmentData } = commitment
  const { proofs, transactions } = commitmentData

  // Decode the commitment's ID.
  const decodedId: IdV1DecodeUnsafely = decodeUnsafely({
    id: commitmentData.id,
  })

  const verificationProofs: VerificationProof[] = []

  // Verify that each proof is chained correctly and that each
  // is provable using the Merkle tree inclusion proof and Merkle root.
  for (let i = 0; i < proofs.length; i++) {
    const proof: CommitProof = proofs[i]

    const vp: VerificationProof = {
      ok: false,
      inputHash: proof.inputHash,
      merkleRoot: proof.merkleRoot,
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
      const isTreeVerified = Tree.verify(
        hexDecode(proof.merkleRoot),
        proof.inclusionProof,
        hexDecode(proof.inputHash),
      )
      if (isTreeVerified) {
        vp.ok = true
      } else {
        throw new Error('tree verification failed')
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

  const proofMerkleRoots: string[] = proofs.map(
    (proof: CommitProof): string => {
      return proof.merkleRoot
    },
  )

  const verificationTransactions: VerificationTransaction[] = []

  for (const merkleRoot of proofMerkleRoots) {
    const transactionsForMerkleRoot: CommitTransaction[] =
      transactions[merkleRoot] || []

    for (let i = 0; i < transactionsForMerkleRoot.length; i++) {
      try {
        let verificationResult
        switch (transactionsForMerkleRoot[i].intent) {
          case 'xlm':
            if (options.offline === true) {
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

          case 'twtr':
            if (options.offline === true) {
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
            if (options.offline === true) {
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
            if (options.offline === true) {
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
              // TODO: verify twitter
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
            offline: options.offline ? true : false,
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
  const allTransactionsVerifiedOrSkipped = verificationTransactions.every(
    (v: VerificationTransaction) => {
      return v.ok
    },
  )

  // Canonicalize the commitment data and make sure that the resulting hash
  // matches the 'hash' property.
  const commitmentDataCanonicalizedAndHashed =
    canonicalizeAndHashData(commitmentData)

  const canonicalDataMatchesHash = equal(
    hexDecode(commitment.hash),
    hexDecode(commitmentDataCanonicalizedAndHashed.hashHex),
  )

  // Verify ed25519 signature on the commitment.
  const publicKey = base64Decode(commitment.signatures[0].publicKey)
  const commitmentSignatureVerified = verifyEd25519(
    publicKey,
    hexDecode(commitment.hash),
    base64Decode(commitment.signatures[0].signature),
  )

  // Verify that the public key used for the signature matches one
  // of the known authoritative public keys and is validly self-signed.
  const publicKeyVerified: boolean = await publicKeyMatchesKnownPublicKey(
    publicKey,
    options.keys,
    options.offline,
  )

  const isVerified =
    allProofsVerified &&
    allTransactionsVerifiedOrSkipped &&
    canonicalDataMatchesHash &&
    publicKeyVerified &&
    commitmentSignatureVerified

  const verificationResult: CommitmentVerification = {
    type: 'commitment-verification',
    ok: isVerified,
    offline: options.offline ? true : false,
    testEnv: decodedId.test,
    signature: {
      hash: canonicalDataMatchesHash,
      publicKey: publicKeyVerified,
      verified: commitmentSignatureVerified,
    },
    proofs: verificationProofs,
    transactions: verificationTransactions,
  }

  assert(verificationResult, CommitmentVerificationStruct)
  return verificationResult
}

/**
 * Predicate function to check if a commitment is valid. Throws no Errors.
 * @param commitment A commitment object to verify online.
 * @param options.keys Force use of a set of keys.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerified(
  commitment: Commitment,
  options?: { keys?: SignedKey[] },
): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verify(commitment, {
      keys: options?.keys,
      offline: false,
    })

    return verification.ok
  } catch (error) {
    return false
  }
}

/**
 * Predicate function to check if a commitment is valid while skipping any Internet fetches. Throws no Errors.
 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerifiedUnsafelyOffline(
  commitment: Commitment,
  options?: { keys?: SignedKey[] },
): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verify(commitment, {
      keys: options?.keys,
      offline: true,
    })
    return verification.ok && verification.offline
  } catch (error) {
    return false
  }
}

/**
 * Assert that the commitment is valid. If not, throw an Error.
 * @param commitment A commitment object to verify online.
 * @param options.keys Force use of a set of keys.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerified(
  commitment: Commitment,
  options?: { keys?: SignedKey[] },
): Promise<void> {
  try {
    const verification: CommitmentVerification = await verify(commitment, {
      keys: options?.keys,
      offline: false,
    })
    if (!verification.ok) {
      throw new Error(verification.error || 'Commitment is not valid')
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Commitment is not valid`)
    }
  }
}

/**
 * Assert that the commitment is valid while skipping any Internet fetches. If not, throw an Error.
 * @param commitment A commitment object to verify offline.
 * @param options.keys Force use of a set of keys.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerifiedUnsafelyOffline(
  commitment: Commitment,
  options?: { keys?: SignedKey[] },
): Promise<void> {
  try {
    const verification: CommitmentVerification = await verify(commitment, {
      keys: options?.keys,
      offline: true,
    })
    if (!verification.ok) {
      throw new Error(verification.error || 'Commitment is not valid offline')
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Commitment is not valid offline`)
    }
  }
}
