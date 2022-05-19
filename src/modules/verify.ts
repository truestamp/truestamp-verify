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
  UnsignedKey,
  UnsignedKeyStruct,
  VerificationProof,
  VerificationTransaction,
  VerificationTransactionStruct,
} from './types'

import { verifyStellar } from './verifyStellar'

const KEY_SERVER_BASE_URL = 'https://keys.truestamp.com'

/**
 * For a given public key, calculate its handle.
 * @param publicKey The public key to calculate the handle for
 * @return The public key's handle
 */
function getHandleForPublicKey(publicKey: Uint8Array): string {
  return hexEncode(sha256(publicKey)).slice(0, 8).toLowerCase()
}

/**
 * For a given public key, calculate its handle, look it up on a public key server
 * and verify that the key associated with the handle matches the public key passed in.
 * @param publicKey The public key to verify is authoritatively published
 * @return A boolean indicating whether the public key is authoritatively published
 */
async function publishedPublicKeyMatchesPublicKey(
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    const handle = getHandleForPublicKey(publicKey)

    const response = await fetch(`${KEY_SERVER_BASE_URL}/${handle}`)

    if (!response.ok) {
      return false
    }

    const foundKey: SignedKey = create(await response.json(), SignedKeyStruct)

    const foundPublicKey = base64Decode(foundKey.publicKey)
    if (!equal(foundPublicKey, publicKey)) {
      return false
    }

    // Ensure that the handles from the website key server match the handle we calculated
    if (
      handle !== getHandleForPublicKey(foundPublicKey) ||
      handle !== foundKey.handle
    ) {
      return false
    }

    // Verify that the self-signed signature on the published key is valid
    // Do this last as its the most expensive step.
    const foundKeySelfSignature = base64Decode(foundKey.selfSignature)

    const unsignedKey: UnsignedKey = {
      environment: foundKey.environment,
      expired: foundKey.expired,
      handle: foundKey.handle,
      publicKey: foundKey.publicKey,
      type: foundKey.type,
    }

    const canonicalHashedUnsignedKey = canonicalizeAndHashData(unsignedKey)
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
 * the appropriate 'verified' property will be set to 'false' and an 'errors'
 * property may be populated with a helpful message to indicate what failed.
 *
 * @param commitment A commitment object to verify.
 * @returns A promise that resolves to an Object. The `verified` property will be 'true' if the entire proof is verified.
 *
 * @example Sample output:
 *
 * ```typescript
 *{
 *  type: 'commitment-verification',
 *  testing: true,
 *  verified: true,
 *  signatureVerified: true,
 *  proofs: [
 *    {
 *      verified: true,
 *      inputHash: 'b2faa122f53e1b36c41680c42a5aba0c8dfc5fdb4cdb32565ad89107e5c26e5f',
 *      merkleRoot: 'd555db5eb2e227660965f96a0ef5db3cb89d5f9f39112f061691eff278a0bf84'
 *    },
 *    {
 *      verified: true,
 *      inputHash: 'd555db5eb2e227660965f96a0ef5db3cb89d5f9f39112f061691eff278a0bf84',
 *      merkleRoot: 'a0d54547ea370cd56dd3690160c88d6b8af3a0d3fbb37e34a8c55fcc36b9621f'
 *    },
 *    {
 *      verified: true,
 *      inputHash: 'a0d54547ea370cd56dd3690160c88d6b8af3a0d3fbb37e34a8c55fcc36b9621f',
 *      merkleRoot: '401a33e0cf753c5f2c076ef5f1092d2109661963bc0f95a51bcdf7c083ad0d59'
 *    }
 *  ],
 *  transactions: [
 *    {
 *      verified: true,
 *      intent: 'xlm',
 *      inputHash: 'd555db5eb2e227660965f96a0ef5db3cb89d5f9f39112f061691eff278a0bf84',
 *      transactionId: 'd4eb2e02aff51117f3374dc9029702128164bfc737b60e9340d246800a8583d4',
 *      blockId: '923404',
 *      timestamp: '2022-05-11T13:49:04Z',
 *      urlApi: 'https://horizon-testnet.stellar.org/transactions/d4eb2e02aff51117f3374dc9029702128164bfc737b60e9340d246800a8583d4',
 *      urlWeb: 'https://stellar.expert/explorer/testnet/tx/d4eb2e02aff51117f3374dc9029702128164bfc737b60e9340d246800a8583d4'
 *    }
 *  ]
 *}
 * ```
 */
export async function verify(
  commitment: Commitment,
): Promise<CommitmentVerification> {
  try {
    // Verify the entire structure of the incoming commitment
    assert(commitment, CommitmentStruct)
  } catch (error) {
    const commitmentResponse: CommitmentVerification = {
      type: 'commitment-verification',
      testing: undefined,
      verified: false,
      signatureHashVerified: false,
      signatureVerified: false,
      signaturePublicKeyVerified: false,
      proofs: [],
      transactions: [],
    }

    if (error instanceof StructError) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const { key, value, type } = error

      if (value === undefined) {
        // eslint-disable-next-line prettier/prettier
        commitmentResponse.error = `Commitment missing required attribute '${key as string}'`
      } else if (type === 'never') {
        // eslint-disable-next-line prettier/prettier
        commitmentResponse.error = `Commitment has unknown attribute '${key as string}'`
      } else {
        // eslint-disable-next-line prettier/prettier
        commitmentResponse.error = `Commitment has invalid attribute for '${key as string}'`
      }
    } else if (error instanceof Error) {
      commitmentResponse.error = `Commitment has error ${error.message}`
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
      verified: false,
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
        vp.verified = true
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
    return v.verified
  })

  const proofMerkleRoots = proofs.map((proof: CommitProof) => {
    return proof.merkleRoot
  })

  const verificationTransactions: VerificationTransaction[] = []

  for (const merkleRoot of proofMerkleRoots) {
    const transactionsForMerkleRoot: CommitTransaction[] =
      transactions[merkleRoot] ?? []

    for (let i = 0; i < transactionsForMerkleRoot.length; i++) {
      try {
        let verificationResult
        switch (transactionsForMerkleRoot[i].intent) {
          case 'xlm':
            verificationResult = await verifyStellar(
              transactionsForMerkleRoot[i],
              decodedId.test, // verify against a test network?
            )
            break

          case 'twtr':
            break

          case 'btc':
            break

          case 'eth':
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
            verified: false,
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

  // Check if the 'verified' attribute is set to true for every transaction.
  const allTransactionsVerified = verificationTransactions.every(
    (v: VerificationTransaction) => {
      return v.verified
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
  const signatureVerified = verifyEd25519(
    publicKey,
    hexDecode(commitment.hash),
    base64Decode(commitment.signatures[0].signature),
  )

  // Verify that the public key used for the signature matches one
  // of the known authoritative public keys.
  const publicKeyVerified = await publishedPublicKeyMatchesPublicKey(publicKey)

  const isVerified =
    allProofsVerified &&
    allTransactionsVerified &&
    canonicalDataMatchesHash &&
    publicKeyVerified &&
    signatureVerified

  const verificationResult: CommitmentVerification = {
    type: 'commitment-verification',
    testing: decodedId.test,
    verified: isVerified,
    signatureHashVerified: canonicalDataMatchesHash,
    signatureVerified: signatureVerified,
    signaturePublicKeyVerified: publicKeyVerified,
    proofs: verificationProofs,
    transactions: verificationTransactions,
  }

  if (!verificationResult.verified) {
    verificationResult.error = `Commitment verification failed, failure points indicated where 'verified' is 'false'.`
  }

  assert(verificationResult, CommitmentVerificationStruct)
  return verificationResult
}

/**
 * Predicate function to check if a commitment is valid. Throws no Errors.
 * @param commitment A commitment object to verify.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerified(commitment: Commitment): Promise<boolean> {
  try {
    const verification: CommitmentVerification = await verify(commitment)
    return verification.verified
  } catch (error) {
    return false
  }
}

/**
 * Assert that the commitment is valid. If not, throw an Error.
 * @param commitment A commitment object to verify.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerified(commitment: Commitment): Promise<void> {
  try {
    const verification: CommitmentVerification = await verify(commitment)
    if (!verification.verified) {
      throw new Error(verification.error ?? 'Commitment is not valid')
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Commitment is not valid`)
    } else {
      throw new Error(`Commitment is not valid`)
    }
  }
}
