// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { assert, StructError } from 'superstruct'
import { Tree } from '@truestamp/tree'
import { decodeUnsafely, IdV1DecodeUnsafely } from '@truestamp/truestamp-id'
import { decode as hexDecode } from '@stablelib/hex'

import {
  Commitment,
  CommitmentStruct,
  CommitProof,
  CommitTransaction,
  CommitmentVerification,
  CommitmentVerificationStruct,
  Verification,
  VerificationStruct,
} from './types'

import { verifyStellar } from './verifyStellar'

export async function verify(
  commitment: Commitment,
  options: { testing?: boolean } = { testing: false },
): Promise<CommitmentVerification> {
  try {
    assert(commitment, CommitmentStruct)
  } catch (err) {
    if (err instanceof StructError) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const { key, value, type } = err

      if (value === undefined) {
        throw new Error(`Missing required attribute '${key as string}'`)
      } else if (type === 'never') {
        throw new Error(`Unknown attribute '${key as string}'`)
      } else {
        throw new Error(`Invalid attribute for '${key as string}'`)
      }
    } else if (err instanceof Error) {
      throw err
    }
  }

  try {
    const decodedId: IdV1DecodeUnsafely = decodeUnsafely({ id: commitment.id })
    if (decodedId.test !== options.testing) {
      throw new Error(
        `function 'options.testing' arg must match the 'test' flag embedded in the Id`,
      )
    }
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Invalid commitment Id: ${error.message}`)
    }
  }

  const { proofs } = commitment

  // Verify that each proof is chained correctly and that each
  // is provable using the Merkle tree inclusion proof and Merkle root.
  for (let i = 0; i < proofs.length; i++) {
    const proof: CommitProof = proofs[i]

    if (i === 0) {
      if (commitment.envelopeHash !== proof.inputHash) {
        throw new Error(`First proof envelopeHash must equal inputHash`)
      }
    }

    // Subsequent proof's inputHash must match the Merkle root of the previous proof
    // and must be a valid proof.
    if (i >= 1) {
      const previousProofIndex = i - 1
      const previousProof: CommitProof = proofs[previousProofIndex]
      if (proof.inputHash !== previousProof.merkleRoot) {
        throw new Error(
          `Proof [${i}] inputHash must match previous proof [${previousProofIndex}] merkleRoot`,
        )
      }

      // Verify that the proof is valid for the given data and Merkle root.
      try {
        const isTreeVerified = Tree.verify(
          hexDecode(proof.merkleRoot),
          proof.inclusionProof,
          hexDecode(proof.inputHash),
        )
        if (!isTreeVerified) {
          throw new Error(`inclusionProof [${i}] is not a valid proof`)
        }
      } catch (error) {
        if (error instanceof Error) {
          throw new Error(
            `Proof [${i}] failed Merkle tree verification : ${error.message}`,
          )
        }
      }
    }
  }

  const proofMerkleRoots = proofs.map((proof: CommitProof) => {
    return proof.merkleRoot
  })

  const verifications: Verification[] = []

  for (const merkleRoot of proofMerkleRoots) {
    const transactionsForMerkleRoot: CommitTransaction[] =
      commitment.transactions[merkleRoot] ?? []
    // console.log(`transactionsForMerkleRoot: ${JSON.stringify(transactionsForMerkleRoot, null, 2)}`)

    for (let i = 0; i < transactionsForMerkleRoot.length; i++) {
      if (transactionsForMerkleRoot[i].intent === 'xlm') {
        try {
          const v: Verification = await verifyStellar(
            transactionsForMerkleRoot[i],
            options.testing,
          )
          assert(v, VerificationStruct)
          verifications.push(v)
        } catch (error) {
          if (error instanceof Error) {
            throw new Error(
              `Proof [${i}] failed Stellar transaction verification : ${error.message}`,
            )
          }
        }
      }
    }
  }

  const verificationResult: CommitmentVerification = {
    type: 'commitment-verification',
    verified: verifications.length >= 1,
    verifications: verifications,
  }

  assert(verificationResult, CommitmentVerificationStruct)
  return verificationResult
}

/**
 * Predicate function to check if a commitment is valid. Never throws an Error.
 * @param commitment A commitment object to verify.
 * @returns A promise that resolves to a boolean indicating if the commitment is valid.
 */
export async function isVerified(
  commitment: Commitment,
  options: { testing?: boolean } = { testing: false },
): Promise<boolean> {
  try {
    await verify(commitment, { testing: options.testing })
    return true
  } catch (error) {
    return false
  }
}

/**
 * Assert that the commitment is valid. If it is not, throw an error.
 * @param commitment A commitment object to verify.
 * @returns A promise that resolves to void when the commitment is valid.
 */
export async function assertVerified(
  commitment: Commitment,
  options: { testing?: boolean } = { testing: false },
): Promise<void> {
  if (!(await isVerified(commitment, { testing: options.testing }))) {
    throw new Error('Invalid commitment')
  }
}
