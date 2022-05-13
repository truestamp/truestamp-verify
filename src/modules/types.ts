// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { DateTime } from 'luxon'

import {
  array,
  boolean,
  define,
  enums,
  nonempty,
  object,
  pattern,
  size,
  string,
  number,
  record,
  tuple,
  Infer,
} from 'superstruct'

import { isValidUnsafely } from '@truestamp/truestamp-id'

// SHA-1 -> 20 bytes
// SHA-256 -> 32 bytes
// SHA-384 -> 48 bytes
// SHA-512 -> 64 bytes
export const REGEX_HASH_HEX_20_64 = /^(([a-f0-9]{2}){20,64})$/i

// SHA-256 -> 32 bytes
export const REGEX_HASH_HEX_32 = /^(([a-f0-9]{2}){32})$/i

/**
 *  The names of the built-in hash functions supported by the library.
 * @ignore
 * */
export const HASH_FUNCTION_NAMES: string[] = [
  'sha224',
  'sha256',
  'sha384',
  'sha512',
  'sha512_256',
  'sha3_224',
  'sha3_256',
  'sha3_384',
  'sha3_512',
]

// A valid ISO 8601 date string or any precision in any timezone
const iso8601 = () =>
  define<string>('iso8601', value => {
    try {
      if (typeof value === 'string') {
        return DateTime.fromISO(value).isValid
      } else {
        return false
      }
    } catch (error) {
      return false
    }
  })

const truestampId = () =>
  define<string>('truestampId', value => {
    if (typeof value === 'string') {
      return isValidUnsafely({ id: value })
    } else {
      return false
    }
  })

/**
 * The struct that defines the shape of one layer of an Object encoded inclusion proof.
 * */
export const ProofObjectLayerStruct = tuple([
  size(number(), 0, 1), // 0 : left, 1 : right
  pattern(string(), REGEX_HASH_HEX_20_64),
])

/**
 * The inferred type that defines the shape of one layer of an Object encoded inclusion proof.
 * */
export type ProofObjectLayer = Infer<typeof ProofObjectLayerStruct>

/**
 * The struct that defines the shape of an Object encoded inclusion proof.
 * v : version number
 * h : hash function
 * p : proof
 * */
export const ProofObjectStruct = object({
  v: enums([1]),
  h: enums(HASH_FUNCTION_NAMES),
  p: array(ProofObjectLayerStruct),
})

/**
 * The inferred type that defines the shape of an Object encoded inclusion proof.
 * */
export type ProofObject = Infer<typeof ProofObjectStruct>

export const CommitProofStruct = object({
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  inclusionProof: ProofObjectStruct,
  merkleRoot: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
})

export type CommitProof = Infer<typeof CommitProofStruct>

export const CommitTransactionStruct = object({
  intent: enums(['xlm', 'twtr', 'eth', 'btc']),
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  transactionId: nonempty(string()),
  blockId: nonempty(string()),
})

export type CommitTransaction = Infer<typeof CommitTransactionStruct>

export const CommitmentStruct = object({
  type: enums(['commitment']),
  id: nonempty(truestampId()),
  envelopeHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  submittedAt: nonempty(iso8601()),
  proofs: array(CommitProofStruct),
  transactions: record(string(), array(CommitTransactionStruct)),
})

export type Commitment = Infer<typeof CommitmentStruct>

export const VerificationStruct = object({
  intent: enums(['xlm', 'twtr', 'eth', 'btc']),
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  transactionId: nonempty(string()),
  blockId: nonempty(string()),
  timestamp: nonempty(iso8601()),
  urlApi: nonempty(string()),
  urlWeb: nonempty(string()),
  testing: boolean(),
})

export type Verification = Infer<typeof VerificationStruct>

export const CommitmentVerificationStruct = object({
  type: enums(['commitment-verification']),
  verified: boolean(),
  verifications: nonempty(array(VerificationStruct)),
})

export type CommitmentVerification = Infer<typeof CommitmentVerificationStruct>
