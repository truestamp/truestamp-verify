// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { DateTime } from 'luxon'
import * as EmailValidator from 'email-validator'
import isURI from '@stdlib/assert/is-uri'
import { decode } from '@stablelib/base64'
import {
  array,
  boolean,
  define,
  enums,
  nonempty,
  object,
  omit,
  optional,
  pattern,
  size,
  string,
  number,
  record,
  trimmed,
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

// A valid ISO 8601 date string in UTC timezone Z or with no offset +00:00
const iso8601UTC = () =>
  define<string>('iso8601UTC', value => {
    try {
      if (typeof value === 'string') {
        if (!value.endsWith('Z') && !value.endsWith('+00:00')) {
          return false
        }

        const d = DateTime.fromISO(value, { zone: 'utc' })
        return d.isValid && d.offsetNameShort === 'UTC'
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

const email = () =>
  define<string>('email', value => {
    try {
      if (typeof value === 'string') {
        return EmailValidator.validate(value)
      } else {
        return false
      }
    } catch (error) {
      return false
    }
  })

const base64 = () =>
  define<string>('base64', value => {
    if (typeof value === 'string') {
      decode(value)
    }

    try {
      if (typeof value === 'string') {
        decode(value)
        return true
      } else {
        return false
      }
    } catch (error) {
      return false
    }
  })

const URI = () =>
  define<string>('URI', value => {
    try {
      if (typeof value === 'string') {
        return isURI(value)
      } else {
        return false
      }
    } catch (error) {
      return false
    }
  })

/**
 * A simplified version of the PersonStruct.
 */
export const VerificationPersonStruct = object({
  type: enums(['person']),
  organizationName: size(trimmed(string()), 1, 64),
  email: email(),
  uri: URI(),
})

export const SignatureStruct = object({
  type: enums(['signature']),
  publicKey: base64(),
  signature: base64(),
  signatureType: enums(['ed25519']),
  signer: optional(VerificationPersonStruct),
})

export type Signature = Infer<typeof SignatureStruct>

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

export const CommitmentDataStruct = object({
  id: truestampId(),
  submittedAt: iso8601UTC(),
  proofs: array(CommitProofStruct),
  transactions: record(string(), array(CommitTransactionStruct)),
})

export type CommitmentData = Infer<typeof CommitmentDataStruct>

export const CommitmentStruct = object({
  type: enums(['commitment']),
  hash: pattern(string(), REGEX_HASH_HEX_32), // MUST be h(canonify(data))
  hashType: enums(['sha-256']),
  signatures: nonempty(array(SignatureStruct)), // One, or more, sign(hash||hashType)
  data: CommitmentDataStruct,
  timestamp: iso8601UTC(),
})

export type Commitment = Infer<typeof CommitmentStruct>

export const VerificationProofStruct = object({
  verified: boolean(),
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  merkleRoot: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  error: optional(string()),
})

export type VerificationProof = Infer<typeof VerificationProofStruct>

export const VerificationTransactionStruct = object({
  intent: enums(['xlm', 'twtr', 'eth', 'btc']),
  verified: boolean(),
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  transactionId: nonempty(string()),
  blockId: nonempty(string()),
  timestamp: optional(nonempty(iso8601UTC())),
  urlApi: optional(nonempty(string())),
  urlWeb: optional(nonempty(string())),
  error: optional(string()),
})

export type VerificationTransaction = Infer<
  typeof VerificationTransactionStruct
>

export const CommitmentVerificationStruct = object({
  type: enums(['commitment-verification']),
  verified: boolean(),
  signatureHashVerified: boolean(),
  signatureVerified: boolean(),
  signaturePublicKeyVerified: boolean(),
  testing: optional(boolean()),
  proofs: array(VerificationProofStruct),
  transactions: array(VerificationTransactionStruct),
  error: optional(string()),
})

export type CommitmentVerification = Infer<typeof CommitmentVerificationStruct>

export const EnvironmentStruct = enums(['development', 'staging', 'production'])
export type Environment = Infer<typeof EnvironmentStruct>

export const SignedKeyStruct = object({
  environment: EnvironmentStruct,
  expired: boolean(),
  handle: string(),
  publicKey: base64(),
  type: enums(['ed25519']),
  selfSignature: base64(),
})

export type SignedKey = Infer<typeof SignedKeyStruct>

export const UnsignedKeyStruct = omit(SignedKeyStruct, ['selfSignature'])

export type UnsignedKey = Infer<typeof UnsignedKeyStruct>

export interface CanonicalHash {
  hash: Uint8Array
  hashHex: string
  hashType: string
}
