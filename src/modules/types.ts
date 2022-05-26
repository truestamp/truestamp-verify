// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { DateTime } from 'luxon'
import * as EmailValidator from 'email-validator'
import isURI from '@stdlib/assert/is-uri'
import { isValidUnsafely } from '@truestamp/truestamp-id'
import { decode as base64Decode } from '@stablelib/base64'
import { isIso3166Alpha2Code, Iso3166Alpha2Code } from 'iso-3166-ts'

import {
  array,
  defaulted,
  define,
  enums,
  integer,
  lazy,
  nonempty,
  nullable,
  object,
  omit,
  pattern,
  size,
  string,
  trimmed,
  union,
  optional,
  pick,
  boolean,
  number,
  record,
  tuple,
  Infer,
  Describe,
} from 'superstruct'

// SHA-1 -> 20 bytes
// SHA-256 -> 32 bytes
// SHA-384 -> 48 bytes
// SHA-512 -> 64 bytes
export const REGEX_HASH_HEX_20_64 = /^(([a-f0-9]{2}){20,64})$/i

// SHA-256 -> 32 bytes
export const REGEX_HASH_HEX_32 = /^(([a-f0-9]{2}){32})$/i

export interface HashType {
  minBytes: number
  maxBytes: number
}

export interface HashTypes {
  [key: string]: HashType
}

// Limit the available hash types for now to those that are supported by the browser
// and crypto.subtle.digest
// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#syntax
export const HASH_TYPES: HashTypes = {
  'sha-1': { minBytes: 20, maxBytes: 20 },
  'sha-256': { minBytes: 32, maxBytes: 32 },
  'sha-384': { minBytes: 48, maxBytes: 48 },
  'sha-512': { minBytes: 64, maxBytes: 64 },
}

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
    try {
      if (typeof value === 'string') {
        // if it safely decodes, then it is base64
        base64Decode(value)
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

// A valid ISO 3166 Alpha 2 Country Code
// https://github.com/karpour/iso-3166-ts
// https://www.iso.org/iso-3166-country-codes.html
const iso3166Alpha2Code = () =>
  define<Iso3166Alpha2Code>('iso3166Alpha2Code', value => {
    try {
      if (typeof value === 'string') {
        return isIso3166Alpha2Code(value)
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

const latitude = () =>
  define<string>('latitude', value => {
    try {
      if (value && typeof value === 'string') {
        const decimalLatLongValueString = /^[-+]?[0-9]*\.?[0-9]+$/
        if (!decimalLatLongValueString.test(value)) {
          return false
        }
        const valueFloat = parseFloat(value)
        return valueFloat >= -90 && valueFloat <= 90 ? true : false
      }
      return false
    } catch (error) {
      return false
    }
  })

const longitude = () =>
  define<string>('longitude', value => {
    try {
      if (value && typeof value === 'string') {
        const decimalLatLongValueString = /^[-+]?[0-9]*\.?[0-9]+$/
        if (!decimalLatLongValueString.test(value)) {
          return false
        }
        const valueFloat = parseFloat(value)
        return valueFloat >= -180 && valueFloat <= 180 ? true : false
      }
      return false
    } catch (error) {
      return false
    }
  })

// Universal Postal Union (UPU) S42 International Addressing Standards
// https://www.upu.int/UPU/media/upu/documents/PostCode/S42_International-Addressing-Standards.pdf
// https://www.upu.int/UPU/media/upu/documents/PostCode/AddressElementsFormattingAnInternationalAdressEn.pdf
export const AddressStruct = object({
  type: defaulted(enums(['address']), 'address'),
  streetNo: optional(size(trimmed(string()), 1, 8)),
  streetName: optional(size(trimmed(string()), 1, 64)),
  streetType: optional(size(trimmed(string()), 1, 16)),
  floor: optional(size(trimmed(string()), 1, 8)),
  town: optional(size(trimmed(string()), 1, 64)),
  region: optional(size(trimmed(string()), 1, 64)),
  postcode: optional(size(trimmed(string()), 1, 16)),
  countryCode: iso3166Alpha2Code(),
})

export type Address = Infer<typeof AddressStruct>

// A Location on Earth where the data structure is aligned with the iOS CoreLocation framework
// https://developer.apple.com/documentation/corelocation
// It is presumed that the location is derived from a device's GPS or other location sensor.
export const LocationStruct = object({
  type: defaulted(enums(['location']), 'location'),
  coordinate: object({ latitude: latitude(), longitude: longitude() }), // coordinate in decimal degrees(WGS84): ["38.8895563", "-77.0352546"]
  altitude: optional(size(number(), -100000, 100000)), // The altitude above mean sea level associated with a location, measured in meters.
  ellipsoidalAltitude: optional(size(number(), -100000, 100000)), // The altitude as a height above the World Geodetic System 1984 (WGS84) ellipsoid, measured in meters.
  floor: optional(size(integer(), 0, 1000)), // The logical floor of the building in which the user is located. If floor information is not available for the current location, the value of this property is nil
  horizontalAccuracy: optional(size(number(), -100000, 100000)), // The radius of uncertainty for the location, measured in meters. The location’s latitude and longitude identify the center of the circle, and this value indicates the radius of that circle. A negative value indicates that the latitude and longitude are invalid.
  verticalAccuracy: optional(size(number(), -100000, 100000)), // The validity of the altitude values, and their estimated uncertainty, measured in meters. A positive verticalAccuracy value represents the estimated uncertainty associated with altitude and ellipsoidalAltitude. This value is available whenever altitude values are available. If verticalAccuracy is 0 or a negative number, altitude and ellipsoidalAltitude values are invalid. If verticalAccuracy is a positive number, altitude and ellipsoidalAltitude values are valid.
  timestamp: optional(trimmed(iso8601())), // The time at which the location was determined.
  speed: optional(size(number(), -10000, 10000)), // The instantaneous speed of the device, measured in meters per second. This value reflects the instantaneous speed of the device as it moves in the direction of its current heading. A negative value indicates an invalid speed. Because the actual speed can change many times between the delivery of location events, use this property for informational purposes only.
  speedAccuracy: optional(size(number(), -10000, 10000)), // The accuracy of the speed value, measured in meters per second. When this property contains 0 or a positive number, the value in the speed property is plus or minus the specified number of meters per second. When this property contains a negative number, the value in the speed property is invalid.
  course: optional(size(number(), -360, 360)), // The direction in which the device is traveling, measured in degrees and relative to due north. Course values are measured in degrees starting at due north and continue clockwise around the compass. Thus, north is 0 degrees, east is 90 degrees, south is 180 degrees, and so on. Course values may not be available on all devices. A negative value indicates that the course information is invalid.
  courseAccuracy: optional(size(number(), -360, 360)), // The accuracy of the course value, measured in degrees. When this property contains 0 or a positive number, the value in the course property is plus or minus the specified number degrees, modulo 360. When this property contains a negative number, the value in the course property is invalid.
  magneticHeading: optional(size(number(), 0, 359)), // Heading relative to the magnetic North Pole, which is different from the geographic North Pole. The value 0 means the device is pointed toward magnetic north, 90 means it is pointed east, 180 means it is pointed south, and so on.
  headingAccuracy: optional(size(number(), -180, 180)), // A positive value in this property represents the potential error between the value reported by the magneticHeading property and the actual direction of magnetic north. Thus, the lower the value of this property, the more accurate the heading. A negative value means that the reported heading is invalid, which can occur when the device is uncalibrated or there is strong interference from local magnetic fields.
  trueHeading: optional(size(number(), 0, 359)), // Heading relative to the geographic North Pole. The value 0 means the device is pointed toward true north, 90 means it is pointed due east, 180 means it is pointed due south, and so on.
})

export type Location = Infer<typeof LocationStruct>

export const PersonStruct = object({
  type: defaulted(enums(['person']), 'person'),
  givenName: optional(size(trimmed(string()), 1, 32)),
  surname: optional(size(trimmed(string()), 1, 32)),
  organizationName: optional(size(trimmed(string()), 1, 64)),
  roles: optional(nonempty(array(size(trimmed(string()), 1, 32)))),
  email: optional(email()),
  uri: optional(URI()),
  address: optional(AddressStruct),
})

export type Person = Infer<typeof PersonStruct>

// Recursive JSON type: https://devblogs.microsoft.com/typescript/announcing-typescript-3-7/#more-recursive-type-aliases
export type Json =
  | string
  | number
  | boolean
  | null
  | Json[]
  | { [key: string]: Json }

const JsonStruct: Describe<Json> = nullable(
  union([
    string(),
    number(),
    boolean(),
    nullable(string()),
    array(lazy(() => JsonStruct)),
    record(
      string(),
      lazy(() => JsonStruct),
    ),
  ]),
)

export const SignatureStruct = object({
  type: defaulted(enums(['signature']), 'signature'),
  publicKey: base64(),
  signature: base64(),
  signatureType: enums(['ed25519']),
  signer: optional(PersonStruct),
})

export type Signature = Infer<typeof SignatureStruct>

// Incoming Cloudflare request properties
// https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties
export const ItemRequestPropsStruct = object({
  type: defaulted(enums(['item-req-props']), 'item-req-props'),
  asn: optional(nullable(union([integer(), string()]))),
  colo: optional(nullable(nonempty(string()))),
  country: optional(nullable(nonempty(string()))),
  city: optional(nullable(nonempty(string()))),
  continent: optional(nullable(nonempty(string()))),
  latitude: optional(nullable(nonempty(string()))),
  longitude: optional(nullable(nonempty(string()))),
  postalCode: optional(nullable(nonempty(string()))),
  metroCode: optional(nullable(nonempty(string()))),
  region: optional(nullable(nonempty(string()))),
  regionCode: optional(nullable(nonempty(string()))),
  timezone: optional(nullable(nonempty(string()))),
})

export type ItemRequestProps = Infer<typeof ItemRequestPropsStruct>

export const ItemDataStruct = object({
  type: defaulted(enums(['item-data']), 'item-data'),
  people: optional(nonempty(array(PersonStruct))),
  address: optional(AddressStruct),
  location: optional(LocationStruct),
  timestamp: optional(trimmed(iso8601())),
  content: JsonStruct, // Arbitrary content, must be serializable to valid JSON
})

export type ItemData = Infer<typeof ItemDataStruct>

// User submitted Item
// An Item is a wrapper around ItemData, with a hash and optional signature over the ItemData
// The Item will be decorated with additional properties, such as the Cloudflare worker request properties
// and the latest entropy hash value from the Observable Entropy project.
export const ItemStruct = object({
  type: defaulted(enums(['item']), 'item'),
  hash: pattern(size(trimmed(string()), 20 * 2, 64 * 2), REGEX_HASH_HEX_20_64), // MUST be h(canonify(data))
  hashType: enums(Object.keys(HASH_TYPES)),
  signatures: optional(nonempty(array(SignatureStruct))), // One, or more, sign(hash||hashType)
  data: optional(nonempty(array(ItemDataStruct))),
  request: optional(ItemRequestPropsStruct), // Cloudflare request properties
  observableEntropy: optional(
    pattern(size(trimmed(string()), 32 * 2), REGEX_HASH_HEX_32),
  ), // Observable Entropy : latest SHA-256 hash : https://github.com/truestamp/observable-entropy/blob/main/README.md
})

export type Item = Infer<typeof ItemStruct>

// A subset of ItemStruct, used to validate user provided input
export const ItemRequestStruct = pick(ItemStruct, [
  'hash',
  'hashType',
  'signatures',
  'data',
])

export type ItemRequest = Infer<typeof ItemRequestStruct>

// An Envelope is a wrapper around an Item, with a hash and signature over the Item
export const EnvelopeStruct = object({
  type: defaulted(enums(['envelope']), 'envelope'),
  owner: string(), // DB only
  ulid: string(), // DB only
  id: truestampId(), // Response only
  hash: pattern(string(), REGEX_HASH_HEX_32), // MUST be h(canonify(data))
  hashType: enums(['sha-256']),
  signatures: nonempty(array(SignatureStruct)), // One, or more, sign(hash||hashType)
  data: ItemStruct,
  timestamp: iso8601UTC(), // Response only
})

export type Envelope = Infer<typeof EnvelopeStruct>

// A subset of EnvelopeStruct, used to send the envelope to the database
export const EnvelopeDbStruct = omit(EnvelopeStruct, ['id', 'timestamp'])

export type EnvelopeDb = Infer<typeof EnvelopeDbStruct>

// A subset of EnvelopeStruct, used to respond to user requests
export const EnvelopeResponseStruct = omit(EnvelopeStruct, ['owner', 'ulid'])

export type EnvelopeResponse = Infer<typeof EnvelopeResponseStruct>

export const SNSTopicMessageStruct = object({
  owner: optional(nonempty(string())),
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
})

export type SNSTopicMessage = Infer<typeof SNSTopicMessageStruct>

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
  intent: enums(['btc', 'eth', 'twitter', 'xlm']),
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
  type: defaulted(enums(['commitment']), 'commitment'),
  hash: pattern(string(), REGEX_HASH_HEX_32), // MUST be h(canonify(data))
  hashType: enums(['sha-256']),
  signatures: nonempty(array(SignatureStruct)), // One, or more, sign(hash||hashType)
  data: CommitmentDataStruct,
  timestamp: iso8601UTC(),
})

export type Commitment = Infer<typeof CommitmentStruct>

export const ULIDResponseStruct = object({
  t: number(),
  ts: iso8601UTC(),
  ulid: string(),
})

export type ULIDResponse = Infer<typeof ULIDResponseStruct>

export const ULIDResponseCollectionStruct = array(ULIDResponseStruct)

export type ULIDResponseCollection = Infer<typeof ULIDResponseCollectionStruct>
export const VerificationProofStruct = object({
  ok: boolean(),
  inputHash: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  merkleRoot: nonempty(pattern(size(string(), 32 * 2), REGEX_HASH_HEX_32)),
  error: optional(string()),
})

export type VerificationProof = Infer<typeof VerificationProofStruct>

export const VerificationTransactionStruct = object({
  intent: enums(['btc', 'eth', 'twitter', 'xlm']),
  ok: boolean(),
  offline: boolean(),
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
  id: truestampId(),
  ok: boolean(),
  offline: boolean(),
  testEnv: optional(boolean()),
  signature: optional(
    object({
      hash: boolean(),
      publicKey: boolean(),
      verified: boolean(),
      error: optional(string()),
    }),
  ),
  proofs: optional(nonempty(array(VerificationProofStruct))),
  transactions: optional(nonempty(array(VerificationTransactionStruct))),
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

export const SignedKeysStruct = array(SignedKeyStruct)

export type SignedKeys = Infer<typeof SignedKeysStruct>

export const UnsignedKeyStruct = omit(SignedKeyStruct, ['selfSignature'])

export type UnsignedKey = Infer<typeof UnsignedKeyStruct>

export interface CanonicalHash {
  hash: Uint8Array
  hashHex: string
  hashType: string
}
