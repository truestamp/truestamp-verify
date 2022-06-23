import { DateTime } from 'luxon'
import { canonify } from '@truestamp/canonify'
import { hash as stableSHA256 } from '@stablelib/sha256'
import { equal } from '@stablelib/constant-time'
import { encode as hexEncode } from '@stablelib/hex'
import { decode as base64Decode } from '@stablelib/base64'
import { sha256 } from '@truestamp/tree'
import { create, is } from 'superstruct'
import { verify as verifyEd25519 } from '@stablelib/ed25519'

import unfetch from 'isomorphic-unfetch'

import {
  CanonicalHash,
  CommitmentData,
  Item,
  ItemData,
  SignedKey,
  SignedKeyStruct,
  SignedKeysStruct,
  UnsignedKey,
  EntropyResponse,
  EntropyResponseStruct,
} from './types'

const ENTROPY_SERVER_BASE_URL = 'https://entropy.truestamp.com'
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
 * Default function to fetch the current JSON string value for an Observable Entropy hash.
 * In some cases this function will be replaced with a custom function. For example, if the
 * function needs to be called against a Cloudflare worker service binding.
 */
export async function getEntropyFromHash(hash: string): Promise<EntropyResponse | undefined> {
  try {
    const entropyUrl = `${ENTROPY_SERVER_BASE_URL}/hash/${hash}`
    const entropyResp = await unfetch(entropyUrl)

    if (entropyResp.ok) {
      const entropyObj = (await entropyResp.json()) as EntropyResponse
      return create(entropyObj, EntropyResponseStruct)
    }
  } catch (error) {
    // Ignore error
  }

  return undefined
}

export function timestampMicrosecondsToISO(timestamp: number): string {
  return DateTime.fromMillis(Math.floor(timestamp / 1000))
    .toUTC()
    .toISO()
}

/**
 * For a given public key, calculate its handle.
 * @param publicKey The public key to calculate the handle for
 * @return The public key's handle
 */
export function getHandleForPublicKey(publicKey: Uint8Array): string {
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
export async function getKeyByHandle(handle: string, keys?: SignedKey[], offline?: boolean): Promise<SignedKey | undefined> {
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
export async function publicKeyMatchesKnownPublicKey(publicKey: Uint8Array, keys?: SignedKey[], offline?: boolean): Promise<boolean> {
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
export function canonicalizeAndHashData(data: Item | ItemData[] | CommitmentData | UnsignedKey): CanonicalHash {
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
