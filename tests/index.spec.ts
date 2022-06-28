// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { string } from 'zod'
import { verify, verifyUnsafelyOffline, isVerified, isVerifiedUnsafelyOffline, assertVerified, assertVerifiedUnsafelyOffline } from '../src/index'

const goodCommitment = require('./commitments/good.json')
const badHashCommitment = require('./commitments/badHash.json')
const offlineKeys = require('./keys.json')

import { CommitTransactionBitcoin, CommitTransactionEthereum, CommitTransactionStellar, CommitTransactionTwitter, VerificationTransaction, EntropyResponse } from '../src/modules/types'

async function mockGetEntropyFromHash(hash: string): Promise<EntropyResponse | undefined> {
  const entropy: EntropyResponse = {
    files: [
      { name: 'bitcoin.json', hash: '15bf04ad96321f7c19ca48e2d4fa8a8b6010ab1edb14c69a9c5a66c7a9c09079', hashType: 'sha256' },
      { name: 'drand-beacon.json', hash: '0bbb6ceec71af4e0c4498181f4680112a2120e7ed8bf88d9ae5dfadd7d9eb0d5', hashType: 'sha256' },
      { name: 'entropy_previous.json', hash: '99733551042778e9229d3745829a8b7f55351e9e2cfdf537b12e60d31f76ac6a', hashType: 'sha256' },
      { name: 'ethereum.json', hash: '38064f29e78919480d1c7e6895f380e745c93181831835a2f1e2701989822b14', hashType: 'sha256' },
      { name: 'hacker-news.json', hash: '9a075f43a9985c4d2cc30407f92563f4a0fc2cdc82394a0c85cbd87de186890d', hashType: 'sha256' },
      { name: 'nist-beacon.json', hash: '9eb292eeb5e952a825d5e8c5daee6ffff030d7fce9f7b2807b53e81b281fb553', hashType: 'sha256' },
      { name: 'stellar.json', hash: '1acea9abf4e33dc304ae31fa4f24c4f140c3d3f1dbc781424d020016600b6c31', hashType: 'sha256' },
      { name: 'timestamp.json', hash: 'd0d2bd4d711a16964dbccff8863a266cd4e9f931319e0b2e4c3adc94f3584c83', hashType: 'sha256' },
      { name: 'user-entropy.json', hash: '62bb03259d2d130d863376adc233fc94b4ccae641b3fc49396c619fa8e9cf829', hashType: 'sha256' },
    ],
    hashType: 'sha256',
    hashIterations: 500000,
    hash: 'e9e24e1a552f4f78691d225a6e2af5f56c61cbb38b3d39e0bfc2a81c8679344a',
    createdAt: '2022-04-09T14:40:23.359Z',
    signature: '7609cd8398454fa7c2d1b2cc384f9d6a5cd0682dd215264680a8283c2c5ff185b1d6af16fb8e1f915b324f523d61c9035f110f64bb942a0f80e66fbde35d0505',
    prevHash: '99f633aacafbc6c48212b44c490404a2c51192fb12e3b2a0b97278ef7ab53fd3',
  }

  return EntropyResponse.parse(entropy)
}

describe('verify()', () => {
  describe('with a known good commitment', () => {
    test('should return a commitment status of passed', async () => {
      const result = await verify(goodCommitment)
      expect(result).toBeTruthy()
      expect(result.success).toEqual(true)
      expect(result.offline).toEqual(false)
      expect(result.testnet).toEqual(true)
      expect(result.commitmentData?.signaturesCount).toEqual(1)
      expect(result.commitmentData?.signaturesVerified).toEqual(true)
      expect(result.itemData?.signaturesCount).toEqual(1)
      expect(result.itemData?.signaturesVerified).toEqual(true)
      expect(result.proofs).toBeInstanceOf(Array)
      expect(result.proofs?.length).toBeGreaterThanOrEqual(1)

      if (result.proofs) {
        for (const proof of result.proofs) {
          expect(proof.ok).toEqual(true)
          expect(/^[0-9a-f]+$/.test(proof.inputHash)).toEqual(true)
          expect(/^[0-9a-f]+$/.test(proof.merkleRoot)).toEqual(true)
        }
      }

      expect(result.transactions).toBeInstanceOf(Array)
      expect(result.transactions?.length).toBeGreaterThanOrEqual(1)

      if (result.transactions) {
        for (const vt of result.transactions) {
          expect(VerificationTransaction.safeParse(vt).success).toEqual(true)
          expect(vt.success).toEqual(true)
          expect(vt.offline).toEqual(false)

          switch (vt.intent) {
            case "bitcoin":
              expect(vt.intent).toEqual("bitcoin")
              expect(CommitTransactionBitcoin.safeParse(vt.transaction).success).toEqual(true)
              break;

            case "ethereum":
              expect(vt.intent).toEqual("ethereum")
              expect(CommitTransactionEthereum.safeParse(vt.transaction).success).toEqual(true)
              break;

            case "stellar":
              expect(vt.intent).toEqual("stellar")
              expect(CommitTransactionStellar.safeParse(vt.transaction).success).toEqual(true)
              break;

            case "twitter":
              expect(vt.intent).toEqual("twitter")
              expect(CommitTransactionTwitter.safeParse(vt.transaction).success).toEqual(true)
              break;

            default:
              break;
          }
        }
      }

      expect(result.commitsTo?.hashes).toBeInstanceOf(Array)
      expect(result.commitsTo?.hashes.length).toBeGreaterThanOrEqual(1)
      expect(result.commitsTo?.observableEntropy).toBeTruthy()
      expect(result.commitsTo?.timestamps).toBeTruthy()
      expect(result.commitsTo?.timestamps.submittedAfter).toBeTruthy()
      expect(result.commitsTo?.timestamps.submittedAt).toBeTruthy()
      expect(result.commitsTo?.timestamps.submittedBefore).toBeTruthy()
      expect(result.commitsTo?.timestamps.submitWindowMilliseconds).toBeGreaterThanOrEqual(1)
    })

    test('should use an external entropyFromHashFunction', async () => {
      const result = await verify(goodCommitment, { entropyFromHashFunction: mockGetEntropyFromHash })
      expect(result.success).toEqual(true)
      expect(result.commitsTo?.timestamps?.submittedAfter).toEqual("2022-04-09T14:40:23.359Z")
    })

  })

  describe('with a known bad commitment', () => {
    test('should return false when the commitment hash is bad', async () => {
      const result = await verify(badHashCommitment)
      expect(result.success).toEqual(false)
      expect(result.offline).toEqual(false)
      expect(result.error).toContain("Commitment invalid : invalid_string : [commitmentData, itemData, 0, hash] : Invalid")
    })
  })
})

describe('verifyUnsafelyOffline()', () => {
  describe('with a known good commitment', () => {
    test('should return a commitment success with keys provided', async () => {
      const result = await verifyUnsafelyOffline(goodCommitment, {
        keys: offlineKeys,
      })
      expect(result).toBeTruthy()
      expect(result.success).toEqual(true)
      expect(result.offline).toEqual(true)
      expect(result.testnet).toEqual(true)
      expect(result.commitmentData?.signaturesCount).toEqual(1)
      expect(result.commitmentData?.signaturesVerified).toEqual(true)
      expect(result.itemData?.signaturesCount).toEqual(1)
      expect(result.itemData?.signaturesVerified).toEqual(true)
      expect(result.proofs).toBeInstanceOf(Array)
      expect(result.proofs?.length).toBeGreaterThanOrEqual(1)

      if (result.proofs) {
        for (const proof of result.proofs) {
          expect(proof.ok).toEqual(true)
          expect(/^[0-9a-f]+$/.test(proof.inputHash)).toEqual(true)
          expect(/^[0-9a-f]+$/.test(proof.merkleRoot)).toEqual(true)
        }
      }

      expect(result.transactions).toBeInstanceOf(Array)
      expect(result.transactions?.length).toBeGreaterThanOrEqual(1)

      if (result.transactions) {
        for (const vt of result.transactions) {
          expect(VerificationTransaction.safeParse(vt).success).toEqual(true)
          expect(vt.success).toEqual(true)
          expect(vt.offline).toEqual(true)

          switch (vt.intent) {
            case "bitcoin":
              expect(vt.intent).toEqual("bitcoin")
              expect(CommitTransactionBitcoin.safeParse(vt.transaction).success).toEqual(true)
              break;

            case "ethereum":
              expect(vt.intent).toEqual("ethereum")
              expect(CommitTransactionEthereum.safeParse(vt.transaction).success).toEqual(true)
              break;

            case "stellar":
              expect(vt.intent).toEqual("stellar")
              expect(CommitTransactionStellar.safeParse(vt.transaction).success).toEqual(true)
              break;

            case "twitter":
              expect(vt.intent).toEqual("twitter")
              expect(CommitTransactionTwitter.safeParse(vt.transaction).success).toEqual(true)
              break;

            default:
              break;
          }
        }
      }
    })

    test('should return a commitment success with no keys provided', async () => {
      const result = await verifyUnsafelyOffline(goodCommitment)
      expect(result).toBeTruthy()
      expect(result.success).toEqual(true)
      expect(result.offline).toEqual(true)
      expect(result.testnet).toEqual(true)
      expect(result.commitmentData?.signaturesCount).toEqual(1)
      expect(result.commitmentData?.signaturesVerified).toEqual(true)
      expect(result.itemData?.signaturesCount).toEqual(1)
      expect(result.itemData?.signaturesVerified).toEqual(true)
    })
  })

  describe('with a known bad commitment', () => {
    test('should return false when the commitment hash is bad', async () => {
      const result = await verifyUnsafelyOffline(badHashCommitment)
      expect(result.success).toEqual(false)
      expect(result.offline).toEqual(true)
      expect(result.error).toContain("Commitment invalid : invalid_string : [commitmentData, itemData, 0, hash] : Invalid")
    })
  })
})

describe('isVerified()', () => {
  describe('with a known good commitment', () => {
    test('should return true', async () => {
      const result = await isVerified(goodCommitment)
      expect(result).toEqual(true)
    })
  })

  describe('with a known bad commitment', () => {
    test('should return false', async () => {
      const result = await isVerified(badHashCommitment)
      expect(result).toEqual(false)
    })
  })
})

describe('isVerifiedUnsafelyOffline()', () => {
  describe('with a known good commitment', () => {
    test('should return true', async () => {
      const result = await isVerifiedUnsafelyOffline(goodCommitment)
      expect(result).toEqual(true)
    })
  })

  describe('with a known bad commitment', () => {
    test('should return false', async () => {
      const result = await isVerifiedUnsafelyOffline(badHashCommitment)
      expect(result).toEqual(false)
    })
  })
})

describe('assertVerified()', () => {
  describe('with a known good commitment', () => {
    test('should return void and not throw', async () => {
      const result = await assertVerified(goodCommitment)
      expect(result).toBeUndefined()
    })
  })

  describe('with a known bad commitment', () => {
    test('should throw an Error', () => {
      expect.assertions(1)
      return assertVerified(badHashCommitment).catch(e => expect(e.message).toMatch("Commitment invalid : invalid_string : [commitmentData, itemData, 0, hash] : Invalid"))
    })
  })
})

describe('assertVerifiedUnsafelyOffline()', () => {
  describe('with a known good commitment', () => {
    test('should return void and not throw', async () => {
      const result = await assertVerifiedUnsafelyOffline(goodCommitment)
      expect(result).toBeUndefined()
    })
  })

  describe('with a known bad commitment', () => {
    test('should throw an Error', () => {
      expect.assertions(1)
      return assertVerifiedUnsafelyOffline(badHashCommitment).catch(e => expect(e.message).toMatch("Commitment invalid : invalid_string : [commitmentData, itemData, 0, hash] : Invalid"))
    })
  })
})
