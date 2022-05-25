// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import {
  verify,
  isVerified,
  isVerifiedUnsafelyOffline,
  assertVerified,
  assertVerifiedUnsafelyOffline,
} from '../src/index'

const goodCommitment = require('./commitments/good.json')
const badHashCommitment = require('./commitments/badHash.json')
const offlineKeys = require('./keys.json')

describe('verify()', () => {
  describe('online', () => {
    describe('with a known good commitment', () => {
      test('should return a commitment status of passed', async () => {
        const result = await verify(goodCommitment)
        expect(result).toBeTruthy()
        expect(result.ok).toEqual(true)
        expect(result.offline).toEqual(false)
        expect(result.testEnv).toEqual(true)
        expect(result.signature?.hash).toEqual(true)
        expect(result.signature?.publicKey).toEqual(true)
        expect(result.signature?.verified).toEqual(true)
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
          for (const transaction of result.transactions) {
            expect(transaction.ok).toEqual(true)
            expect(transaction.offline).toEqual(false)
            expect(
              ['btc', 'eth', 'twitter', 'xlm'].includes(transaction.intent),
            ).toBeTruthy()
            expect(/^[0-9a-f]+$/.test(transaction.inputHash)).toEqual(true)
            expect(transaction.transactionId?.length).toBeGreaterThanOrEqual(1)
            expect(transaction.blockId?.length).toBeGreaterThanOrEqual(1)
          }
        }
      })
    })

    describe('with a known bad commitment', () => {
      test('should return false when the commitment hash is bad', async () => {
        const result = await verify(badHashCommitment)
        expect(result.ok).toEqual(false)
        expect(result.offline).toEqual(false)
        expect(result.signature).toBeUndefined()
        expect(result.error).toContain("invalid attribute for 'hash'")
      })
    })
  })

  describe('offline', () => {
    describe('with a known good commitment', () => {
      test('should return a commitment ok with keys provided', async () => {
        const result = await verify(goodCommitment, {
          keys: offlineKeys,
          offline: true,
        })
        expect(result).toBeTruthy()
        expect(result.ok).toEqual(true)
        expect(result.offline).toEqual(true)
        expect(result.testEnv).toEqual(true)
        expect(result.signature?.hash).toEqual(true)
        expect(result.signature?.publicKey).toEqual(true)
        expect(result.signature?.verified).toEqual(true)
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
          for (const transaction of result.transactions) {
            expect(transaction.ok).toEqual(true)
            expect(transaction.offline).toEqual(true)
            expect(
              ['btc', 'eth', 'twitter', 'xlm'].includes(transaction.intent),
            ).toBeTruthy()
            expect(/^[0-9a-f]+$/.test(transaction.inputHash)).toEqual(true)
            expect(transaction.transactionId?.length).toBeGreaterThanOrEqual(1)
            expect(transaction.blockId?.length).toBeGreaterThanOrEqual(1)
          }
        }
      })

      test('should return a commitment ok with no keys provided', async () => {
        const result = await verify(goodCommitment, {
          offline: true,
        })
        expect(result).toBeTruthy()
        expect(result.ok).toEqual(true)
        expect(result.offline).toEqual(true)
        expect(result.testEnv).toEqual(true)
        expect(result.signature?.hash).toEqual(true)
        expect(result.signature?.publicKey).toEqual(true)
        expect(result.signature?.verified).toEqual(true)
      })

    })

    describe('with a known bad commitment', () => {
      test('should return false when the commitment hash is bad', async () => {
        const result = await verify(badHashCommitment, { offline: true })
        expect(result.ok).toEqual(false)
        expect(result.offline).toEqual(true)
        expect(result.signature).toBeUndefined()
        expect(result.error).toContain("invalid attribute for 'hash'")
      })
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
      return assertVerified(badHashCommitment).catch(e =>
        expect(e.message).toMatch('Commitment is not valid'),
      )
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
      return assertVerifiedUnsafelyOffline(badHashCommitment).catch(e =>
        expect(e.message).toMatch('Commitment is not valid'),
      )
    })
  })
})
