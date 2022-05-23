// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

import { verify, isVerified, assertVerified } from '../src/index'

// import goodCommitment from ("./commitments/good.json")
const goodCommitment = require("./commitments/good.json");
const badHashCommitment = require("./commitments/badHash.json");

describe('verify()', () => {
  describe('with a known good commitment', () => {
    test('should return a verified commitment response', async () => {
      const result = await verify(goodCommitment);
      // console.log(JSON.stringify(result, null, 2));
      expect(result).toBeTruthy();
    });
  });

  describe('with a known bad commitment', () => {
    test('should return false when the commitment hash is bad', async () => {
      const result = await verify(badHashCommitment);
      console.log(JSON.stringify(result, null, 2));
      expect(result.verified).toBeFalsy();
      expect(result.signatureHashVerified).toBeFalsy();
      expect(result.signatureVerified).toBeFalsy();
      expect(result.error).toContain("invalid attribute for 'hash'");
    });
  });

})

describe('isVerified()', () => {
  describe('with a known good commitment', () => {
    test('should return true', async () => {
      const result = await isVerified(goodCommitment);
      expect(result).toBeTruthy();
    });
  });

  describe('with a known bad commitment', () => {
    test('should return false', async () => {
      const result = await isVerified(badHashCommitment);
      expect(result).toBeFalsy();
    });
  });

})

describe('assertVerified()', () => {
  describe('with a known good commitment', () => {
    test('should return void and not throw', async () => {
      const result = await assertVerified(goodCommitment);
      expect(result).toBeUndefined();
    });
  });

  describe('with a known bad commitment', () => {
    test('should throw an Error', () => {
      expect.assertions(1);
      return assertVerified(badHashCommitment).catch(e => expect(e.message).toMatch('Commitment is not valid'));
    });
  });

})
