# @truestamp/verify

This library provides a TypeScript/JavaScript API for verifying
[Truestamp](https://www.truestamp.com) Commitments.

This library provides a thorough cryptographic verification of
Truestamp Commitments. Ideally, this verification is independent of, and without
reliance on, Truestamp services or APIs. This library has no external
dependencies.

This independence helps provides users with the confidence that their
Commitments are verifiable for the long term. The code for this verification is
intended to be simple to audit so as to provide confidence in its functionality
and security.

The verification of the cryptographic integrity of the Commitment is **always**
performed locally and requires no access to the Internet. There are requests
made to external services for the purpose of comparing locally calculated
results to the values expected to be stored on-chain and to determine the
timestamp that a commitment attests to.

If an array of signed public keys is provided as an argument to the various
verification functions, as can be found on the server
[https://keys.truestamp.com](https://keys.truestamp.com), they will be used and
no connections to a key server will be attempted.

When `verify()` is called, an object will be returned that provides details of
the status of each verification performed on a commitment as well as an `ok`
property to indicated success or failure.

Alternatively, there are functions that will only return a boolean, or throw an
`Error` if there is any verification failure.

## About Commitments

A Truestamp Commitment is the cryptographic "glue" that binds your original data,
and additional metadata, to one or more public blockchains.

You'll note that commitments do not attest to the "answer" to a question. They are
more analogous to the left side of a math equation. All of the elements are there to
do the math and calculate an answer, and this calculated answer is then compared to
what is found on the blockchain. The "math" is check along the way to ensure that
a series of equations generate consistent results.

If the verification of the Commitment is a match to what is found on the blockchain, we
can be certain of the integrity of the data reflected in the Commitment.

Once this verification of integrity is confirmed, the timestamp of the data
can then be extracted from the blockchain block the data was committed to.

If any part of the equation fails, or if the data was changed by even a single bit, then
the Commitment will fail to be fully processed and return an error, or the expected data
will not be found actually committed to the blockchain. In this case the commitment is
considered invalid and the output of the verification functions will reflect that.

## Install

```sh
npm install @truestamp/verify
```

## Sample Usage

Node.js:

```javascript
// Node.js Require
const { assertVerified, isVerified, verify } = require('@truestamp/verify')

// ES Modules Import
// import { assertVerified, isVerified, verify } from '@truestamp/verify';

// Substitute with a Truestamp commitment object to be verified.
const commitment = {...}

// Returns a Promise that resolves to an object that details commitment
// properties and a summary of what this commitment attests to.
// It also provides pointers to the web URL's (e.g. blockchain explorer API)
// that were used to verify transactions and where commitments can be
// manually verified by comparing a hash with your own eyes.
console.log('verify', await verify(commitment))

// Resolves to boolean `true` or `false` and will not throw Errors
if (await isVerified(commitment)) {
  console.log('verified')
} else {
  console.log('bad commitment')
}

// Throws an Error on commitment validation issue,
// or external service verification failure. Resolves
// to `void` (returns nothing) if verified OK.
await assertVerified(commitment)
```

A more detailed version of this example can be found in [examples/example.cjs].

## Sample JSON Verifier Output

The `ok` property will be set to true if the entirety of the Commitment is valid.

If there are errors along the way that will be reflected in the verifier output.

```json
{
  "ok": true,
  "id": "T11_01G63P5WPW0CWJ7N6WGAXEXGJH_1655833818400000_A6D3501894C9D27D3A626B6E1ACFCD1B",
  "offline": false,
  "testEnv": true,
  "itemData": {
    "hash": "c15fbfedf73881e7264ccefbabdcb679d247348e35dea14eba1d906c174c3e8e",
    "signaturesCount": 1,
    "signaturesVerified": true
  },
  "item": {
    "hash": "7901019d4f28788058e5e661e756d33049ad40f69dbf3057c8260f1dde8dfeb8"
  },
  "commitmentData": {
    "hash": "bf58d1780fe8a5fb30be1599781e96857bc21e3eb0a530f1c3d75b72d51833c9",
    "signaturesCount": 1,
    "signaturesVerified": true,
    "signaturesPublicKeyVerified": true
  },
  "proofs": [
    {
      "ok": true,
      "inputHash": "7901019d4f28788058e5e661e756d33049ad40f69dbf3057c8260f1dde8dfeb8",
      "merkleRoot": "7d371488a002714c9d2efb7f86da7c289bd865d0b359a1dadd13966078f7abce"
    }
  ],
  "transactions": [
    {
      "ok": true,
      "offline": false,
      "intent": "xlm",
      "inputHash": "7d371488a002714c9d2efb7f86da7c289bd865d0b359a1dadd13966078f7abce",
      "transactionId": "09f0c766b0d393f27a7eddfceea46167106cd8fd4f21756196117876d5880503",
      "blockId": "1600114",
      "timestamp": "2022-06-21T17:52:06Z",
      "urlApi": "https://horizon-testnet.stellar.org/transactions/09f0c766b0d393f27a7eddfceea46167106cd8fd4f21756196117876d5880503",
      "urlWeb": "https://stellar.expert/explorer/testnet/tx/09f0c766b0d393f27a7eddfceea46167106cd8fd4f21756196117876d5880503"
    }
  ]
}
```

## API Documentation

The
[TypeScript API documentation](https://truestamp.github.io/truestamp-verify/)
for this project is generated and published upon each new release.

## Testing

This library aims to achieve 100% code test coverage.

```sh
npm install
npm test
```

## Contributing

We'd love you to join our network of contributors. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) for help getting started.

### Releasing

- Commit changes, merge PR's to `main` branch
- Bump `version` field in `package.json`
- Cut a new [release](https://github.com/truestamp/truestamp-verify/releases)
- New release will trigger workflow to build, test, and publish package to
  [Github Package Registry](https://github.com/truestamp/truestamp-verify/packages)
  and [NPM.js](https://www.npmjs.com/package/@truestamp/verify).

## Code of Conduct

We expect all members of the community to respect our
[Code of Conduct](CODE_OF_CONDUCT.md) at all times.

## Legal

Copyright © 2022 Truestamp Inc. All Rights Reserved.
