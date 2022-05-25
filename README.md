# @truestamp/verify

This library provides a TypeScript/JavaScript API for verifying
[Truestamp](https://www.truestamp.com) Commitments.

This library is intended to provide thorough cryptographic verification of
Truestamp Commitments. Ideally, this verification is independent of,
and without reliance on, Truestamp services or APIs. This library has
no external dependencies.

This independence helps provides users with the confidence that their Commitments
are verifiable for the long term. The code for this verification is intended
to be simple to audit so as to provide confidence in its functionality and security.

The verification of the cryptographic integrity of the Commitment is **always**
performed locally and requires no access to the Internet. There are requests
made to external services for the purpose of comparing locally calculated
results to the values expected to be stored on-chain and to determine the
timestamp that a commitment attests to.

Currently, the server [https://keys.truestamp.com](https://keys.truestamp.com) will be called to help verify that the
public key in the signature is authoritative.

When `verify()` is called, an object will be returned that provides details of the
status of each verification performed on a commitment as well as an `ok` property to
indicated success or failure.

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

## Sample Output

```javascript
{
  type: 'commitment-verification',
  ok: true,
  offline: false,
  testEnv: true,
  signature: { hash: true, publicKey: true, verified: true },
  proofs: [
    {
      ok: true,
      inputHash: 'b1fc469deae708277eb87b089800731a57f61ddbddf0c71332288397daffa8fa',
      merkleRoot: 'ebbe387c731b1fdcee412b4fc7c82d966cd0276e79c6a9c319e304dd78dedac4'
    },
    {
      ok: true,
      inputHash: 'ebbe387c731b1fdcee412b4fc7c82d966cd0276e79c6a9c319e304dd78dedac4',
      merkleRoot: '93c5277c0135e85b61a9798345e8c3ea21b17c0f85defe45e390b4758cf1b16b'
    },
    {
      ok: true,
      inputHash: '93c5277c0135e85b61a9798345e8c3ea21b17c0f85defe45e390b4758cf1b16b',
      merkleRoot: '333e65c8b3ee8c4a095dfb97890d295a0d36097cf03e391118f4a214e8c171a2'
    },
    {
      ok: true,
      inputHash: '333e65c8b3ee8c4a095dfb97890d295a0d36097cf03e391118f4a214e8c171a2',
      merkleRoot: '37aea4f6c62d1fb647fca9e13f90a474033fdd0102df00c80623ab8e6dd9aefe'
    }
  ],
  transactions: [
    {
      ok: true,
      offline: false,
      intent: 'xlm',
      inputHash: 'ebbe387c731b1fdcee412b4fc7c82d966cd0276e79c6a9c319e304dd78dedac4',
      transactionId: '3c702c91598c7ae69d80d6cebe4faf329680ddadb6c2621ad8235f0f999e37a9',
      blockId: '1071745',
      timestamp: '2022-05-20T14:33:03Z',
      urlApi: 'https://horizon-testnet.stellar.org/transactions/3c702c91598c7ae69d80d6cebe4faf329680ddadb6c2621ad8235f0f999e37a9',
      urlWeb: 'https://stellar.expert/explorer/testnet/tx/3c702c91598c7ae69d80d6cebe4faf329680ddadb6c2621ad8235f0f999e37a9'
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
