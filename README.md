# @truestamp/verify

This library provides a TypeScript/JavaScript API for verifying [Truestamp](https://www.truestamp.com) Commitments.

This library provides a thorough cryptographic verification of Truestamp Commitments. Ideally, this verification is independent of, and without reliance on,
Truestamp services or APIs. This library has no external dependencies.

This independence helps provides users with the confidence that their Commitments are verifiable for the long term. The code for this verification is intended
to be simple to audit so as to provide confidence in its functionality and security.

The verification of the cryptographic integrity of the Commitment is **always** performed locally and requires no access to the Internet. There are requests
made to external services for the purpose of comparing locally calculated results to the values expected to be stored on-chain and to determine the timestamp
that a commitment attests to.

If an array of signed public keys is provided as an argument to the various verification functions, as can be found on the server
[https://keys.truestamp.com](https://keys.truestamp.com), they will be used and no connections to a key server will be attempted.

When `verify()` is called, an object will be returned that provides details of the status of each verification performed on a commitment as well as an `ok`
property to indicated success or failure.

Alternatively, there are functions that will only return a boolean, or throw an `Error` if there is any verification failure.

## About Commitments

A Truestamp Commitment is the cryptographic "glue" that binds your original data, and additional metadata, to one or more public blockchains.

You'll note that commitments do not attest to the "answer" to a question. They are more analogous to the left side of a math equation. All of the elements are
there to do the math and calculate an answer, and this calculated answer is then compared to what is found on the blockchain. The "math" is check along the way
to ensure that a series of equations generate consistent results.

If the verification of the Commitment is a match to what is found on the blockchain, we can be certain of the integrity of the data reflected in the Commitment.

Once this verification of integrity is confirmed, the timestamp of the data can then be extracted from the blockchain block the data was committed to.

If any part of the equation fails, or if the data was changed by even a single bit, then the Commitment will fail to be fully processed and return an error, or
the expected data will not be found actually committed to the blockchain. In this case the commitment is considered invalid and the output of the verification
functions will reflect that.

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

If there are errors they will be reflected in the verifier output `error` property and `ok` will be `false`.

The `commitsTo` property contains values that are verifiable and are derived from
the successful verification of a Commitment.

- `submittedAfter` : A timestamp retrieved from Observable Entropy that your Item must have been submitted after.
- `submittedAt` : A timestamp that was embedded in the Truestamp Id, representing the time we recorded submission via the API.
- `submittedBefore` : The earliest timestamp that Commitment `transactions` are verified against. This is retrieved from on-chain block/ledger data.
- `submitWindowMilliseconds` : The time difference, in milliseconds, between `submittedAfter` and `submittedBefore`.

```json
{
  "id": "T11_01G6ND2ZAP3QQWJGM4AGTRCQ9P_1656428265850000_0D6F6F7057B6C0AEF63D043A5AB0FF79",
  "success": true,
  "offline": false,
  "testnet": true,
  "itemData": {
    "hash": "c15fbfedf73881e7264ccefbabdcb679d247348e35dea14eba1d906c174c3e8e",
    "signaturesCount": 1,
    "signaturesVerified": true
  },
  "item": {
    "hash": "6c624010de9050296f78daf1865eea20cf1e787d8cf9c81fdf43a3e70ce2ae20"
  },
  "commitmentData": {
    "hash": "813a5342ae5bafcc10ce375a9de87eabe70a310db5c5dede18ad93a98984c256",
    "signaturesCount": 1,
    "signaturesVerified": true,
    "signaturesPublicKeyVerified": true
  },
  "proofs": [
    {
      "ok": true,
      "inputHash": "6c624010de9050296f78daf1865eea20cf1e787d8cf9c81fdf43a3e70ce2ae20",
      "merkleRoot": "4ac380cda4821b1e5fb2c5ce6e7ae19ff1a8ee11b828061ab25ddc49e1ef24f5"
    },
    {
      "ok": true,
      "inputHash": "4ac380cda4821b1e5fb2c5ce6e7ae19ff1a8ee11b828061ab25ddc49e1ef24f5",
      "merkleRoot": "b4fe024ab042302b02763fcd0ebe8b12e8394c623bf8d2565b931c0e44d21f26"
    }
  ],
  "transactions": [
    {
      "intent": "stellar",
      "success": true,
      "offline": false,
      "transaction": {
        "inputHash": "4ac380cda4821b1e5fb2c5ce6e7ae19ff1a8ee11b828061ab25ddc49e1ef24f5",
        "intent": "stellar",
        "hash": "50e43c22fc2274d72fb82e74a24eac50de33d71060deb75d50a6b56ab6c258db",
        "ledger": 101654
      },
      "timestamp": "2022-06-28T14:59:07Z",
      "urls": [
        "https://horizon-testnet.stellar.org/transactions/50e43c22fc2274d72fb82e74a24eac50de33d71060deb75d50a6b56ab6c258db",
        "https://stellar.expert/explorer/testnet/tx/50e43c22fc2274d72fb82e74a24eac50de33d71060deb75d50a6b56ab6c258db"
      ]
    }
  ],
  "commitsTo": {
    "hashes": [
      "d54db6e2435ddbeee76ba718c438558afeb0fe718ca1ab3cd7e4f00be37eff42"
    ],
    "observableEntropy": "8e5d4171458c69d5bc812f6dee6d9335cc73331c45d3b5fb7bb33e0912af5003",
    "timestamps": {
      "submittedAfter": "2022-06-28T14:55:23.763Z",
      "submittedAt": "2022-06-28T14:57:45.850Z",
      "submittedBefore": "2022-06-28T14:59:07Z",
      "submitWindowMilliseconds": 223237
    }
  }
}
```

## API Documentation

The [TypeScript API documentation](https://truestamp.github.io/truestamp-verify/) for this project is generated and published upon each new release.

## Testing

This library aims to achieve 100% code test coverage.

```sh
npm install
npm test
```

## Contributing

We'd love you to join our network of contributors. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for help getting started.

### Releasing

- Commit changes, merge PR's to `main` branch
- Bump `version` field in `package.json`
- Cut a new [release](https://github.com/truestamp/truestamp-verify/releases)
- New release will trigger workflow to build, test, and publish package to [Github Package Registry](https://github.com/truestamp/truestamp-verify/packages) and
  [NPM.js](https://www.npmjs.com/package/@truestamp/verify).

## Code of Conduct

We expect all members of the community to respect our [Code of Conduct](CODE_OF_CONDUCT.md) at all times.

## Legal

Copyright © 2022 Truestamp Inc. All Rights Reserved.
