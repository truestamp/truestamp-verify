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
made to a few external services for the purpose of comparing locally calculated
results to values expected to be stored on chain.

Currently, the server `keys.truestamp.com` will be called to help verify that the
public key in the signature is authoritative.

Additional requests may be made to third-party blockchain APIs in order to verify
transactions for that chain or service.

The library will return a comprehensive audit object to indicate overall pass/fail
verification, as well as more granular information to indicate what exactly failed.

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
