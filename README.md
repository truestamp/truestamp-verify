# @truestamp/verify

This library provides a TypeScript/JavaScript API for verifying
[Truestamp](https://www.truestamp.com) Commitments.

As a first principle this library is intended to provide verification of
Truestamp Commitments independently of, and without reliance on, any Truestamp
service or API. This provides users with the confidence that their Commitments
are verifiable for the long term. The code for this verification is purposely
designed to be as simple and easy to audit as possible so as to provide
confidence in its functionality and security.

## Install

```sh
npm install @truestamp/verify
```

## Sample Usage

Node.js:

```javascript
const { assertVerified, isVerified, verify } = require('@truestamp/verify')
// import { assertVerified, isVerified, verify } from '@truestamp/verify';

// Substitute with a Truestamp commitment object to be verified.
const commitment = {...}

// Throws an Error on commitment validation issue,
// or external service verification failure. Resolves
// to `void` if verified.
await assertVerified(commitment)

// Resolves to boolean `true` or `false` and will not throw Errors
if (await isVerified(commitment)) {
  console.log('verified')
} else {
  console.log('bad commitment')
}

// Resolves to an object that details commitment properties
// and a summary of what this commitment attests to.
// It also provides pointers to web URL's (e.g. blockchain explorers)
// where commitments can be manually verified by comparing a hash.
// Will throw an Error if there is a failure to verify.
console.log('verify', await verify(commitment))
```

A more detailed version of this example can be found in [examples/example.cjs].

## API Documentation

The
[TypeScript API documentation](https://truestamp.github.io/truestamp-verify/)
for this project is generated and published upon each new release.

## Testing

This library aims to maintain 100% code test coverage.

```sh
npm i
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
