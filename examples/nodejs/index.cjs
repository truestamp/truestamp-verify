// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

// Usage: run this sample with:
//   npm run build (in the root of the repository)
//   node examples/nodejs/index.cjs

const { assertVerified, isVerified, verify } = require('../../dist/index.cjs')

// Substitute with a Truestamp commitment object to be verified.
const commitmentSample = require('../commitment.json')

// There are three ways to verify a commitment.
async function run() {
  // 1) Assertion
  // Throws an Error on commitment verification issue,
  // or external service verification failure. Resolves
  // to `void` if verified.
  await assertVerified(commitmentSample)

  // 2) Predicate function (boolean)
  // Resolves to boolean `true` or `false` and will not throw Errors
  if (await isVerified(commitmentSample)) {
    console.log('isVerified : verified')
  } else {
    console.log('isVerified : bad commitment')
  }

  // 3) Function that returns details of the verification
  // Resolves to an object that details commitment properties
  // and a summary of what this commitment attests to.
  // It also provides pointers to web URL's (e.g. blockchain explorers)
  // where commitments can be manually verified by comparing a hash.
  // Will throw an Error if there is a failure to verify.
  console.time('verify')
  console.log(await verify(commitmentSample))
  console.timeEnd('verify')
}

run().then(() => {
  // no-op
}
).catch(err => {
  console.error(err)
})
