const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {deriveKey} = require('./../../keys');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

// Shared secrets and derived keys are from the BOLT 04 route blinding vectors
const bobSharedSecret = hexAsBuffer(
  '76771bab0cc3d0de6e6f60147fd7c9c7249a5ced3d0612bdfaeec3b15452229d'
);
const aliceSharedSecret = hexAsBuffer(
  'c04d2a4c518241cb49f2800eea92554cb543f268b4c73f85693541e86d649205'
);

const tests = [
  {
    args: {type: 'rho'},
    description: 'A secret is required',
    error: 'ExpectedSecretBufferToDeriveKey',
  },
  {
    args: {secret: bobSharedSecret.toString('hex'), type: 'rho'},
    description: 'A buffer secret is required',
    error: 'ExpectedSecretBufferToDeriveKey',
  },
  {
    args: {secret: Buffer.alloc(1), type: 'rho'},
    description: 'A full length secret is required',
    error: 'ExpectedSecretBufferToDeriveKey',
  },
  {
    args: {secret: bobSharedSecret},
    description: 'A key type is required',
    error: 'ExpectedKeyTypeToDeriveKey',
  },
  {
    args: {secret: bobSharedSecret, type: 1},
    description: 'A string key type is required',
    error: 'ExpectedKeyTypeToDeriveKey',
  },
  {
    args: {secret: bobSharedSecret, type: 'rho'},
    description: 'A rho key is derived from a shared secret',
    expected: {
      key: hexAsBuffer(
        'ba217b23c0978d84c4a19be8a9ff64bc1b40ed0d7ecf59521567a5b3a9a1dd48'
      ),
    },
  },
  {
    args: {secret: aliceSharedSecret, type: 'blinded_node_id'},
    description: 'A blinded node id key is derived from a shared secret',
    expected: {
      key: hexAsBuffer(
        'bc5388417c8db33af18ab7ba43f6a5641861f7b0ecb380e501a739af446a7bf4'
      ),
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => deriveKey(args), new Error(error), 'Got expected error');

      return end();
    }

    strictSame(deriveKey(args), expected, 'Got expected derived key');

    return end();
  });
});
