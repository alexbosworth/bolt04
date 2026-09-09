const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {multiplyPrivateKey} = require('./../../keys');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

// Path key secrets and blinding factors are from the BOLT 04 message vector
const curveOrder = hexAsBuffer(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
);

const tests = [
  {
    args: {key: Buffer.alloc(32, 1)},
    description: 'A multiplier is required',
    error: 'ExpectedMultiplierToMultiplyPrivateKey',
  },
  {
    args: {multiplier: Buffer.alloc(1, 1), key: Buffer.alloc(32, 1)},
    description: 'A full length multiplier is required',
    error: 'ExpectedMultiplierToMultiplyPrivateKey',
  },
  {
    args: {multiplier: '01'.repeat(32), key: Buffer.alloc(32, 1)},
    description: 'A buffer multiplier is required',
    error: 'ExpectedMultiplierToMultiplyPrivateKey',
  },
  {
    args: {multiplier: Buffer.alloc(32, 1)},
    description: 'A private key is required',
    error: 'ExpectedValidPrivateKeyToMultiply',
  },
  {
    args: {multiplier: Buffer.alloc(32, 1), key: Buffer.alloc(32)},
    description: 'A valid private key is required',
    error: 'ExpectedValidPrivateKeyToMultiply',
  },
  {
    args: {multiplier: curveOrder, key: Buffer.alloc(32, 1)},
    description: 'The product must be a valid private key',
    error: 'UnexpectedInvalidPrivateKeyMultiplicationProduct',
  },
  {
    args: {
      multiplier: hexAsBuffer(
        '1889a6cf337d9b34f80bb23a91a2ca194e80d7614f0728bdbda153da85e46b69'
      ),
      key: Buffer.alloc(32, 1),
    },
    description: 'A private key is multiplied to derive the next path key',
    expected: {
      key: hexAsBuffer(
        'f7ab6dca6152f7b6b0c9d7c82d716af063d72d8eef8816dfc51a8ae828fa7dce'
      ),
    },
  },
  {
    args: {
      multiplier: hexAsBuffer(
        '83377bd6096f82df3a46afec20d68f3f506168f2007f6e86c2dc267417de9e34'
      ),
      key: Buffer.alloc(32, 0x63),
    },
    description: 'A private key product wraps around the curve order',
    expected: {
      key: hexAsBuffer(
        'bf3e8999518c0bb6e876abb0ae01d44b9ba211720048099a2ba5a83afd730cad'
      ),
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => multiplyPrivateKey(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(multiplyPrivateKey(args), expected, 'Got expected product');

    return end();
  });
});
