const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {sharedSecret} = require('./../../keys');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

// Keys and shared secrets are from the BOLT 04 onion message test vector
const bobNodeId = hexAsBuffer(
  '0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c'
);
const bobPathKey = hexAsBuffer(
  '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f'
);
const bobSharedSecret = hexAsBuffer(
  '196f1f3e0be9d65f88463c1ab63e07f41b4e7c0368c28c3e6aa290cc0d22eaed'
);

const tests = [
  {
    args: undefined,
    description: 'Arguments are required',
    error: 'ExpectedArgumentsToDeriveSharedSecret',
  },
  {
    args: {public_key: bobNodeId},
    description: 'A private key is required',
    error: 'ExpectedValidPrivateKeyToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(1, 1), public_key: bobNodeId},
    description: 'A full length private key is required',
    error: 'ExpectedValidPrivateKeyToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(32), public_key: bobNodeId},
    description: 'A valid private key is required',
    error: 'ExpectedValidPrivateKeyToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(32, 1)},
    description: 'A public key is required',
    error: 'ExpectedPublicKeyBufferToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(32, 1), public_key: '02'.repeat(33)},
    description: 'A buffer public key is required',
    error: 'ExpectedPublicKeyBufferToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(32, 1), public_key: Buffer.alloc(1, 2)},
    description: 'A compressed public key is required',
    error: 'ExpectedCompressedPublicKeyToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(32, 1), public_key: Buffer.alloc(33)},
    description: 'A valid public key is required',
    error: 'ExpectedValidPublicKeyToDeriveSharedSecret',
  },
  {
    args: {private_key: Buffer.alloc(32, 1), public_key: bobNodeId},
    description: 'The path creator derives a shared secret with a node key',
    expected: {secret: bobSharedSecret},
  },
  {
    args: {private_key: Buffer.alloc(32, 0x42), public_key: bobPathKey},
    description: 'The node derives the same shared secret with the path key',
    expected: {secret: bobSharedSecret},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => sharedSecret(args), new Error(error), 'Got expected error');

      return end();
    }

    strictSame(sharedSecret(args), expected, 'Got expected shared secret');

    return end();
  });
});
