const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const blinding = require('./../fixtures/route_blinding.json');
const {decryptHopData} = require('./../../blinding');
const message = require('./../fixtures/onion_message.json');
const {sharedSecret} = require('./../../keys');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const paths = [].concat(message.paths).concat(blinding.paths);

const hops = paths.flatMap(n => n.hops);

// A hop derives the shared secret with the path key using its private key
const pathSecret = ({path_key, private_key}) => {
  return sharedSecret({
    private_key: hexAsBuffer(private_key),
    public_key: hexAsBuffer(path_key),
  }).secret;
};

const tests = [
  {
    args: {},
    description: 'Encrypted data is required',
    error: 'ExpectedEncryptedDataBufferToDecryptHopData',
  },
  {
    args: {encrypted: '00'.repeat(16)},
    description: 'Encrypted data must be a buffer',
    error: 'ExpectedEncryptedDataBufferToDecryptHopData',
  },
  {
    args: {encrypted: Buffer.alloc(1)},
    description: 'Encrypted data must include an authentication tag',
    error: 'ExpectedAuthenticatedEncryptedDataToDecryptHopData',
  },
  {
    args: {encrypted: Buffer.alloc(16)},
    description: 'A shared secret is required',
    error: 'ExpectedSharedSecretBufferToDecryptHopData',
  },
  {
    args: {encrypted: Buffer.alloc(16), secret: '01'.repeat(32)},
    description: 'A shared secret must be a buffer',
    error: 'ExpectedSharedSecretBufferToDecryptHopData',
  },
  {
    args: {encrypted: Buffer.alloc(16), secret: Buffer.alloc(1)},
    description: 'A shared secret must be a hash byte length',
    error: 'ExpectedSharedSecretByteLengthToDecryptHopData',
  },
  {
    args: {encrypted: Buffer.alloc(16), secret: Buffer.alloc(32, 1)},
    description: 'Encrypted data must be encrypted to the shared secret',
    error: 'FailedToAuthenticateEncryptedDataToDecryptHopData',
  },
  ...hops.map(hop => ({
    args: {
      encrypted: hexAsBuffer(hop.encrypted_data),
      secret: pathSecret(hop),
    },
    description: `Hop data is decrypted by ${hop.alias}`,
    expected: {data: hexAsBuffer(hop.data)},
  })),
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decryptHopData(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(decryptHopData(args), expected, 'Got expected decrypted data');

    return end();
  });
});
