const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {isPoint} = require('tiny-secp256k1');

const blinding = require('./../fixtures/route_blinding.json');
const {createBlindedPath} = require('./../../blinding');
const {decryptBlindedPath} = require('./../../');
const message = require('./../fixtures/onion_message.json');
const {sharedSecret} = require('./../../keys');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const invalidPoint = hexAsBuffer(`02${'00'.repeat(32)}`);
const paths = [].concat(message.paths).concat(blinding.paths);
const [{hops}] = blinding.paths;

const asHop = ({data, public_key}) => {
  return {data: hexAsBuffer(data), public_key: hexAsBuffer(public_key)};
};

const isPublicKey = n => Buffer.isBuffer(n) && n.length === 33 && isPoint(n);

const [{public_key}] = hops;

const tests = [
  {
    args: {},
    description: 'Hops are required',
    error: 'ExpectedArrayOfHopsToCreateBlindedPath',
  },
  {
    args: {hops: []},
    description: 'At least one hop is required',
    error: 'ExpectedArrayOfHopsToCreateBlindedPath',
  },
  {
    args: {hops: [{public_key: hexAsBuffer(public_key)}]},
    description: 'Hop data is required',
    error: 'ExpectedDataBufferForHopToCreateBlindedPath',
  },
  {
    args: {hops: [{data: '00', public_key: hexAsBuffer(public_key)}]},
    description: 'Hop data must be a buffer',
    error: 'ExpectedDataBufferForHopToCreateBlindedPath',
  },
  {
    args: {hops: [{data: Buffer.alloc(1)}]},
    description: 'A hop public key is required',
    error: 'ExpectedPublicKeyBufferForHopToCreateBlindedPath',
  },
  {
    args: {hops: [{data: Buffer.alloc(1), public_key}]},
    description: 'A hop public key must be a buffer',
    error: 'ExpectedPublicKeyBufferForHopToCreateBlindedPath',
  },
  {
    args: {hops: [{data: Buffer.alloc(1), public_key: Buffer.alloc(1, 2)}]},
    description: 'A hop public key must be a compressed public key',
    error: 'ExpectedCompressedPublicKeyForHopToCreateBlindedPath',
  },
  {
    args: {hops: [{data: Buffer.alloc(1), public_key: invalidPoint}]},
    description: 'A hop public key must be a valid public key',
    error: 'ExpectedValidPublicKeyForHopToCreateBlindedPath',
  },
  {
    args: {hops: hops.map(asHop), secret: '01'.repeat(32)},
    description: 'A secret must be a buffer',
    error: 'ExpectedSecretBufferToCreateBlindedPath',
  },
  {
    args: {hops: hops.map(asHop), secret: Buffer.alloc(1, 1)},
    description: 'A secret must be a full length private key',
    error: 'ExpectedPathKeySecretByteLengthToCreateBlindedPath',
  },
  {
    args: {hops: hops.map(asHop), secret: Buffer.alloc(32)},
    description: 'A secret must be a valid private key',
    error: 'ExpectedValidPathKeySecretToCreateBlindedPath',
  },
  ...paths.map(path => ({
    args: {hops: path.hops.map(asHop), secret: hexAsBuffer(path.secret)},
    description: `A blinded path is created to ${path.hops.at(-1).alias}`,
    expected: {
      hops: path.hops.map(hop => ({
        blinded_public_key: hexAsBuffer(hop.blinded_public_key),
        encrypted_data: hexAsBuffer(hop.encrypted_data),
      })),
      key: hexAsBuffer(path.path_key),
    },
  })),
  {
    args: {hops: hops.map(asHop)},
    description: 'A blinded path is created with a random secret',
    expected: {hops: hops.map(hop => ({data: hop.data}))},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => createBlindedPath(args), new Error(error), 'Got error');

      return end();
    }

    const path = createBlindedPath(args);

    // Exit early when the path is deterministic
    if (!!expected.key) {
      strictSame(path, expected, 'Got expected blinded path');

      return end();
    }

    strictSame(isPublicKey(path.key), true, 'Got random path key');

    // Every hop uses the path key it receives to decrypt its blinded data
    const final = path.hops.reduce((pathKey, hop, i) => {
      strictSame(isPublicKey(hop.blinded_public_key), true, 'Blinded key');

      const {secret} = sharedSecret({
        private_key: hexAsBuffer(hops[i].private_key),
        public_key: pathKey,
      });

      const decrypted = decryptBlindedPath({
        encrypted: bufferAsHex(hop.encrypted_data),
        key: bufferAsHex(pathKey),
        secret: bufferAsHex(secret),
      });

      strictSame(decrypted.data, expected.hops[i].data, 'Got hop data');

      return hexAsBuffer(decrypted.next_path_key);
    }, path.key);

    strictSame(isPublicKey(final), true, 'Got final next path key');

    return end();
  });
});
