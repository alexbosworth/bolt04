const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {pointFromScalar} = require('tiny-secp256k1');

const {blindHop} = require('./../../blinding');
const blinding = require('./../fixtures/route_blinding.json');
const message = require('./../fixtures/onion_message.json');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const invalidPoint = hexAsBuffer(`02${'00'.repeat(32)}`);
const paths = [].concat(message.paths).concat(blinding.paths);
const publicKey = n => bufferAsHex(Buffer.from(pointFromScalar(n, true)));

const [{hops: [bob]}] = blinding.paths;

const bobId = hexAsBuffer(bob.public_key);
const bobSecret = hexAsBuffer(bob.private_key);

// Every hop of every path in the test vectors is blinded with a known secret
const hops = paths.flatMap(path => {
  return path.hops.reduce((blinded, hop, i) => {
    // The secret for a hop after the first comes from blinding the hop before
    const secret = !i ? hexAsBuffer(path.secret) : blindHop({
      data: hexAsBuffer(path.hops[i - 1].data),
      id: hexAsBuffer(path.hops[i - 1].public_key),
      secret: blinded[i - 1].secret,
    }).next_secret;

    return [].concat(blinded).concat([{hop, secret, next: path.hops[i + 1]}]);
  }, []);
});

const tests = [
  {
    args: {id: bobId, secret: bobSecret},
    description: 'Data is required',
    error: 'ExpectedDataBufferToBlindHop',
  },
  {
    args: {data: '', id: bobId, secret: bobSecret},
    description: 'Data must be a buffer',
    error: 'ExpectedDataBufferToBlindHop',
  },
  {
    args: {data: Buffer.alloc(0), id: bob.public_key, secret: bobSecret},
    description: 'A node id must be a buffer',
    error: 'ExpectedCompressedNodeIdToBlindHop',
  },
  {
    args: {data: Buffer.alloc(0), id: Buffer.alloc(1, 2), secret: bobSecret},
    description: 'A node id must be a compressed public key',
    error: 'ExpectedCompressedNodeIdToBlindHop',
  },
  {
    args: {data: Buffer.alloc(0), id: invalidPoint, secret: bobSecret},
    description: 'A node id must be a valid public key',
    error: 'ExpectedValidNodeIdToBlindHop',
  },
  {
    args: {data: Buffer.alloc(0), id: bobId, secret: bob.private_key},
    description: 'A path key secret must be a buffer',
    error: 'ExpectedPathKeySecretToBlindHop',
  },
  {
    args: {data: Buffer.alloc(0), id: bobId, secret: Buffer.alloc(1, 1)},
    description: 'A path key secret must be a full length private key',
    error: 'ExpectedPathKeySecretToBlindHop',
  },
  {
    args: {data: Buffer.alloc(0), id: bobId, secret: Buffer.alloc(32)},
    description: 'A path key secret must be a valid private key',
    error: 'ExpectedValidPathKeySecretToBlindHop',
  },
  ...hops.map(({hop, next, secret}) => ({
    args: {
      data: hexAsBuffer(hop.data),
      id: hexAsBuffer(hop.public_key),
      secret,
    },
    description: `A hop is blinded for ${hop.alias}`,
    expected: {
      blinded_public_key: hexAsBuffer(hop.blinded_public_key),
      encrypted_data: hexAsBuffer(hop.encrypted_data),
      next_path_key: !next ? undefined : next.path_key,
    },
  })),
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => blindHop(args), new Error(error), 'Got error');

      return end();
    }

    const blinded = blindHop(args);

    strictSame(blinded.blinded_public_key, expected.blinded_public_key, 'Key');
    strictSame(blinded.encrypted_data, expected.encrypted_data, 'Got data');

    // The next hop path key is the public key of the next hop path key secret
    if (!!expected.next_path_key) {
      strictSame(publicKey(blinded.next_secret), expected.next_path_key, 'Key');
    }

    return end();
  });
});
