const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeTlvStream} = require('bolt01');

const {blindedPathFromHops} = require('./../../');
const {decodeOnionPacket} = require('./../../packets');
const {decryptBlindedPath} = require('./../../');
const {deriveEphemeralKey} = require('./../../packets');
const message = require('./../fixtures/onion_message.json');
const {onionForPath} = require('./../../');
const {sharedSecret} = require('./../../keys');

const [, recipientPath] = message.paths;
const [bob, carol, dave] = recipientPath.hops;
const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const invalidPoint = `02${'00'.repeat(32)}`;
const isPathId = n => /^[0-9a-f]{64}$/.test(n);
const isPublicKey = n => /^0[23][0-9a-f]{64}$/.test(n);
const uniq = arr => Array.from(new Set(arr));

const tests = [
  {
    args: {},
    description: 'Hops are required',
    error: 'ExpectedArrayOfHopsToBlindPath',
  },
  {
    args: {hops: []},
    description: 'At least one hop is required',
    error: 'ExpectedArrayOfHopsToBlindPath',
  },
  {
    args: {hops: ['key']},
    description: 'A hop public key must be hex encoded',
    error: 'ExpectedHexEncodedHopPublicKeyToBlindPath',
  },
  {
    args: {hops: ['02']},
    description: 'A hop public key must be a compressed public key',
    error: 'ExpectedCompressedHopPublicKeyToBlindPath',
  },
  {
    args: {hops: [invalidPoint]},
    description: 'A hop public key must be a valid public key',
    error: 'ExpectedValidHopPublicKeyToBlindPath',
  },
  {
    args: {hops: [dave.public_key], id: 'id'},
    description: 'A path id must be hex encoded',
    error: 'ExpectedHexEncodedPathIdToBlindPath',
  },
  {
    args: {hops: [bob.public_key, carol.public_key, dave.public_key]},
    description: 'A blinded path is created with a random path id',
    expected: {
      hops: [
        {next_node_id: carol.public_key, private_key: bob.private_key},
        {next_node_id: dave.public_key, private_key: carol.private_key},
        {private_key: dave.private_key},
      ],
    },
  },
  {
    args: {hops: [bob.public_key, carol.public_key], id: '00'},
    description: 'A blinded path is created with a short path id',
    expected: {
      hops: [
        {next_node_id: carol.public_key, private_key: bob.private_key},
        {private_key: carol.private_key},
      ],
      id: '00',
    },
  },
  {
    args: {hops: [dave.public_key], id: '01'.repeat(300)},
    description: 'A blinded path is created to a single hop with a long id',
    expected: {hops: [{private_key: dave.private_key}], id: '01'.repeat(300)},
  },
  {
    args: {hops: [dave.public_key, dave.public_key, dave.public_key]},
    description: 'A blinded path is created with dummy hops to the destination',
    expected: {
      hops: [
        {next_node_id: dave.public_key, private_key: dave.private_key},
        {next_node_id: dave.public_key, private_key: dave.private_key},
        {private_key: dave.private_key},
      ],
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => blindedPathFromHops(args), new Error(error), 'Got error');

      return end();
    }

    const {id, key, path} = blindedPathFromHops(args);

    // A path id is randomly generated when it is not specified
    if (!expected.id) {
      strictSame(isPathId(id), true, 'Got random path id');
    } else {
      strictSame(id, expected.id, 'Got expected path id');
    }

    strictSame(isPublicKey(key), true, 'Got path key');
    strictSame(path.length, expected.hops.length, 'Got a hop for every hop');

    // Padding gives every hop encrypted data of the same length
    strictSame(uniq(path.map(n => byteLength(n.encrypted_data))).length, 1);

    // Every hop decrypts its data with the path key it receives
    const final = expected.hops.reduce((pathKey, hop, i) => {
      const {secret} = sharedSecret({
        private_key: hexAsBuffer(hop.private_key),
        public_key: hexAsBuffer(pathKey),
      });

      const decrypted = decryptBlindedPath({
        encrypted: path[i].encrypted_data,
        key: pathKey,
        secret: bufferAsHex(secret),
      });

      const {records} = decodeTlvStream({encoded: decrypted.data});

      const nextNodeId = records.find(n => n.type === '4');
      const pathId = records.find(n => n.type === '6');

      strictSame(
        !nextNodeId ? undefined : nextNodeId.value,
        hop.next_node_id,
        'Got expected next node id'
      );

      // Only the final hop has the path id in its data
      strictSame(
        !pathId ? undefined : pathId.value,
        !hop.next_node_id ? id : undefined,
        'Got expected path id'
      );

      return decrypted.next_path_key;
    }, key);

    strictSame(isPublicKey(final), true, 'Got final hop next path key');

    // An onion encoded to the blinded path is peeled by every hop
    const created = onionForPath({
      key,
      inbound: path,
      outbound: [args.hops[0]],
      records: [{type: '65537', value: '00'}],
    });

    const peeled = expected.hops.reduce((delivery, hop) => {
      const ecdh = public_key => {
        return sharedSecret({
          private_key: hexAsBuffer(hop.private_key),
          public_key,
        });
      };

      const pathSecret = ecdh(hexAsBuffer(delivery.path_key)).secret;

      const {public_key} = deriveEphemeralKey({
        onion: delivery.onion,
        secret: pathSecret,
      });

      const decoded = decodeOnionPacket({
        onion: delivery.onion,
        secret: ecdh(public_key).secret,
      });

      const payload = bufferAsHex(decoded.payload);

      const {records} = decodeTlvStream({encoded: payload});

      const {next_path_key} = decryptBlindedPath({
        encrypted: records.find(n => n.type === '4').value,
        key: delivery.path_key,
        secret: bufferAsHex(pathSecret),
      });

      return {onion: decoded.onion, path_key: next_path_key, records};
    }, {onion: hexAsBuffer(created.onion), path_key: created.key});

    strictSame(peeled.onion, undefined, 'The final hop has no next onion');

    strictSame(
      peeled.records.map(n => n.type),
      ['4', '65537'],
      'The final hop has the message record'
    );

    return end();
  });
});
