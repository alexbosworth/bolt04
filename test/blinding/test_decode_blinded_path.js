const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {createBlindedPath} = require('./../../blinding');
const {decodeBlindedPath} = require('./../../blinding');
const {encodeBlindedPath} = require('./../../blinding');
const message = require('./../fixtures/onion_message.json');
const path = require('./../fixtures/blinded_path.json');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const [hop] = path.hops;
const invalidPoint = `02${'00'.repeat(32)}`;
const [, recipient] = message.paths;

// The encoded path starts with the first node id, first path key, hops count
const firstNodeId = path.encoded.slice(0, 66);
const firstPathKey = path.encoded.slice(66, 132);
const pathHops = path.encoded.slice(132);

const singleHop = `${firstNodeId}${firstPathKey}01`;

// An edge to the first node is a direction byte and a short channel id
const edge = '000ebd480008a70000';
const reversedEdge = '010ebd480008a70000';

// A hop with a data length that is longer than the data that follows it
const truncatedHop = `${hop.blinded_public_key}0010${'00'.repeat(8)}`;

// A decoded path is compared to the test vector as hex
const asHex = decoded => ({
  ...(!decoded.first_edge ? {} : {first_edge: decoded.first_edge}),
  ...(!decoded.first_node_id ? {} : {
    first_node_id: bufferAsHex(decoded.first_node_id),
  }),
  first_path_key: bufferAsHex(decoded.first_path_key),
  hops: decoded.hops.map(n => ({
    blinded_public_key: bufferAsHex(n.blinded_public_key),
    encrypted_data: bufferAsHex(n.encrypted_data),
  })),
});

// The recipient in the onion message test vector creates a blinded path
const created = createBlindedPath({
  hops: recipient.hops.map(n => ({
    data: hexAsBuffer(n.data),
    public_key: hexAsBuffer(n.public_key),
  })),
  secret: hexAsBuffer(recipient.secret),
});

const roundTrip = {
  first_node_id: hexAsBuffer(recipient.hops[0].public_key),
  first_path_key: created.key,
  hops: created.hops,
};

const tests = [
  {
    args: {},
    description: 'An encoded blinded path is required',
    error: 'ExpectedBlindedPathBufferToDecode',
  },
  {
    args: {encoded: path.encoded},
    description: 'An encoded blinded path must be a buffer',
    error: 'ExpectedBlindedPathBufferToDecode',
  },
  {
    args: {encoded: hexAsBuffer(`00${'00'.repeat(8)}`)},
    description: 'An edge first node must have a path key and hops count',
    error: 'ExpectedLongerEncodedBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(firstNodeId)},
    description: 'An encoded blinded path must have a path key and hops count',
    error: 'ExpectedLongerEncodedBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(`${invalidPoint}${path.encoded.slice(66)}`)},
    description: 'A first node id must be a valid public key',
    error: 'ExpectedValidFirstNodeIdInBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(`${firstNodeId}${invalidPoint}${pathHops}`)},
    description: 'A first path key must be a valid public key',
    error: 'ExpectedValidFirstPathKeyInBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(`${firstNodeId}${firstPathKey}00`)},
    description: 'At least one hop is required',
    error: 'ExpectedHopsInBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(singleHop)},
    description: 'A hop must have a blinded public key and a data length',
    error: 'ExpectedBlindedKeyAndDataLengthForHopInBlindedPath',
  },
  {
    args: {encoded: hexAsBuffer(`${singleHop}${invalidPoint}0000`)},
    description: 'A hop blinded public key must be a valid public key',
    error: 'ExpectedValidBlindedKeyForHopInBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(`${singleHop}${truncatedHop}`)},
    description: 'A hop must have all of its encrypted data',
    error: 'ExpectedEncryptedDataForHopInBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(`${path.encoded}00`)},
    description: 'An encoded blinded path must end with its final hop',
    error: 'UnexpectedTrailingBytesInBlindedPathToDecode',
  },
  {
    args: {encoded: hexAsBuffer(path.encoded)},
    description: 'A blinded path is decoded',
    expected: {
      first_node_id: path.first_node_id,
      first_path_key: path.first_path_key,
      hops: path.hops,
    },
  },
  {
    args: {encoded: hexAsBuffer(`${singleHop}${hop.blinded_public_key}0000`)},
    description: 'A blinded path is decoded with empty encrypted data',
    expected: {
      first_node_id: path.first_node_id,
      first_path_key: path.first_path_key,
      hops: [{blinded_public_key: hop.blinded_public_key, encrypted_data: ''}],
    },
  },
  {
    args: {encoded: encodeBlindedPath(roundTrip).encoded},
    description: 'A created blinded path is decoded after it is encoded',
    expected: asHex(roundTrip),
  },
  {
    args: {encoded: hexAsBuffer(`${edge}${firstPathKey}${pathHops}`)},
    description: 'A blinded path is decoded with a first node edge',
    expected: {
      first_edge: '965960x2215x0x0',
      first_path_key: path.first_path_key,
      hops: path.hops,
    },
  },
  {
    args: {encoded: hexAsBuffer(`${reversedEdge}${firstPathKey}${pathHops}`)},
    description: 'A blinded path is decoded with a reversed first node edge',
    expected: {
      first_edge: '965960x2215x0x1',
      first_path_key: path.first_path_key,
      hops: path.hops,
    },
  },
  {
    args: {
      encoded: encodeBlindedPath({
        first_edge: '1x2x3x1',
        first_path_key: roundTrip.first_path_key,
        hops: roundTrip.hops,
      }).encoded,
    },
    description: 'A first edge blinded path is decoded after it is encoded',
    expected: {
      first_edge: '1x2x3x1',
      first_path_key: bufferAsHex(roundTrip.first_path_key),
      hops: asHex(roundTrip).hops,
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decodeBlindedPath(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(asHex(decodeBlindedPath(args)), expected, 'Got expected path');

    return end();
  });
});
