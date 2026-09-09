const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {encodeBlindedPath} = require('./../../blinding');
const path = require('./../fixtures/blinded_path.json');

const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const [{blinded_public_key}] = path.hops;
const invalidPoint = hexAsBuffer(`02${'00'.repeat(32)}`);

const hops = path.hops.map(hop => ({
  blinded_public_key: hexAsBuffer(hop.blinded_public_key),
  encrypted_data: hexAsBuffer(hop.encrypted_data),
}));

const [hop] = hops;

// Encode a path with fields of the path in the test vector replaced
const args = overrides => ({
  first_node_id: hexAsBuffer(path.first_node_id),
  first_path_key: hexAsBuffer(path.first_path_key),
  hops,
  ...overrides,
});

const tests = [
  {
    args: undefined,
    description: 'Arguments are required',
    error: 'ExpectedArgumentsToEncodeBlindedPath',
  },
  {
    args: {},
    description: 'A first edge or a first node id is required',
    error: 'ExpectedEitherFirstEdgeOrFirstNodeIdToEncodeBlindedPath',
  },
  {
    args: args({first_edge: '965960x2215x0x0'}),
    description: 'A first edge and a first node id are exclusive',
    error: 'ExpectedEitherFirstEdgeOrFirstNodeIdToEncodeBlindedPath',
  },
  {
    args: args({first_edge: '965960x2215x0', first_node_id: undefined}),
    description: 'A first edge must be in edge format',
    error: 'ExpectedEdgeFormatFirstEdgeToEncodeBlindedPath',
  },
  {
    args: args({first_node_id: path.first_node_id}),
    description: 'A first node id must be a buffer',
    error: 'ExpectedFirstNodeIdBufferToEncodeBlindedPath',
  },
  {
    args: args({first_node_id: Buffer.alloc(1, 2)}),
    description: 'A first node id must be a compressed public key',
    error: 'ExpectedCompressedFirstNodeIdToEncodeBlindedPath',
  },
  {
    args: args({first_node_id: invalidPoint}),
    description: 'A first node id must be a valid public key',
    error: 'ExpectedValidFirstNodeIdToEncodeBlindedPath',
  },
  {
    args: args({first_path_key: undefined}),
    description: 'A first path key is required',
    error: 'ExpectedFirstPathKeyBufferToEncodeBlindedPath',
  },
  {
    args: args({first_path_key: path.first_path_key}),
    description: 'A first path key must be a buffer',
    error: 'ExpectedFirstPathKeyBufferToEncodeBlindedPath',
  },
  {
    args: args({first_path_key: Buffer.alloc(1, 2)}),
    description: 'A first path key must be a compressed public key',
    error: 'ExpectedCompressedFirstPathKeyToEncodeBlindedPath',
  },
  {
    args: args({first_path_key: invalidPoint}),
    description: 'A first path key must be a valid public key',
    error: 'ExpectedValidFirstPathKeyToEncodeBlindedPath',
  },
  {
    args: args({hops: undefined}),
    description: 'Hops are required',
    error: 'ExpectedArrayOfHopsToEncodeBlindedPath',
  },
  {
    args: args({hops: []}),
    description: 'At least one hop is required',
    error: 'ExpectedArrayOfHopsToEncodeBlindedPath',
  },
  {
    args: args({hops: Array(256).fill(hop)}),
    description: 'The count of hops must fit in a byte',
    error: 'ExpectedFewerHopsToEncodeBlindedPath',
  },
  {
    args: args({hops: [null]}),
    description: 'A hop is required',
    error: 'ExpectedBlindedKeyBufferForHopToEncodeBlindedPath',
  },
  {
    args: args({hops: [{encrypted_data: hop.encrypted_data}]}),
    description: 'A hop blinded public key is required',
    error: 'ExpectedBlindedKeyBufferForHopToEncodeBlindedPath',
  },
  {
    args: args({hops: [{...hop, blinded_public_key: Buffer.alloc(1, 2)}]}),
    description: 'A hop blinded public key must be a compressed public key',
    error: 'ExpectedCompressedBlindedKeyForHopToEncodeBlindedPath',
  },
  {
    args: args({hops: [{...hop, blinded_public_key: invalidPoint}]}),
    description: 'A hop blinded public key must be a valid public key',
    error: 'ExpectedValidBlindedKeyForHopToEncodeBlindedPath',
  },
  {
    args: args({hops: [{blinded_public_key: hop.blinded_public_key}]}),
    description: 'Hop encrypted data is required',
    error: 'ExpectedEncryptedDataBufferForHopToEncodeBlindedPath',
  },
  {
    args: args({hops: [{...hop, encrypted_data: path.hops[0].encrypted_data}]}),
    description: 'Hop encrypted data must be a buffer',
    error: 'ExpectedEncryptedDataBufferForHopToEncodeBlindedPath',
  },
  {
    args: args({hops: [{...hop, encrypted_data: Buffer.alloc(65536)}]}),
    description: 'Hop encrypted data length must fit in two bytes',
    error: 'ExpectedShorterEncryptedDataForHopToEncodeBlindedPath',
  },
  {
    args: args({}),
    description: 'A blinded path is encoded',
    expected: {encoded: path.encoded},
  },
  {
    args: args({first_edge: '965960x2215x0x0', first_node_id: undefined}),
    description: 'A blinded path is encoded with a first node edge',
    expected: {encoded: `000ebd480008a70000${path.encoded.slice(66)}`},
  },
  {
    args: args({hops: [{...hop, encrypted_data: Buffer.alloc(0)}]}),
    description: 'A blinded path is encoded with empty encrypted data',
    expected: {
      encoded: `${path.encoded.slice(0, 132)}01${blinded_public_key}0000`,
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => encodeBlindedPath(args), new Error(error), 'Got error');

      return end();
    }

    const {encoded} = encodeBlindedPath(args);

    strictSame(bufferAsHex(encoded), expected.encoded, 'Got expected path');

    return end();
  });
});
