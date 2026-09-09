const {isPoint} = require('tiny-secp256k1');

const encodeEdge = require('./encode_edge');
const {encodeNumber} = require('./../numbers');
const {lengthEncryptedDataLengthBytes} = require('./constants');
const {lengthHopsCountBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {maxEncryptedDataByteLength} = require('./constants');
const {maxHopsCount} = require('./constants');

const {concat} = Buffer;
const {isArray} = Array;
const {isBuffer} = Buffer;
const isCompressedKey = n => n.length === lengthPointBytes;
const fitsLengthPrefix = n => n.length <= maxEncryptedDataByteLength;
const isEdge = n => typeof n === 'string' && /^\d+x\d+x\d+x[01]$/.test(n);

/** Encode a blinded path

  An encoded blinded path is the reply path of an onion message or a path in a
  BOLT 12 offer. The first hop is referenced either by its public key or by an
  edge from it across one of its channels, and the first path key is the path
  key that the first hop uses.

  {
    [first_edge]: <First Hop Node Edge Format Channel Id String>
    [first_node_id]: <First Hop Node Public Key Buffer Object>
    first_path_key: <First Hop Path Key Public Key Buffer Object>
    hops: [{
      blinded_public_key: <Blinded Node Public Key Buffer Object>
      encrypted_data: <Encrypted Data Buffer Object>
    }]
  }

  @throws
  <Error>

  @returns
  {
    encoded: <Encoded Blinded Path Buffer Object>
  }
*/
module.exports = args => {
  if (!args) {
    throw new Error('ExpectedArgumentsToEncodeBlindedPath');
  }

  // The first node is referenced by either an edge or a node id, not both
  if (!!args.first_edge === !!args.first_node_id) {
    throw new Error('ExpectedEitherFirstEdgeOrFirstNodeIdToEncodeBlindedPath');
  }

  if (!!args.first_edge && !isEdge(args.first_edge)) {
    throw new Error('ExpectedEdgeFormatFirstEdgeToEncodeBlindedPath');
  }

  if (!!args.first_node_id && !isBuffer(args.first_node_id)) {
    throw new Error('ExpectedFirstNodeIdBufferToEncodeBlindedPath');
  }

  if (!!args.first_node_id && !isCompressedKey(args.first_node_id)) {
    throw new Error('ExpectedCompressedFirstNodeIdToEncodeBlindedPath');
  }

  if (!!args.first_node_id && !isPoint(args.first_node_id)) {
    throw new Error('ExpectedValidFirstNodeIdToEncodeBlindedPath');
  }

  if (!isBuffer(args.first_path_key)) {
    throw new Error('ExpectedFirstPathKeyBufferToEncodeBlindedPath');
  }

  if (!isCompressedKey(args.first_path_key)) {
    throw new Error('ExpectedCompressedFirstPathKeyToEncodeBlindedPath');
  }

  if (!isPoint(args.first_path_key)) {
    throw new Error('ExpectedValidFirstPathKeyToEncodeBlindedPath');
  }

  if (!isArray(args.hops) || !args.hops.length) {
    throw new Error('ExpectedArrayOfHopsToEncodeBlindedPath');
  }

  // The count of hops is encoded in a single byte
  if (args.hops.length > maxHopsCount) {
    throw new Error('ExpectedFewerHopsToEncodeBlindedPath');
  }

  if (!args.hops.every(n => !!n && isBuffer(n.blinded_public_key))) {
    throw new Error('ExpectedBlindedKeyBufferForHopToEncodeBlindedPath');
  }

  if (!args.hops.every(n => isCompressedKey(n.blinded_public_key))) {
    throw new Error('ExpectedCompressedBlindedKeyForHopToEncodeBlindedPath');
  }

  if (!args.hops.every(n => isPoint(n.blinded_public_key))) {
    throw new Error('ExpectedValidBlindedKeyForHopToEncodeBlindedPath');
  }

  if (!args.hops.every(n => isBuffer(n.encrypted_data))) {
    throw new Error('ExpectedEncryptedDataBufferForHopToEncodeBlindedPath');
  }

  // The length of the encrypted data is encoded in two bytes
  if (!args.hops.every(n => fitsLengthPrefix(n.encrypted_data))) {
    throw new Error('ExpectedShorterEncryptedDataForHopToEncodeBlindedPath');
  }

  const hopsCount = encodeNumber({
    bytes: lengthHopsCountBytes,
    number: args.hops.length,
  });

  // Every hop has a blinded node id and length prefixed encrypted data
  const hops = args.hops.map(hop => {
    const lengthPrefix = encodeNumber({
      bytes: lengthEncryptedDataLengthBytes,
      number: hop.encrypted_data.length,
    });

    return concat([
      hop.blinded_public_key,
      lengthPrefix.encoded,
      hop.encrypted_data,
    ]);
  });

  // An edge to the first node is encoded as a direction and short channel id
  const edge = !args.first_edge ? null : encodeEdge({edge: args.first_edge});

  // The first node is referenced either by an edge or by its node id
  const firstNode = !edge ? args.first_node_id : edge.encoded;

  const encoded = concat([
    firstNode,
    args.first_path_key,
    hopsCount.encoded,
    concat(hops),
  ]);

  return {encoded};
};
