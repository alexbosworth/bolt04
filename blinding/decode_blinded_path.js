const {isPoint} = require('tiny-secp256k1');

const decodeEdge = require('./decode_edge');
const {edgeDirections} = require('./constants');
const {lengthDirectionBytes} = require('./constants');
const {lengthEncryptedDataLengthBytes} = require('./constants');
const {lengthHopsCountBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {lengthShortChannelIdBytes} = require('./constants');

const {isBuffer} = Buffer;
const minHopsCount = 1;

/** Decode an encoded blinded path

  The first node in the path is referenced by `first_edge` or `first_node_id`

  `first_edge` is a short channel id plus a directional flag based on
  lexicographical key ordering and `first_node_id` is an identity public key.

  {
    encoded: <Encoded Blinded Path Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    [first_edge]: <First Hop Node Edge Format Channel Id String>
    [first_node_id]: <First Hop Node Public Key Buffer Object>
    first_path_key: <First Hop Path Key Public Key Buffer Object>
    hops: [{
      blinded_public_key: <Blinded Node Public Key Buffer Object>
      encrypted_data: <Encrypted Data Buffer Object>
    }]
  }
*/
module.exports = ({encoded}) => {
  if (!isBuffer(encoded)) {
    throw new Error('ExpectedBlindedPathBufferToDecode');
  }

  // A first node that starts with a direction byte is referenced by an edge
  const isEdge = edgeDirections.includes(encoded[Number()]);

  const lengthEdgeBytes = lengthDirectionBytes + lengthShortChannelIdBytes;

  const firstNodeEnd = isEdge ? lengthEdgeBytes : lengthPointBytes;

  const firstPathKeyEnd = firstNodeEnd + lengthPointBytes;

  const headersLength = firstPathKeyEnd + lengthHopsCountBytes;

  if (encoded.length < headersLength) {
    throw new Error('ExpectedLongerEncodedBlindedPathToDecode');
  }

  const firstNode = encoded.subarray(Number(), firstNodeEnd);

  if (!isEdge && !isPoint(firstNode)) {
    throw new Error('ExpectedValidFirstNodeIdInBlindedPathToDecode');
  }

  const firstPathKey = encoded.subarray(firstNodeEnd, firstPathKeyEnd);

  if (!isPoint(firstPathKey)) {
    throw new Error('ExpectedValidFirstPathKeyInBlindedPathToDecode');
  }

  const hopsCount = encoded[firstPathKeyEnd];

  if (hopsCount < minHopsCount) {
    throw new Error('ExpectedHopsInBlindedPathToDecode');
  }

  const cursor = {offset: headersLength};

  // Hops have a blinded node id and a length prefixed encrypted data
  const hops = [...Array(hopsCount)].map(() => {
    const keyEnd = cursor.offset + lengthPointBytes;
    const lengthEnd = keyEnd + lengthEncryptedDataLengthBytes;

    if (encoded.length < lengthEnd) {
      throw new Error('ExpectedBlindedKeyAndDataLengthForHopInBlindedPath');
    }

    const blindedPublicKey = encoded.subarray(cursor.offset, keyEnd);

    if (!isPoint(blindedPublicKey)) {
      throw new Error('ExpectedValidBlindedKeyForHopInBlindedPathToDecode');
    }

    const dataEnd = lengthEnd + encoded.readUInt16BE(keyEnd);

    if (encoded.length < dataEnd) {
      throw new Error('ExpectedEncryptedDataForHopInBlindedPathToDecode');
    }

    cursor.offset = dataEnd;

    return {
      blinded_public_key: blindedPublicKey,
      encrypted_data: encoded.subarray(lengthEnd, dataEnd),
    };
  });

  // There should not be data beyond the hops in the encoded path
  if (cursor.offset !== encoded.length) {
    throw new Error('UnexpectedTrailingBytesInBlindedPathToDecode');
  }

  return {
    first_edge: !isEdge ? undefined : decodeEdge({encoded: firstNode}).edge,
    first_node_id: isEdge ? undefined : firstNode,
    first_path_key: firstPathKey,
    hops,
  };
};
