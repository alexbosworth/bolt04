const {randomBytes} = require('node:crypto');

const {isPoint} = require('tiny-secp256k1');

const createBlindedPath = require('./create_blinded_path');
const {lengthPathIdBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const padHopData = require('./pad_hop_data');
const {typeNextNodeId} = require('./constants');
const {typePathId} = require('./constants');

const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const {from} = Buffer;
const hexAsBuffer = hex => from(hex, 'hex');
const {isArray} = Array;
const isHex = n => !(n.length % 2) && /^[0-9A-F]*$/i.test(n);
const isHexString = n => typeof n === 'string' && isHex(n);
const isPublicKey = n => isPoint(from(n, 'hex'));

/** Create a blinded path from a series of hops to a destination

  The final hop is the destination, which is given a path `id` for reference.

  {
    hops: [<Relaying Node Public Key Id Hex String>]
    [id]: <Path Identifier Hex String>
  }

  @throws
  <Error>

  @returns
  {
    id: <Path Identifier Hex String>
    key: <Path Key Hex String>
    path: [{
      encrypted_data: <Encrypted Data Hex String>
      relay_key: <Blinded Node Public Key Hex String>
    }]
  }
*/
module.exports = ({hops, id}) => {
  if (!isArray(hops) || !hops.length) {
    throw new Error('ExpectedArrayOfHopsToBlindPath');
  }

  if (!hops.every(isHexString)) {
    throw new Error('ExpectedHexEncodedHopPublicKeyToBlindPath');
  }

  if (!hops.every(n => byteLength(n) === lengthPointBytes)) {
    throw new Error('ExpectedCompressedHopPublicKeyToBlindPath');
  }

  if (!hops.every(isPublicKey)) {
    throw new Error('ExpectedValidHopPublicKeyToBlindPath');
  }

  if (!!id && !isHexString(id)) {
    throw new Error('ExpectedHexEncodedPathIdToBlindPath');
  }

  const pathId = id || bufferAsHex(randomBytes(lengthPathIdBytes));

  // Forwarding hops are told the next node, the final hop is given the path id
  const records = hops.map((publicKey, i) => {
    const next = hops[i + 1];

    if (!next) {
      return [{type: typePathId, value: pathId}];
    }

    return [{type: typeNextNodeId, value: next}];
  });

  // Every hop gets data of the same length so that the hops look alike
  const {data} = padHopData({records});

  const path = createBlindedPath({
    hops: hops.map((publicKey, i) => ({
      data: data[i],
      public_key: hexAsBuffer(publicKey),
    })),
  });

  return {
    id: pathId,
    key: bufferAsHex(path.key),
    path: path.hops.map(hop => ({
      encrypted_data: bufferAsHex(hop.encrypted_data),
      relay_key: bufferAsHex(hop.blinded_public_key),
    })),
  };
};
