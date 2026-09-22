const {isPoint} = require('tiny-secp256k1');

const blindHopRecords = require('./blind_hop_records');
const {lengthPointBytes} = require('./constants');
const {typeNextNodeId} = require('./constants');

const byteLength = hex => hex.length / 2;
const {from} = Buffer;
const {isArray} = Array;
const isHex = n => !(n.length % 2) && /^[0-9A-F]*$/i.test(n);
const isHexString = n => typeof n === 'string' && isHex(n);
const isPublicKey = n => isPoint(from(n, 'hex'));

/** Create a blinded path from a series of hops culminating in a destination

  {
    hops: [<Relaying Node Public Key Hex String>]
  }

  @throws
  <Error>

  @returns
  {
    key: <Path Key Hex String>
    path: [{
      encrypted_data: <Encrypted Data Hex String>
      relay_key: <Blinded Node Public Key Hex String>
    }]
  }
*/
module.exports = ({hops}) => {
  if (!isArray(hops) || !hops.length) {
    throw new Error('ExpectedArrayOfHopsToBlindPathToNode');
  }

  if (!hops.every(isHexString)) {
    throw new Error('ExpectedHexEncodedHopPublicKeyToBlindPathToNode');
  }

  if (!hops.every(n => byteLength(n) === lengthPointBytes)) {
    throw new Error('ExpectedCompressedHopPublicKeyToBlindPathToNode');
  }

  if (!hops.every(isPublicKey)) {
    throw new Error('ExpectedValidHopPublicKeyToBlindPathToNode');
  }

  // Forwarding hops are told the next node, the final hop is given no records
  const records = hops.map((publicKey, i) => {
    const next = hops[i + 1];

    if (!next) {
      return [];
    }

    return [{type: typeNextNodeId, value: next}];
  });

  const blinded = blindHopRecords({
    hops: hops.map((publicKey, i) => ({
      public_key: publicKey,
      records: records[i],
    })),
  });

  return {key: blinded.key, path: blinded.path};
};
