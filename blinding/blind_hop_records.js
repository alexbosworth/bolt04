const {isPoint} = require('tiny-secp256k1');

const createBlindedPath = require('./create_blinded_path');
const {lengthPointBytes} = require('./constants');
const padHopData = require('./pad_hop_data');

const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const {from} = Buffer;
const hexAsBuffer = hex => from(hex, 'hex');
const {isArray} = Array;
const isHex = n => !(n.length % 2) && /^[0-9A-F]*$/i.test(n);
const isHexString = n => typeof n === 'string' && isHex(n);
const isPublicKey = n => isPoint(from(n, 'hex'));

/** Blind a series of hops with the data records to encrypt for each hop

  The records of every hop are padded to the same length before encryption.

  {
    hops: [{
      public_key: <Node Identity Public Key Hex String>
      records: [{
        type: <Record Type Number String>
        value: <Record Value Hex String>
      }]
    }]
  }

  @throws
  <Error>

  @returns
  {
    key: <First Hop Path Key Public Key Hex String>
    path: [{
      encrypted_data: <Encrypted Data Hex String>
      relay_key: <Blinded Node Public Key Hex String>
    }]
  }
*/
module.exports = ({hops}) => {
  if (!isArray(hops) || !hops.length) {
    throw new Error('ExpectedArrayOfHopsToBlindHopRecords');
  }

  if (!hops.every(n => !!n && isHexString(n.public_key))) {
    throw new Error('ExpectedHexEncodedHopPublicKeyToBlindHopRecords');
  }

  if (!hops.every(n => byteLength(n.public_key) === lengthPointBytes)) {
    throw new Error('ExpectedCompressedHopPublicKeyToBlindHopRecords');
  }

  if (!hops.every(n => isPublicKey(n.public_key))) {
    throw new Error('ExpectedValidHopPublicKeyToBlindHopRecords');
  }

  if (!hops.every(n => isArray(n.records))) {
    throw new Error('ExpectedArrayOfRecordsForHopToBlindHopRecords');
  }

  // Every hop gets data of the same length so that the hops look alike
  const {data} = padHopData({records: hops.map(n => n.records)});

  const path = createBlindedPath({
    hops: hops.map((hop, i) => ({
      data: data[i],
      public_key: hexAsBuffer(hop.public_key),
    })),
  });

  return {
    key: bufferAsHex(path.key),
    path: path.hops.map(hop => ({
      encrypted_data: bufferAsHex(hop.encrypted_data),
      relay_key: bufferAsHex(hop.blinded_public_key),
    })),
  };
};
