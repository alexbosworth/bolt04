const {decodeTlvStream} = require('bolt01');

const bufferAsHex = buffer => buffer.toString('hex');
const {isBuffer} = Buffer;
const isOrdered = (n, i, all) => !i || BigInt(n.type) > BigInt(all[i-1].type);

/** Decode the decrypted data of a blinded path hop into its records

  {
    data: <Decrypted Data TLV Stream Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    records: [{
      type: <Record Type Number String>
      value: <Record Value Hex String>
    }]
  }
*/
module.exports = ({data}) => {
  if (!isBuffer(data)) {
    throw new Error('ExpectedDataBufferToDecodeHopData');
  }

  const stream = {};

  // The decrypted data of a hop is a TLV stream
  try {
    stream.records = decodeTlvStream({encoded: bufferAsHex(data)}).records;
  } catch (err) {
    throw new Error('ExpectedValidTlvStreamToDecodeHopData');
  }

  // Record types in a TLV stream must be strictly increasing
  if (!stream.records.every(isOrdered)) {
    throw new Error('ExpectedOrderedTlvStreamToDecodeHopData');
  }

  return {records: stream.records.map(({type, value}) => ({type, value}))};
};
