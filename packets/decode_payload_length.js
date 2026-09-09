const {decodeBigSize} = require('bolt01');

const bufferAsHex = buffer => buffer.toString('hex');
const {isBuffer} = Buffer;
const maxBigSizeByteLength = 9;

/** Decode the BigSize byte length prefix of a hop payload

  {
    encoded: <Length Prefixed Hop Payload Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    bytes: <Length Prefix Byte Length Number>
    number: <Payload Byte Length Number>
  }
*/
module.exports = ({encoded}) => {
  if (!isBuffer(encoded)) {
    throw new Error('ExpectedPayloadBufferToDecodePayloadLength');
  }

  // The prefix is at most the largest BigSize encoding
  const prefix = bufferAsHex(encoded.subarray(Number(), maxBigSizeByteLength));

  try {
    const bigSize = decodeBigSize({encoded: prefix});

    return {bytes: bigSize.length, number: Number(bigSize.decoded)};
  } catch (err) {
    throw new Error('ExpectedValidBigSizePrefixToDecodePayloadLength');
  }
};
