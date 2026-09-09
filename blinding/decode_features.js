const {bitsPerByte} = require('./constants');

const bitPositions = [...Array(bitsPerByte).keys()];
const {isBuffer} = Buffer;
const isSet = (byte, bit) => !!((byte >> bit) & 1);

/** Decode a features bit vector into the feature bits that are set

  Feature bits are numbered from the least significant bit of the final byte

  {
    encoded: <Features Bit Vector Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    bits: [<Feature Bit Number>]
  }
*/
module.exports = ({encoded}) => {
  if (!isBuffer(encoded)) {
    throw new Error('ExpectedFeaturesBufferToDecodeFeatures');
  }

  // The final byte holds the lowest feature bits
  const bits = [...encoded].reverse().flatMap((byte, i) => {
    return bitPositions
      .filter(bit => isSet(byte, bit))
      .map(bit => i * bitsPerByte + bit);
  });

  return {bits};
};
