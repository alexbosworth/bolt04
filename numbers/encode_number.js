const {bitsPerByte} = require('./constants');
const {maxByteLength} = require('./constants');
const {minByteLength} = require('./constants');

const {alloc} = Buffer;
const isByteLength = n => n >= minByteLength && n <= maxByteLength;
const {isSafeInteger} = Number;
const isUnsigned = n => isSafeInteger(n) && n >= Number();
const maxValue = bytes => 2 ** (bytes * bitsPerByte) - 1;

/** Encode a number as a fixed length big endian unsigned integer

  {
    bytes: <Encoded Byte Length Number>
    number: <Unsigned Integer Number>
  }

  @throws
  <Error>

  @returns
  {
    encoded: <Big Endian Encoded Number Buffer Object>
  }
*/
module.exports = ({bytes, number}) => {
  if (!isSafeInteger(bytes) || !isByteLength(bytes)) {
    throw new Error('ExpectedSupportedByteLengthToEncodeNumber');
  }

  if (!isUnsigned(number)) {
    throw new Error('ExpectedUnsignedIntegerToEncodeNumber');
  }

  if (number > maxValue(bytes)) {
    throw new Error('ExpectedNumberWithinByteLengthToEncodeNumber');
  }

  const encoded = alloc(bytes);

  encoded.writeUIntBE(number, Number(), bytes);

  return {encoded};
};
