const {bitsPerByte} = require('./constants');
const {maxTruncatedByteLength} = require('./constants');
const {minByteLength} = require('./constants');

const {from} = Buffer;
const hexBase = 16;
const hexPerByte = 2;
const isByteLength = n => n >= minByteLength && n <= maxTruncatedByteLength;
const isNumeric = n => typeof n === 'string' && /^\d+$/.test(n);
const {isSafeInteger} = Number;
const leadingZeroBytes = /^(00)+/;
const maxValue = bytes => BigInt(2) ** BigInt(bytes * bitsPerByte) - BigInt(1);

/** Encode a number as a truncated big endian unsigned integer

  A truncated number is the minimal big endian encoding of an unsigned integer
  with all leading zero bytes removed, as in the BOLT 01 tu16, tu32, tu64 types.

  Zero is encoded as no bytes at all.

  {
    bytes: <Maximum Encoded Byte Length Number>
    number: <Unsigned Integer Number String>
  }

  @throws
  <Error>

  @returns
  {
    encoded: <Truncated Big Endian Encoded Number Buffer Object>
  }
*/
module.exports = ({bytes, number}) => {
  if (!isSafeInteger(bytes) || !isByteLength(bytes)) {
    throw new Error('ExpectedSupportedByteLengthToEncodeTruncatedNumber');
  }

  if (!isNumeric(number)) {
    throw new Error('ExpectedUnsignedIntegerStringToEncodeTruncatedNumber');
  }

  if (BigInt(number) > maxValue(bytes)) {
    throw new Error('ExpectedNumberWithinByteLengthToEncodeTruncatedNumber');
  }

  const hex = BigInt(number).toString(hexBase);

  const fixed = hex.padStart(bytes * hexPerByte, '0');

  // The fixed length encoding is truncated by removing the leading zero bytes
  const truncated = fixed.replace(leadingZeroBytes, String());

  return {encoded: from(truncated, 'hex')};
};
