const {bitsPerByte} = require('./constants');
const {encodeNumber} = require('./../numbers');
const {encodeTruncatedNumber} = require('./../numbers');
const {lengthMaxHeightBytes} = require('./constants');
const {lengthMinHtlcBytes} = require('./constants');

const {concat} = Buffer;
const isNumeric = n => typeof n === 'string' && /^\d+$/.test(n);
const {isSafeInteger} = Number;
const isUnsigned = n => isSafeInteger(n) && n >= Number();
const maxValue = bytes => BigInt(2) ** BigInt(bytes * bitsPerByte) - BigInt(1);

/** Encode the payment constraints of a hop in a blinded payment path

  A node in a blinded payment path rejects a payment that has a CLTV expiry
  past the maximum timeout height or an amount below the minimum HTLC amount.

  {
    max_timeout_height: <Maximum HTLC CLTV Expiry Block Height Number>
    min_htlc_mtokens: <Minimum HTLC Millitokens String>
  }

  @throws
  <Error>

  @returns
  {
    encoded: <Encoded Payment Constraints Buffer Object>
  }
*/
module.exports = args => {
  if (!args) {
    throw new Error('ExpectedArgumentsToEncodePaymentConstraints');
  }

  if (!isUnsigned(args.max_timeout_height)) {
    throw new Error('ExpectedMaxTimeoutHeightToEncodePaymentConstraints');
  }

  if (BigInt(args.max_timeout_height) > maxValue(lengthMaxHeightBytes)) {
    throw new Error('ExpectedMaxHeightWithinRangeToEncodePaymentConstraints');
  }

  if (!isNumeric(args.min_htlc_mtokens)) {
    throw new Error('ExpectedMinHtlcMillitokensToEncodePaymentConstraints');
  }

  if (BigInt(args.min_htlc_mtokens) > maxValue(lengthMinHtlcBytes)) {
    throw new Error('ExpectedMinHtlcWithinRangeToEncodePaymentConstraints');
  }

  const maxTimeoutHeight = encodeNumber({
    bytes: lengthMaxHeightBytes,
    number: args.max_timeout_height,
  });

  // The minimum HTLC is a truncated number so a zero minimum has no bytes
  const minHtlc = encodeTruncatedNumber({
    bytes: lengthMinHtlcBytes,
    number: args.min_htlc_mtokens,
  });

  return {encoded: concat([maxTimeoutHeight.encoded, minHtlc.encoded])};
};
