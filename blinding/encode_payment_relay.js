const {bitsPerByte} = require('./constants');
const {encodeNumber} = require('./../numbers');
const {encodeTruncatedNumber} = require('./../numbers');
const {lengthBaseFeeBytes} = require('./constants');
const {lengthCltvDeltaBytes} = require('./constants');
const {lengthFeeRateBytes} = require('./constants');

const {concat} = Buffer;
const isNumeric = n => typeof n === 'string' && /^\d+$/.test(n);
const {isSafeInteger} = Number;
const isUnsigned = n => isSafeInteger(n) && n >= Number();
const maxValue = bytes => BigInt(2) ** BigInt(bytes * bitsPerByte) - BigInt(1);

/** Encode the payment relay data of a hop in a blinded payment path

  A forwarding node in a blinded payment path uses the relay data to derive the
  amount and CLTV expiry to forward instead of being told them by the sender.

  {
    base_fee_mtokens: <Base Fee Millitokens String>
    cltv_delta: <CLTV Expiry Delta Number>
    fee_rate: <Fee Rate Millitokens Per Million Number>
  }

  @throws
  <Error>

  @returns
  {
    encoded: <Encoded Payment Relay Data Buffer Object>
  }
*/
module.exports = args => {
  if (!args) {
    throw new Error('ExpectedArgumentsToEncodePaymentRelay');
  }

  if (!isNumeric(args.base_fee_mtokens)) {
    throw new Error('ExpectedBaseFeeMillitokensToEncodePaymentRelay');
  }

  if (BigInt(args.base_fee_mtokens) > maxValue(lengthBaseFeeBytes)) {
    throw new Error('ExpectedBaseFeeWithinRangeToEncodePaymentRelay');
  }

  if (!isUnsigned(args.cltv_delta)) {
    throw new Error('ExpectedCltvDeltaToEncodePaymentRelay');
  }

  if (BigInt(args.cltv_delta) > maxValue(lengthCltvDeltaBytes)) {
    throw new Error('ExpectedCltvDeltaWithinRangeToEncodePaymentRelay');
  }

  if (!isUnsigned(args.fee_rate)) {
    throw new Error('ExpectedFeeRateToEncodePaymentRelay');
  }

  if (BigInt(args.fee_rate) > maxValue(lengthFeeRateBytes)) {
    throw new Error('ExpectedFeeRateWithinRangeToEncodePaymentRelay');
  }

  const cltvDelta = encodeNumber({
    bytes: lengthCltvDeltaBytes,
    number: args.cltv_delta,
  });

  const feeRate = encodeNumber({
    bytes: lengthFeeRateBytes,
    number: args.fee_rate,
  });

  // The base fee is a truncated number so a zero base fee has no bytes at all
  const baseFee = encodeTruncatedNumber({
    bytes: lengthBaseFeeBytes,
    number: args.base_fee_mtokens,
  });

  return {
    encoded: concat([cltvDelta.encoded, feeRate.encoded, baseFee.encoded]),
  };
};
