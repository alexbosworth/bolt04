const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {encodePaymentRelay} = require('./../../blinding');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: undefined,
    description: 'Arguments are required',
    error: 'ExpectedArgumentsToEncodePaymentRelay',
  },
  {
    args: {cltv_delta: 36, fee_rate: 150},
    description: 'A base fee is required',
    error: 'ExpectedBaseFeeMillitokensToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: 10000, cltv_delta: 36, fee_rate: 150},
    description: 'A base fee must be a millitokens string',
    error: 'ExpectedBaseFeeMillitokensToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '4294967296', cltv_delta: 36, fee_rate: 150},
    description: 'A base fee must fit in four bytes',
    error: 'ExpectedBaseFeeWithinRangeToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', fee_rate: 150},
    description: 'A cltv delta is required',
    error: 'ExpectedCltvDeltaToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', cltv_delta: -1, fee_rate: 150},
    description: 'A cltv delta must not be negative',
    error: 'ExpectedCltvDeltaToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', cltv_delta: 65536, fee_rate: 150},
    description: 'A cltv delta must fit in two bytes',
    error: 'ExpectedCltvDeltaWithinRangeToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', cltv_delta: 36},
    description: 'A fee rate is required',
    error: 'ExpectedFeeRateToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', cltv_delta: 36, fee_rate: 1.5},
    description: 'A fee rate must be an integer',
    error: 'ExpectedFeeRateToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', cltv_delta: 36, fee_rate: 4294967296},
    description: 'A fee rate must fit in four bytes',
    error: 'ExpectedFeeRateWithinRangeToEncodePaymentRelay',
  },
  {
    args: {base_fee_mtokens: '10000', cltv_delta: 36, fee_rate: 150},
    description: 'Payment relay data is encoded with a truncated base fee',
    expected: {encoded: hexAsBuffer('0024000000962710')},
  },
  {
    args: {base_fee_mtokens: '500', cltv_delta: 48, fee_rate: 100},
    description: 'Payment relay data is encoded with a two byte base fee',
    expected: {encoded: hexAsBuffer('00300000006401f4')},
  },
  {
    args: {base_fee_mtokens: '0', cltv_delta: 144, fee_rate: 250},
    description: 'Payment relay data is encoded with no base fee bytes',
    expected: {encoded: hexAsBuffer('0090000000fa')},
  },
  {
    args: {base_fee_mtokens: '4294967295', cltv_delta: 65535, fee_rate: 0},
    description: 'Payment relay data is encoded with maximum values',
    expected: {encoded: hexAsBuffer('ffff00000000ffffffff')},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => encodePaymentRelay(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(encodePaymentRelay(args), expected, 'Got expected encoding');

    return end();
  });
});
