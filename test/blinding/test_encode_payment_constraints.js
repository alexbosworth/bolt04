const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {encodePaymentConstraints} = require('./../../blinding');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: undefined,
    description: 'Arguments are required',
    error: 'ExpectedArgumentsToEncodePaymentConstraints',
  },
  {
    args: {min_htlc_mtokens: '1500'},
    description: 'A maximum timeout height is required',
    error: 'ExpectedMaxTimeoutHeightToEncodePaymentConstraints',
  },
  {
    args: {max_timeout_height: '748005', min_htlc_mtokens: '1500'},
    description: 'A maximum timeout height must be a number',
    error: 'ExpectedMaxTimeoutHeightToEncodePaymentConstraints',
  },
  {
    args: {max_timeout_height: 4294967296, min_htlc_mtokens: '1500'},
    description: 'A maximum timeout height must fit in four bytes',
    error: 'ExpectedMaxHeightWithinRangeToEncodePaymentConstraints',
  },
  {
    args: {max_timeout_height: 748005},
    description: 'A minimum htlc is required',
    error: 'ExpectedMinHtlcMillitokensToEncodePaymentConstraints',
  },
  {
    args: {max_timeout_height: 748005, min_htlc_mtokens: 1500},
    description: 'A minimum htlc must be a millitokens string',
    error: 'ExpectedMinHtlcMillitokensToEncodePaymentConstraints',
  },
  {
    args: {
      max_timeout_height: 748005,
      min_htlc_mtokens: '18446744073709551616',
    },
    description: 'A minimum htlc must fit in eight bytes',
    error: 'ExpectedMinHtlcWithinRangeToEncodePaymentConstraints',
  },
  {
    args: {max_timeout_height: 748005, min_htlc_mtokens: '1500'},
    description: 'Payment constraints are encoded with a truncated minimum',
    expected: {encoded: hexAsBuffer('000b69e505dc')},
  },
  {
    args: {max_timeout_height: 750150, min_htlc_mtokens: '50'},
    description: 'Payment constraints are encoded with a one byte minimum',
    expected: {encoded: hexAsBuffer('000b724632')},
  },
  {
    args: {max_timeout_height: 0, min_htlc_mtokens: '0'},
    description: 'Payment constraints are encoded with no minimum bytes',
    expected: {encoded: hexAsBuffer('00000000')},
  },
  {
    args: {
      max_timeout_height: 4294967295,
      min_htlc_mtokens: '18446744073709551615',
    },
    description: 'Payment constraints are encoded with maximum values',
    expected: {encoded: hexAsBuffer('ffffffffffffffffffffffff')},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(
        () => encodePaymentConstraints(args),
        new Error(error),
        'Got error'
      );

      return end();
    }

    strictSame(encodePaymentConstraints(args), expected, 'Got encoding');

    return end();
  });
});
