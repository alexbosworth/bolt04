const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {encodeTruncatedNumber} = require('./../../numbers');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'A byte length is required',
    error: 'ExpectedSupportedByteLengthToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 1.5, number: '0'},
    description: 'A byte length must be an integer',
    error: 'ExpectedSupportedByteLengthToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 0, number: '0'},
    description: 'A byte length must be at least one byte',
    error: 'ExpectedSupportedByteLengthToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 9, number: '0'},
    description: 'A byte length must be at most eight bytes',
    error: 'ExpectedSupportedByteLengthToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 4},
    description: 'A number is required',
    error: 'ExpectedUnsignedIntegerStringToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 4, number: 10000},
    description: 'A number must be a string',
    error: 'ExpectedUnsignedIntegerStringToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 4, number: '1.5'},
    description: 'A number must be an integer',
    error: 'ExpectedUnsignedIntegerStringToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 4, number: '-1'},
    description: 'A number must not be negative',
    error: 'ExpectedUnsignedIntegerStringToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 4, number: '4294967296'},
    description: 'A number must fit within the byte length',
    error: 'ExpectedNumberWithinByteLengthToEncodeTruncatedNumber',
  },
  {
    args: {bytes: 4, number: '0'},
    description: 'Zero is encoded as no bytes',
    expected: {encoded: hexAsBuffer('')},
  },
  {
    args: {bytes: 4, number: '1'},
    description: 'A small number is encoded as a single byte',
    expected: {encoded: hexAsBuffer('01')},
  },
  {
    args: {bytes: 4, number: '255'},
    description: 'A maximum single byte number is encoded as a single byte',
    expected: {encoded: hexAsBuffer('ff')},
  },
  {
    args: {bytes: 4, number: '256'},
    description: 'A number is encoded as big endian bytes',
    expected: {encoded: hexAsBuffer('0100')},
  },
  {
    args: {bytes: 4, number: '10000'},
    description: 'A base fee of ten thousand millitokens is encoded',
    expected: {encoded: hexAsBuffer('2710')},
  },
  {
    args: {bytes: 4, number: '4294967295'},
    description: 'A maximum four byte number is encoded',
    expected: {encoded: hexAsBuffer('ffffffff')},
  },
  {
    args: {bytes: 8, number: '4294967296'},
    description: 'A number larger than four bytes is encoded into five bytes',
    expected: {encoded: hexAsBuffer('0100000000')},
  },
  {
    args: {bytes: 8, number: '18446744073709551615'},
    description: 'A maximum eight byte number is encoded',
    expected: {encoded: hexAsBuffer('ffffffffffffffff')},
  },
  {
    args: {bytes: 8, number: '18446744073709551616'},
    description: 'A number must fit within eight bytes',
    error: 'ExpectedNumberWithinByteLengthToEncodeTruncatedNumber',
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(
        () => encodeTruncatedNumber(args),
        new Error(error),
        'Got error'
      );

      return end();
    }

    strictSame(encodeTruncatedNumber(args), expected, 'Got expected encoded');

    return end();
  });
});
