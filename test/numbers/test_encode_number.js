const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {encodeNumber} = require('./../../numbers');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'A byte length is required',
    error: 'ExpectedSupportedByteLengthToEncodeNumber',
  },
  {
    args: {bytes: 1.5, number: 0},
    description: 'A byte length must be an integer',
    error: 'ExpectedSupportedByteLengthToEncodeNumber',
  },
  {
    args: {bytes: 0, number: 0},
    description: 'A byte length must be at least one byte',
    error: 'ExpectedSupportedByteLengthToEncodeNumber',
  },
  {
    args: {bytes: 7, number: 0},
    description: 'A byte length must be at most six bytes',
    error: 'ExpectedSupportedByteLengthToEncodeNumber',
  },
  {
    args: {bytes: 1},
    description: 'A number is required',
    error: 'ExpectedUnsignedIntegerToEncodeNumber',
  },
  {
    args: {bytes: 1, number: 1.5},
    description: 'A number must be an integer',
    error: 'ExpectedUnsignedIntegerToEncodeNumber',
  },
  {
    args: {bytes: 1, number: -1},
    description: 'A number must not be negative',
    error: 'ExpectedUnsignedIntegerToEncodeNumber',
  },
  {
    args: {bytes: 1, number: 256},
    description: 'A number must fit within the byte length',
    error: 'ExpectedNumberWithinByteLengthToEncodeNumber',
  },
  {
    args: {bytes: 1, number: 0},
    description: 'Zero is encoded as a zero byte',
    expected: {encoded: hexAsBuffer('00')},
  },
  {
    args: {bytes: 1, number: 255},
    description: 'A maximum single byte number is encoded',
    expected: {encoded: hexAsBuffer('ff')},
  },
  {
    args: {bytes: 2, number: 258},
    description: 'A number is encoded as big endian bytes',
    expected: {encoded: hexAsBuffer('0102')},
  },
  {
    args: {bytes: 3, number: 965960},
    description: 'A number is encoded into three bytes',
    expected: {encoded: hexAsBuffer('0ebd48')},
  },
  {
    args: {bytes: 6, number: 2 ** 48 - 1},
    description: 'A maximum six byte number is encoded',
    expected: {encoded: hexAsBuffer('ffffffffffff')},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => encodeNumber(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(encodeNumber(args), expected, 'Got expected encoded number');

    return end();
  });
});
