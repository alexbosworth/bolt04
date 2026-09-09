const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodePayloadLength} = require('./../../packets');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'An encoded payload is required',
    error: 'ExpectedPayloadBufferToDecodePayloadLength',
  },
  {
    args: {encoded: '00'},
    description: 'An encoded payload must be a buffer',
    error: 'ExpectedPayloadBufferToDecodePayloadLength',
  },
  {
    args: {encoded: Buffer.alloc(0)},
    description: 'An encoded payload must have a length prefix',
    error: 'ExpectedValidBigSizePrefixToDecodePayloadLength',
  },
  {
    args: {encoded: hexAsBuffer('fd')},
    description: 'A length prefix must have all of its bytes',
    error: 'ExpectedValidBigSizePrefixToDecodePayloadLength',
  },
  {
    args: {encoded: hexAsBuffer('fd0001')},
    description: 'A length prefix must be minimally encoded',
    error: 'ExpectedValidBigSizePrefixToDecodePayloadLength',
  },
  {
    args: {encoded: Buffer.alloc(1)},
    description: 'A zero length prefix is decoded',
    expected: {bytes: 1, number: 0},
  },
  {
    args: {encoded: hexAsBuffer(`2a${'00'.repeat(42)}`)},
    description: 'A single byte length prefix is decoded',
    expected: {bytes: 1, number: 42},
  },
  {
    args: {encoded: hexAsBuffer(`fd0100${'00'.repeat(256)}`)},
    description: 'A three byte length prefix is decoded',
    expected: {bytes: 3, number: 256},
  },
  {
    args: {encoded: hexAsBuffer('fe00010000')},
    description: 'A five byte length prefix is decoded',
    expected: {bytes: 5, number: 65536},
  },
  {
    args: {encoded: hexAsBuffer('ff0000000100000000')},
    description: 'A nine byte length prefix is decoded',
    expected: {bytes: 9, number: 4294967296},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decodePayloadLength(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(decodePayloadLength(args), expected, 'Got expected length');

    return end();
  });
});
