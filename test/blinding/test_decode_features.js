const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeFeatures} = require('./../../blinding');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'Encoded features are required',
    error: 'ExpectedFeaturesBufferToDecodeFeatures',
  },
  {
    args: {encoded: '0200'},
    description: 'Encoded features must be a buffer',
    error: 'ExpectedFeaturesBufferToDecodeFeatures',
  },
  {
    args: {encoded: Buffer.alloc(0)},
    description: 'Empty features have no bits set',
    expected: {bits: []},
  },
  {
    args: {encoded: Buffer.alloc(2)},
    description: 'Zero features have no bits set',
    expected: {bits: []},
  },
  {
    args: {encoded: hexAsBuffer('01')},
    description: 'The lowest bit is the least significant bit of the last byte',
    expected: {bits: [0]},
  },
  {
    args: {encoded: hexAsBuffer('0200')},
    description: 'Bits in earlier bytes are higher feature bits',
    expected: {bits: [9]},
  },
  {
    args: {encoded: hexAsBuffer('8003')},
    description: 'Multiple set bits are decoded in ascending order',
    expected: {bits: [0, 1, 15]},
  },
  {
    args: {encoded: hexAsBuffer('020000000000000000000000000000')},
    description: 'The route blinding vector allowed feature bit is decoded',
    expected: {bits: [113]},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decodeFeatures(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(decodeFeatures(args), expected, 'Got expected feature bits');

    return end();
  });
});
