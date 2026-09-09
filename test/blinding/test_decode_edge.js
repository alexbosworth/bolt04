const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeEdge} = require('./../../blinding');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'An encoded edge is required',
    error: 'ExpectedShortChannelIdBufferToDecodeEdge',
  },
  {
    args: {encoded: '000ebd480008a70000'},
    description: 'An encoded edge must be a buffer',
    error: 'ExpectedShortChannelIdBufferToDecodeEdge',
  },
  {
    args: {encoded: hexAsBuffer('000ebd480008a700')},
    description: 'An encoded edge must have a direction and short channel id',
    error: 'ExpectedDirectionAndShortChannelIdBytesToDecodeEdge',
  },
  {
    args: {encoded: hexAsBuffer('020ebd480008a70000')},
    description: 'An encoded edge must start with a known direction',
    error: 'ExpectedKnownDirectionByteToDecodeEdge',
  },
  {
    args: {encoded: hexAsBuffer('000ebd480008a70000')},
    description: 'An edge from the first node of a channel is decoded',
    expected: {edge: '965960x2215x0x0'},
  },
  {
    args: {encoded: hexAsBuffer('010ebd480008a70000')},
    description: 'An edge from the second node of a channel is decoded',
    expected: {edge: '965960x2215x0x1'},
  },
  {
    args: {encoded: hexAsBuffer('01ffffffffffffffff')},
    description: 'An edge with maximum values is decoded',
    expected: {edge: '16777215x16777215x65535x1'},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decodeEdge(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(decodeEdge(args), expected, 'Got expected decoded edge');

    return end();
  });
});
