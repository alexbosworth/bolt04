const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {encodeEdge} = require('./../../blinding');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'An edge is required',
    error: 'ExpectedEdgeFormatChannelIdToEncodeEdge',
  },
  {
    args: {edge: '965960x2215x0'},
    description: 'An edge must have a direction',
    error: 'ExpectedEdgeFormatChannelIdToEncodeEdge',
  },
  {
    args: {edge: '965960x2215x0x2'},
    description: 'An edge direction must be zero or one',
    error: 'ExpectedEdgeFormatChannelIdToEncodeEdge',
  },
  {
    args: {edge: '16777216x2215x0x0'},
    description: 'An edge block height must fit in three bytes',
    error: 'ExpectedBlockHeightWithinRangeForChannelId',
  },
  {
    args: {edge: '965960x16777216x0x0'},
    description: 'An edge block index must fit in three bytes',
    error: 'ExpectedBlockIndexWithinRangeForChannelId',
  },
  {
    args: {edge: '965960x2215x65536x0'},
    description: 'An edge output index must fit in two bytes',
    error: 'ExpectedOutputIndexWithinRangeForChannelId',
  },
  {
    args: {edge: '965960x2215x0x0'},
    description: 'An edge from the first node of a channel is encoded',
    expected: {encoded: hexAsBuffer('000ebd480008a70000')},
  },
  {
    args: {edge: '965960x2215x0x1'},
    description: 'An edge from the second node of a channel is encoded',
    expected: {encoded: hexAsBuffer('010ebd480008a70000')},
  },
  {
    args: {edge: '16777215x16777215x65535x1'},
    description: 'An edge with maximum values is encoded',
    expected: {encoded: hexAsBuffer('01ffffffffffffffff')},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => encodeEdge(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(encodeEdge(args), expected, 'Got expected encoded edge');

    return end();
  });
});
