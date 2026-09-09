const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeHopData} = require('./../../blinding');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const tests = [
  {
    args: {},
    description: 'Data is required',
    error: 'ExpectedDataBufferToDecodeHopData',
  },
  {
    args: {data: '0100'},
    description: 'Data must be a buffer',
    error: 'ExpectedDataBufferToDecodeHopData',
  },
  {
    args: {data: hexAsBuffer('ff')},
    description: 'Data must be a valid TLV stream',
    error: 'ExpectedValidTlvStreamToDecodeHopData',
  },
  {
    args: {data: hexAsBuffer('080100080100')},
    description: 'Data must not have repeated record types',
    error: 'ExpectedOrderedTlvStreamToDecodeHopData',
  },
  {
    args: {data: hexAsBuffer('04000100')},
    description: 'Data must have ascending record types',
    error: 'ExpectedOrderedTlvStreamToDecodeHopData',
  },
  {
    args: {data: Buffer.alloc(0)},
    description: 'Empty data has no records',
    expected: {records: []},
  },
  {
    args: {data: hexAsBuffer('0100060412345678')},
    description: 'Data records are decoded',
    expected: {
      records: [{type: '1', value: ''}, {type: '6', value: '12345678'}],
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decodeHopData(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(decodeHopData(args), expected, 'Got expected records');

    return end();
  });
});
