const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {padHopData} = require('./../../blinding');

const bufferAsHex = buffer => buffer.toString('hex');
const id = '06'.repeat(32);
const key = `02${'01'.repeat(32)}`;
const nextNodeId = {type: '4', value: key};
const pathId = {type: '6', value: id};
const zeros = count => '00'.repeat(count);

const tests = [
  {
    args: {bytes: -1, records: [[nextNodeId]]},
    description: 'A minimum length must be a positive number',
    error: 'ExpectedMinimumDataLengthNumberToPadHopData',
  },
  {
    args: {bytes: 1.5, records: [[nextNodeId]]},
    description: 'A minimum length must be an integer',
    error: 'ExpectedMinimumDataLengthNumberToPadHopData',
  },
  {
    args: {},
    description: 'Records are required',
    error: 'ExpectedArrayOfHopRecordsWithoutPaddingToPadHopData',
  },
  {
    args: {records: []},
    description: 'Records for at least one hop are required',
    error: 'ExpectedArrayOfHopRecordsWithoutPaddingToPadHopData',
  },
  {
    args: {records: [nextNodeId]},
    description: 'Records must be an array of records for every hop',
    error: 'ExpectedArrayOfHopRecordsWithoutPaddingToPadHopData',
  },
  {
    args: {records: [[null]]},
    description: 'Records must be records',
    error: 'ExpectedArrayOfHopRecordsWithoutPaddingToPadHopData',
  },
  {
    args: {records: [[{type: '1', value: ''}, pathId]]},
    description: 'Records must not already have padding',
    error: 'ExpectedArrayOfHopRecordsWithoutPaddingToPadHopData',
  },
  {
    args: {records: [[nextNodeId], [nextNodeId]]},
    description: 'Hop data of equal length is not padded',
    expected: {data: [`0421${key}`, `0421${key}`]},
  },
  {
    args: {records: [[nextNodeId], [pathId]]},
    description: 'Hop data is padded past a gap that padding cannot fill',
    expected: {data: [`0100${'04'}21${key}`, `010100${'06'}20${id}`]},
  },
  {
    args: {records: [[nextNodeId], [{type: '6', value: '06'.repeat(31)}]]},
    description: 'Hop data is padded with an empty padding record',
    expected: {data: [`0421${key}`, `0100061f${'06'.repeat(31)}`]},
  },
  {
    args: {records: [[nextNodeId], [{type: '6', value: '06'.repeat(300)}]]},
    description: 'Hop data is padded with a long padding record',
    expected: {
      data: [
        `01fd0109${zeros(265)}0421${key}`,
        `06fd012c${'06'.repeat(300)}`,
      ],
    },
  },
  {
    args: {records: [[nextNodeId], [{type: '6', value: '06'.repeat(286)}]]},
    description: 'Hop data is padded past gaps that padding cannot fill',
    expected: {
      data: [
        `01fd00fd${zeros(253)}0421${key}`,
        `010006fd011e${'06'.repeat(286)}`,
      ],
    },
  },
  {
    args: {bytes: 50, records: [[nextNodeId]]},
    description: 'Hop data is padded to a minimum length',
    expected: {data: [`010d${zeros(13)}0421${key}`]},
  },
  {
    args: {bytes: 10, records: [[nextNodeId]]},
    description: 'Hop data is not padded when longer than the minimum length',
    expected: {data: [`0421${key}`]},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => padHopData(args), new Error(error), 'Got error');

      return end();
    }

    const {data} = padHopData(args);

    strictSame(data.map(bufferAsHex), expected.data, 'Got expected data');

    // Every hop has data of the same length
    strictSame(new Set(data.map(n => n.length)).size, 1, 'Got equal lengths');

    return end();
  });
});
