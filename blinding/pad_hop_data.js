const {encodeBigSize} = require('bolt01');
const {encodeTlvStream} = require('bolt01');

const {lengthRecordTypeBytes} = require('./constants');
const {typePadding} = require('./constants');

const bigSizeLength = n => byteLength(encodeBigSize({number: `${n}`}).encoded);
const byteLength = hex => hex.length / 2;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const {isArray} = Array;
const {isInteger} = Number;
const isPositive = n => n >= Number();
const isRecord = n => !!n && BigInt(n.type) !== BigInt(typePadding);
const isRecords = n => isArray(n) && n.every(isRecord);
const {max} = Math;
const paddingOverheads = [2, 4, 6, 10];
const paddingCandidates = n => paddingOverheads.map(overhead => n - overhead);
const recordLength = n => lengthRecordTypeBytes + bigSizeLength(n) + n;
const zeroBytes = count => '00'.repeat(count);

/** Encode hop data records as TLV streams that are padded to the same length

  A zero bytes padding record is added to the data of any hop that is shorter
  than the longest hop data, or shorter than the minimum length when given.

  {
    [bytes]: <Minimum Data Byte Length Number>
    records: [[{
      type: <Record Type Number String>
      value: <Record Value Hex String>
    }]]
  }

  @throws
  <Error>

  @returns
  {
    data: [<Padded Data TLV Stream Buffer Object>]
  }
*/
module.exports = ({bytes, records}) => {
  if (!!bytes && (!isInteger(bytes) || !isPositive(bytes))) {
    throw new Error('ExpectedMinimumDataLengthNumberToPadHopData');
  }

  if (!isArray(records) || !records.length || !records.every(isRecords)) {
    throw new Error('ExpectedArrayOfHopRecordsWithoutPaddingToPadHopData');
  }

  const streams = records.map(n => {
    return hexAsBuffer(encodeTlvStream({records: n}).encoded);
  });

  const lengths = streams.map(n => n.length);

  // A padding record is a type, a length prefix, and the zero padding bytes
  const paddingLength = missing => {
    return paddingCandidates(missing).filter(isPositive).find(n => {
      return recordLength(n) === missing;
    });
  };

  // The common length is the shortest that every hop can be padded to exactly
  const paddedLength = target => {
    const missing = lengths.map(n => target - n);

    if (missing.every(n => !n || paddingLength(n) !== undefined)) {
      return target;
    }

    return paddedLength(target + 1);
  };

  const target = paddedLength(max(...lengths, bytes || Number()));

  // Hops that are short of the common length get a zero bytes padding record
  const data = records.map((hopRecords, i) => {
    const missing = target - lengths[i];

    if (!missing) {
      return streams[i];
    }

    const padding = {
      type: typePadding,
      value: zeroBytes(paddingLength(missing)),
    };

    const {encoded} = encodeTlvStream({records: [padding].concat(hopRecords)});

    return hexAsBuffer(encoded);
  });

  return {data};
};
