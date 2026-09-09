const {chanFormat} = require('bolt07');

const {channelIdSeparator} = require('./constants');
const {edgeDirections} = require('./constants');
const {lengthDirectionBytes} = require('./constants');
const {lengthShortChannelIdBytes} = require('./constants');

const bufferAsHex = buffer => buffer.toString('hex');
const {isBuffer} = Buffer;

/** Decode a short channel id and direction

  {
    encoded: <Encoded Direction And Short Channel Id Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    edge: <Edge Format Channel Id String>
  }
*/
module.exports = ({encoded}) => {
  if (!isBuffer(encoded)) {
    throw new Error('ExpectedShortChannelIdBufferToDecodeEdge');
  }

  if (encoded.length !== lengthDirectionBytes + lengthShortChannelIdBytes) {
    throw new Error('ExpectedDirectionAndShortChannelIdBytesToDecodeEdge');
  }

  // The direction byte indicates which node of the channel is referenced
  if (!edgeDirections.includes(encoded[Number()])) {
    throw new Error('ExpectedKnownDirectionByteToDecodeEdge');
  }

  const id = bufferAsHex(encoded.subarray(lengthDirectionBytes));

  const {channel} = chanFormat({id});

  return {edge: [channel, encoded[Number()]].join(channelIdSeparator)};
};
