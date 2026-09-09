const {rawChanId} = require('bolt07');

const {channelIdSeparator} = require('./constants');
const {edgeDirections} = require('./constants');
const {encodeNumber} = require('./../numbers');
const {lengthDirectionBytes} = require('./constants');

const {concat} = Buffer;
const {from} = Buffer;
const hexAsBuffer = hex => from(hex, 'hex');
const isEdge = n => typeof n === 'string' && /^\d+x\d+x\d+x[01]$/.test(n);

/** Encode an edge to a node as a short channel id and direction

  An edge is the block height, block index, and output index of a channel, and
  the direction of the edge across the channel: 0 when the edge is from the
  first node of the channel to the second, 1 when it is from the second node to
  the first. The first node of a channel has the lesser public key.

  {
    edge: <Edge Format Channel Id String>
  }

  @throws
  <Error>

  @returns
  {
    encoded: <Encoded Direction And Short Channel Id Buffer Object>
  }
*/
module.exports = ({edge}) => {
  if (!isEdge(edge)) {
    throw new Error('ExpectedEdgeFormatChannelIdToEncodeEdge');
  }

  const [height, index, output, direction] = edge.split(channelIdSeparator);

  // The direction byte comes before the short channel id
  const encodedDirection = encodeNumber({
    bytes: lengthDirectionBytes,
    number: edgeDirections[Number(direction)],
  });

  const channel = [height, index, output].join(channelIdSeparator);

  // The short channel id follows the direction byte
  const {id} = rawChanId({channel});

  return {encoded: concat([encodedDirection.encoded, hexAsBuffer(id)])};
};
