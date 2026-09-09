const {encodeTlvStream} = require('bolt01');
const {isPoint} = require('tiny-secp256k1');
const {isPrivate} = require('tiny-secp256k1');

const {blindedPathFromHops} = require('./../blinding');
const {createBlindedPath} = require('./../blinding');
const {encodeBlindedPath} = require('./../blinding');
const encodeOnionPacket = require('./encode_onion_packet');
const {lengthAuthTagBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {padHopData} = require('./../blinding');
const {typeEncryptedRecipientData} = require('./constants');
const {typeNextNodeId} = require('./constants');
const {typeNextPathKeyOverride} = require('./constants');
const {typeReplyPath} = require('./constants');

const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const {from} = Buffer;
const hasType = (records, type) => records.some(n => isType(n.type, type));
const hexAsBuffer = hex => from(hex, 'hex');
const {isArray} = Array;
const isCompressedKey = n => byteLength(n) === lengthPointBytes;
const isHex = n => !(n.length % 2) && /^[0-9A-F]*$/i.test(n);
const isHexString = n => typeof n === 'string' && isHex(n);
const isPrivateKey = n => isPrivate(from(n, 'hex'));
const isPublicKey = n => isPoint(from(n, 'hex'));
const isRecordType = n => typeof n === 'string' && /^\d+$/.test(n);
const isType = (n, type) => BigInt(n) === BigInt(type);
const last = arr => arr[arr.length - 1];
const {max} = Math;
const relays = arr => arr.slice(Number(), -1);

/** Create an onion for a given path

  `inbound` are the blinded hops of the published blinded path

  `outbound` are nodes to reach the blinded path, ending with its introduction

  `records` are added to the payload of the final hop

  `reply` is a route back to the sender that ends with the sender's node id

  Send the `onion` to the first `outbound` node with the path's `key`

  {
    inbound: [{
      encrypted_data: <Encrypted Data Hex String>
      relay_key: <Blinded Relaying Public Key Into Destination Hex String>
    }]
    key: <Inbound Path Key Public Key Hex String>
    outbound: [<Relaying Node Public Key Out of Source Hex String>]
    [records]: [{
      type: <Final Hop Additional Record Type Number String>
      value: <Final Hop Additional Record Value Hex String>
    }]
    [reply]: [<Reply Path Relaying Node Public Key Back To Sender Hex String>]
    [secret]: <Outbound Path Key Secret Private Key Hex String>
  }

  @throws
  <Error>

  @returns
  {
    [id]: <Reply Path Identifier Hex String>
    key: <Path Key To Send With Onion Public Key Hex String>
    onion: <Onion Packet Hex String>
  }
*/
module.exports = ({inbound, key, outbound, records, reply, secret}) => {
  if (!isArray(inbound) || !inbound.length) {
    throw new Error('ExpectedArrayOfInboundHopsToCreatePathOnion');
  }

  if (!inbound.every(n => !!n && isHexString(n.encrypted_data))) {
    throw new Error('ExpectedHexEncodedInboundEncryptedDataToCreatePathOnion');
  }

  if (!inbound.every(n => isHexString(n.relay_key))) {
    throw new Error('ExpectedHexEncodedInboundHopRelayKeyToCreatePathOnion');
  }

  if (!inbound.every(n => isCompressedKey(n.relay_key))) {
    throw new Error('ExpectedCompressedInboundHopRelayKeyToCreatePathOnion');
  }

  if (!inbound.every(n => isPublicKey(n.relay_key))) {
    throw new Error('ExpectedValidInboundHopRelayKeyToCreatePathOnion');
  }

  if (!key || !isHexString(key)) {
    throw new Error('ExpectedHexEncodedInboundPathKeyToCreatePathOnion');
  }

  if (!isCompressedKey(key)) {
    throw new Error('ExpectedCompressedInboundPathKeyToCreatePathOnion');
  }

  if (!isPublicKey(key)) {
    throw new Error('ExpectedValidInboundPathKeyToCreatePathOnion');
  }

  // The outbound keys end with the landmark that starts the inbound path
  if (!isArray(outbound) || !outbound.length) {
    throw new Error('ExpectedArrayOfOutboundRelayKeysToCreatePathOnion');
  }

  if (!outbound.every(isHexString)) {
    throw new Error('ExpectedHexEncodedOutboundRelayKeyToCreatePathOnion');
  }

  if (!outbound.every(isCompressedKey)) {
    throw new Error('ExpectedCompressedOutboundRelayKeyToCreatePathOnion');
  }

  if (!outbound.every(isPublicKey)) {
    throw new Error('ExpectedValidOutboundRelayKeyToCreatePathOnion');
  }

  if (!!records && !isArray(records)) {
    throw new Error('ExpectedArrayOfFinalHopRecordsToCreatePathOnion');
  }

  const finalRecords = records || [];

  if (!finalRecords.every(n => !!n && isRecordType(n.type))) {
    throw new Error('ExpectedRecordTypeNumberStringToCreatePathOnion');
  }

  if (!finalRecords.every(n => isHexString(n.value))) {
    throw new Error('ExpectedHexEncodedRecordValueToCreatePathOnion');
  }

  // The encrypted recipient data record is reserved for the hop encrypted data
  if (hasType(finalRecords, typeEncryptedRecipientData)) {
    throw new Error('UnexpectedEncryptedDataRecordToCreatePathOnion');
  }

  if (!!reply && (!isArray(reply) || !reply.length)) {
    throw new Error('ExpectedArrayOfReplyPathHopsToCreatePathOnion');
  }

  const replyHops = reply || [];

  if (!replyHops.every(isHexString)) {
    throw new Error('ExpectedHexEncodedReplyHopPublicKeyToCreatePathOnion');
  }

  if (!replyHops.every(isCompressedKey)) {
    throw new Error('ExpectedCompressedReplyHopPublicKeyToCreatePathOnion');
  }

  if (!replyHops.every(isPublicKey)) {
    throw new Error('ExpectedValidReplyHopPublicKeyToCreatePathOnion');
  }

  // The reply path record is reserved for the reply path that is blinded here
  if (!!replyHops.length && hasType(finalRecords, typeReplyPath)) {
    throw new Error('UnexpectedReplyPathRecordToCreatePathOnion');
  }

  if (!!secret && !isHexString(secret)) {
    throw new Error('ExpectedHexEncodedPathKeySecretToCreatePathOnion');
  }

  if (!!secret && byteLength(secret) !== lengthKeyBytes) {
    throw new Error('ExpectedPathKeySecretByteLengthToCreatePathOnion');
  }

  if (!!secret && !isPrivateKey(secret)) {
    throw new Error('ExpectedValidPathKeySecretToCreatePathOnion');
  }

  const landmark = last(outbound);

  // The relaying nodes before the landmark each forward to the next one, and
  // the last relaying node forwards to the landmark with the inbound path key
  const relayingRecords = relays(outbound).map((publicKey, i, keys) => {
    const next = keys[i + 1];

    return [
      {type: typeNextNodeId, value: next || landmark},
      ...(!next ? [{type: typeNextPathKeyOverride, value: key}] : []),
    ];
  });

  // The inbound hops encrypted data has an authentication tag after the data
  const inboundDataLength = max(...inbound.map(hop => {
    return byteLength(hop.encrypted_data) - lengthAuthTagBytes;
  }));

  // Relaying data is padded to the inbound data length to look like inbound
  const {data} = !relayingRecords.length ? {data: []} : padHopData({
    bytes: max(inboundDataLength, Number()),
    records: relayingRecords,
  });

  const relaying = relays(outbound).map((publicKey, i) => {
    return {data: data[i], public_key: hexAsBuffer(publicKey)};
  });

  // There are no relaying nodes to blind when intro node is the sender's peer
  const path = !relaying.length ? null : createBlindedPath({
    hops: relaying,
    secret: !secret ? undefined : hexAsBuffer(secret),
  });

  const relayingHops = !path ? [] : path.hops.map(hop => ({
    encrypted_data: bufferAsHex(hop.encrypted_data),
    relay_key: bufferAsHex(hop.blinded_public_key),
  }));

  const hops = [].concat(relayingHops).concat(inbound);

  // A reply path back to the sender is blinded by the sender for the final hop
  const replyPath = !replyHops.length ? null : blindedPathFromHops({
    hops: replyHops,
  });

  const replyRecords = !replyPath ? [] : [{
    type: typeReplyPath,
    value: bufferAsHex(encodeBlindedPath({
      first_node_id: hexAsBuffer(replyHops[Number()]),
      first_path_key: hexAsBuffer(replyPath.key),
      hops: replyPath.path.map(hop => ({
        blinded_public_key: hexAsBuffer(hop.relay_key),
        encrypted_data: hexAsBuffer(hop.encrypted_data),
      })),
    }).encoded),
  }];

  // Every hop payload has its encrypted data, the final one also has records
  const {onion} = encodeOnionPacket({
    hops: hops.map((hop, i) => ({
      payload: hexAsBuffer(encodeTlvStream({
        records: [
          {type: typeEncryptedRecipientData, value: hop.encrypted_data},
          ...(i === hops.length - 1 ? replyRecords.concat(finalRecords) : []),
        ],
      }).encoded),
      public_key: hexAsBuffer(hop.relay_key),
    })),
  });

  return {
    id: !replyPath ? undefined : replyPath.id,
    key: !path ? key : bufferAsHex(path.key),
    onion: bufferAsHex(onion),
  };
};
