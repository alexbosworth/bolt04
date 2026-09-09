const {createHash} = require('node:crypto');

const {isPoint} = require('tiny-secp256k1');
const {pointMultiply} = require('tiny-secp256k1');

const {chanFormat} = require('bolt07');
const decodeFeatures = require('./decode_features');
const decodeHopData = require('./decode_hop_data');
const decryptHopData = require('./decrypt_hop_data');
const {hashAlgorithm} = require('./constants');
const {lengthAuthTagBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {lengthShortChannelIdBytes} = require('./constants');
const {typeAllowedFeatures} = require('./constants');
const {typeNextNodeId} = require('./constants');
const {typeNextPathKeyOverride} = require('./constants');
const {typePathId} = require('./constants');
const {typeShortChannelId} = require('./constants');

const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const {concat} = Buffer;
const {from} = Buffer;
const hexAsBuffer = hex => from(hex, 'hex');
const isHex = n => !(n.length % 2) && /^[0-9A-F]*$/i.test(n);
const isHexString = n => typeof n === 'string' && isHex(n);
const isPublicKey = n => isPoint(from(n, 'hex'));
const sha256 = data => createHash(hashAlgorithm).update(data).digest();

/** Decrypt the data of a hop in a blinded path

  `secret` is a shared secret computed from the node identity and the path key

  `features` are a total whitelist of feature bits allowed on the path

  {
    encrypted: <Encrypted Data Hex String>
    key: <Path Key Public Key Hex String>
    secret: <Path Key Shared Secret Hex String>
  }

  @throws
  <Error>

  @returns
  {
    data: <Decrypted Data TLV Stream Hex String>
    features: [<Allowed Feature Bit Number>]
    [id]: <Path Identifier Hex String>
    [next_channel_id]: <Next Hop Standard Format Channel Id String>
    [next_node_id]: <Next Node Public Key Hex String>
    next_path_key: <Next Hop Path Key Public Key Hex String>
    records: [{
      type: <Record Type Number String>
      value: <Record Value Hex String>
    }]
  }
*/
module.exports = ({encrypted, key, secret}) => {
  if (!encrypted || !isHexString(encrypted)) {
    throw new Error('ExpectedHexEncodedEncryptedDataToDecryptBlindedPath');
  }

  if (byteLength(encrypted) < lengthAuthTagBytes) {
    throw new Error('ExpectedAuthenticatedEncryptedDataToDecryptBlindedPath');
  }

  if (!key || !isHexString(key)) {
    throw new Error('ExpectedHexEncodedPathKeyToDecryptBlindedPath');
  }

  if (byteLength(key) !== lengthPointBytes) {
    throw new Error('ExpectedCompressedPathKeyToDecryptBlindedPath');
  }

  if (!isPublicKey(key)) {
    throw new Error('ExpectedValidPathKeyToDecryptBlindedPath');
  }

  if (!secret || !isHexString(secret)) {
    throw new Error('ExpectedHexEncodedSharedSecretToDecryptBlindedPath');
  }

  if (byteLength(secret) !== lengthKeyBytes) {
    throw new Error('ExpectedSharedSecretByteLengthToDecryptBlindedPath');
  }

  const {data} = decryptHopData({
    encrypted: hexAsBuffer(encrypted),
    secret: hexAsBuffer(secret),
  });

  const {records} = decodeHopData({data});

  const channel = records.find(n => n.type === typeShortChannelId);
  const features = records.find(n => n.type === typeAllowedFeatures);

  if (!!channel && byteLength(channel.value) !== lengthShortChannelIdBytes) {
    throw new Error('ExpectedShortChannelIdInBlindedPathData');
  }

  const nextNodeId = records.find(n => n.type === typeNextNodeId);

  if (!!nextNodeId && byteLength(nextNodeId.value) !== lengthPointBytes) {
    throw new Error('ExpectedCompressedNextNodeIdInBlindedPathData');
  }

  if (!!nextNodeId && !isPublicKey(nextNodeId.value)) {
    throw new Error('ExpectedValidNextNodeIdInBlindedPathData');
  }

  const override = records.find(n => n.type === typeNextPathKeyOverride);

  if (!!override && byteLength(override.value) !== lengthPointBytes) {
    throw new Error('ExpectedCompressedNextPathKeyOverrideInBlindedPathData');
  }

  if (!!override && !isPublicKey(override.value)) {
    throw new Error('ExpectedValidNextPathKeyOverrideInBlindedPathData');
  }

  const pathId = records.find(n => n.type === typePathId);

  // Absent allowed features are treated as an empty list of feature bits
  const allowed = decodeFeatures({
    encoded: hexAsBuffer(!features ? String() : features.value),
  });

  // The short channel id of the next channel is formatted as a channel id
  const nextChannel = !channel ? null : chanFormat({id: channel.value});

  // The next path key is the path key times a hash of it and the secret
  const nextPathKey = from(pointMultiply(
    hexAsBuffer(key),
    sha256(concat([hexAsBuffer(key), hexAsBuffer(secret)])),
    true
  ));

  return {
    records,
    data: bufferAsHex(data),
    features: allowed.bits,
    id: !pathId ? undefined : pathId.value,
    next_channel_id: !nextChannel ? undefined : nextChannel.channel,
    next_node_id: !nextNodeId ? undefined : nextNodeId.value,
    next_path_key: !override ? bufferAsHex(nextPathKey) : override.value,
  };
};
