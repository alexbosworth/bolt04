const {isPoint} = require('tiny-secp256k1');
const {pointMultiply} = require('tiny-secp256k1');

const {deriveKey} = require('./../keys');
const {lengthHmacBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {lengthVersionBytes} = require('./constants');
const {lengthsHopPayloadsBytes} = require('./constants');
const {typeBlindedNodeIdKey} = require('./constants');
const {version} = require('./constants');

const {from} = Buffer;
const {isBuffer} = Buffer;
const slice = (buffer, start, bytes) => buffer.subarray(start, start + bytes);
const sum = numbers => numbers.reduce((total, n) => total + n, Number());

/** Derive the ephemeral public key to perform ECDH with to decode an onion

  The shared secret between the node private key and the ephemeral public key
  is the secret that is used to decode a layer of the onion packet.

  When the onion was encoded to a blinded node key, the shared secret with the
  path key is required to tweak the ephemeral key with the blinded node id
  tweak, which is equivalent to tweaking the node private key.

  {
    onion: <Onion Packet Buffer Object>
    [secret]: <Path Key Shared Secret Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    public_key: <Ephemeral Public Key Buffer Object>
  }
*/
module.exports = ({onion, secret}) => {
  if (!isBuffer(onion)) {
    throw new Error('ExpectedOnionPacketBufferToDeriveEphemeralKey');
  }

  const headersLength = sum([
    lengthVersionBytes,
    lengthPointBytes,
    lengthHmacBytes,
  ]);

  if (!lengthsHopPayloadsBytes.includes(onion.length - headersLength)) {
    throw new Error('ExpectedStandardPayloadsSizeToDeriveEphemeralKey');
  }

  if (!!secret && !isBuffer(secret)) {
    throw new Error('ExpectedPathKeySecretBufferToDeriveEphemeralKey');
  }

  if (!!secret && secret.length !== lengthKeyBytes) {
    throw new Error('ExpectedPathKeySecretByteLengthToDeriveEphemeralKey');
  }

  if (onion[Number()] !== version) {
    throw new Error('UnsupportedOnionPacketVersionToDeriveEphemeralKey');
  }

  const ephemeral = slice(onion, lengthVersionBytes, lengthPointBytes);

  if (!isPoint(ephemeral)) {
    throw new Error('ExpectedValidEphemeralPublicKeyToDeriveEphemeralKey');
  }

  // Without a path key the onion was encoded directly to the node key
  if (!secret) {
    return {public_key: ephemeral};
  }

  const {key} = deriveKey({secret, type: typeBlindedNodeIdKey});

  // Tweaking the ephemeral key is equivalent to tweaking the private key
  const tweaked = pointMultiply(ephemeral, key, true);

  return {public_key: from(tweaked)};
};
