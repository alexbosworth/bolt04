const {createHash} = require('node:crypto');
const {createHmac} = require('node:crypto');
const {timingSafeEqual} = require('node:crypto');

const {isPoint} = require('tiny-secp256k1');
const {pointMultiply} = require('tiny-secp256k1');

const {cipherStream} = require('./../keys');
const decodePayloadLength = require('./decode_payload_length');
const {deriveKey} = require('./../keys');
const {hashAlgorithm} = require('./constants');
const {lengthHmacBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {lengthVersionBytes} = require('./constants');
const {lengthsHopPayloadsBytes} = require('./constants');
const {minPaymentPayloadByteLength} = require('./constants');
const {typeMuKey} = require('./constants');
const {typeRhoKey} = require('./constants');
const {version} = require('./constants');

const {alloc} = Buffer;
const {concat} = Buffer;
const {from} = Buffer;
const {isBuffer} = Buffer;
const isZero = buffer => buffer.equals(alloc(buffer.length));
const sha256 = data => createHash(hashAlgorithm).update(data).digest();
const slice = (buffer, start, bytes) => buffer.subarray(start, start + bytes);
const streamLengthMultiplier = 2;
const sum = numbers => numbers.reduce((total, n) => total + n, Number());
const xor = (a, b) => from(a.map((byte, i) => byte ^ b[i]));

/** Decode an onion packet by peeling off a single layer of the onion

  The payload for the hop is revealed, and when the hop is not the final hop,
  the onion packet to forward to the next hop is returned.

  The hop payloads are 1300 bytes, or 32768 bytes for a large onion message.

  The secret is the ECDH shared secret between the node private key and the
  ephemeral public key of the onion packet, which is the SHA256 hash of the
  compressed shared point. The ephemeral public key is derived from the onion
  packet and the path key when the onion was encoded to a blinded node key.

  Associated data is the payment hash for a payment onion and is absent for an
  onion message. A payment onion hop payload must be at least two bytes.

  {
    [data]: <Associated Data Buffer Object>
    onion: <Onion Packet Buffer Object>
    secret: <Ephemeral Key Shared Secret Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    [onion]: <Next Hop Onion Packet Buffer Object>
    payload: <Hop Payload TLV Stream Buffer Object>
  }
*/
module.exports = ({data, onion, secret}) => {
  if (!!data && !isBuffer(data)) {
    throw new Error('ExpectedDataBufferToDecodeOnionPacket');
  }

  if (!isBuffer(onion)) {
    throw new Error('ExpectedOnionPacketBufferToDecode');
  }

  const headersLength = sum([
    lengthVersionBytes,
    lengthPointBytes,
    lengthHmacBytes,
  ]);

  // Every hop truncates the payloads back to their size so the size is fixed
  if (!lengthsHopPayloadsBytes.includes(onion.length - headersLength)) {
    throw new Error('ExpectedStandardPayloadsSizeInOnionPacketToDecode');
  }

  if (!isBuffer(secret)) {
    throw new Error('ExpectedSharedSecretBufferToDecodeOnionPacket');
  }

  if (secret.length !== lengthKeyBytes) {
    throw new Error('ExpectedSharedSecretByteLengthToDecodeOnionPacket');
  }

  const associatedData = data || alloc(Number());

  if (onion[Number()] !== version) {
    throw new Error('UnsupportedOnionPacketVersionToDecode');
  }

  const ephemeral = slice(onion, lengthVersionBytes, lengthPointBytes);

  if (!isPoint(ephemeral)) {
    throw new Error('ExpectedValidEphemeralPublicKeyInOnionPacketToDecode');
  }

  const hmac = onion.subarray(onion.length - lengthHmacBytes);

  const payloads = onion.subarray(
    lengthVersionBytes + lengthPointBytes,
    onion.length - lengthHmacBytes
  );

  const size = payloads.length;

  // BOLT 04 names the key derived from the shared secret that authenticates
  // the packet "mu", the derivation is an HMAC of the shared secret keyed by it
  const {key: mu} = deriveKey({secret, type: typeMuKey});

  const expectedHmac = createHmac(hashAlgorithm, mu)
    .update(payloads)
    .update(associatedData)
    .digest();

  if (!timingSafeEqual(expectedHmac, hmac)) {
    throw new Error('FailedToAuthenticateOnionPacketToDecode');
  }

  // BOLT 04 names the key derived from the shared secret that obfuscates the
  // payloads "rho", the derivation is an HMAC of the shared secret keyed by it
  const {key: rho} = deriveKey({secret, type: typeRhoKey});

  // The payloads are padded with zero bytes before they are deobfuscated
  const {stream} = cipherStream({
    bytes: size * streamLengthMultiplier,
    key: rho,
  });

  const unwrapped = xor(concat([payloads, alloc(size)]), stream);

  // The hop payload is prefixed with its BigSize encoded byte length
  const prefix = decodePayloadLength({encoded: unwrapped});

  // Payment onion payload lengths of zero and one are reserved
  if (!!associatedData.length && prefix.number < minPaymentPayloadByteLength) {
    throw new Error('UnexpectedReservedPayloadLengthInOnionPacketToDecode');
  }

  const payloadStart = prefix.bytes;
  const payloadEnd = payloadStart + prefix.number;
  const payloadsEnd = payloadEnd + lengthHmacBytes;

  // The hop data must fit within the size of the payloads
  if (payloadsEnd > size) {
    throw new Error('UnexpectedHopPayloadLengthInOnionPacketToDecode');
  }

  const nextHmac = unwrapped.subarray(payloadEnd, payloadsEnd);
  const payload = unwrapped.subarray(payloadStart, payloadEnd);

  // Exit early when this is the final hop, as indicated by a zero HMAC
  if (isZero(nextHmac)) {
    return {payload};
  }

  // The ephemeral key is blinded for the next hop
  const nextEphemeral = pointMultiply(
    ephemeral,
    sha256(concat([ephemeral, secret])),
    true
  );

  const nextOnion = concat([
    from([version]),
    from(nextEphemeral),
    unwrapped.subarray(payloadsEnd, payloadsEnd + size),
    nextHmac,
  ]);

  return {onion: nextOnion, payload};
};
