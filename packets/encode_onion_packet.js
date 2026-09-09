const {createHmac} = require('node:crypto');

const {encodeBigSize} = require('bolt01');
const {isPoint} = require('tiny-secp256k1');
const {isPrivate} = require('tiny-secp256k1');
const {pointFromScalar} = require('tiny-secp256k1');

const {cipherStream} = require('./../keys');
const {deriveKey} = require('./../keys');
const generateFiller = require('./generate_filler');
const {hashAlgorithm} = require('./constants');
const hopSharedSecrets = require('./hop_shared_secrets');
const {lengthHmacBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {lengthsHopPayloadsBytes} = require('./constants');
const {minPaymentPayloadByteLength} = require('./constants');
const {randomPrivateKey} = require('./../keys');
const {typeMuKey} = require('./constants');
const {typePadKey} = require('./constants');
const {typeRhoKey} = require('./constants');
const {version} = require('./constants');

const {alloc} = Buffer;
const {concat} = Buffer;
const {from} = Buffer;
const hexAsBuffer = hex => from(hex, 'hex');
const {isArray} = Array;
const {isBuffer} = Buffer;
const isPaymentLength = n => n.length >= minPaymentPayloadByteLength;
const sum = numbers => numbers.reduce((total, n) => total + n, Number());
const xor = (a, b) => from(a.map((byte, i) => byte ^ b[i]));

/** Encode an onion packet

  Hop payloads are sized to 1300 bytes, or to 32768 bytes when they do not fit
  within 1300 bytes, as is permitted for onion messages.

  Associated data is the payment hash for a payment onion and is absent for an
  onion message. A payment onion hop payload must be at least two bytes.

  A random session key is generated when a session key is not specified.

  {
    [data]: <Associated Data Buffer Object>
    hops: [{
      payload: <Hop Payload TLV Stream Buffer Object>
      public_key: <Hop Public Key Buffer Object>
    }]
    [session_key]: <Ephemeral Session Private Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    onion: <Onion Packet Buffer Object>
  }
*/
module.exports = args => {
  if (!args) {
    throw new Error('ExpectedArgumentsToEncodeOnionPacket');
  }

  if (!!args.data && !isBuffer(args.data)) {
    throw new Error('ExpectedDataBufferToEncodeOnionPacket');
  }

  if (!isArray(args.hops) || !args.hops.length) {
    throw new Error('ExpectedArrayOfHopsToEncodeOnionPacket');
  }

  if (!args.hops.every(n => !!n && isBuffer(n.payload))) {
    throw new Error('ExpectedPayloadBufferForHopToEncodeOnionPacket');
  }

  if (!args.hops.every(n => isBuffer(n.public_key))) {
    throw new Error('ExpectedPublicKeyBufferForHopToEncodeOnionPacket');
  }

  if (!args.hops.every(n => n.public_key.length === lengthPointBytes)) {
    throw new Error('ExpectedCompressedPublicKeyForHopToEncodeOnionPacket');
  }

  if (!args.hops.every(n => isPoint(n.public_key))) {
    throw new Error('ExpectedValidPublicKeyForHopToEncodeOnionPacket');
  }

  // Payment onion payload lengths of zero and one are reserved
  if (!!args.data && !args.hops.every(n => isPaymentLength(n.payload))) {
    throw new Error('ExpectedLongerPayloadForHopToEncodeOnionPacket');
  }

  if (!!args.session_key && !isBuffer(args.session_key)) {
    throw new Error('ExpectedSessionKeyBufferToEncodeOnionPacket');
  }

  if (!!args.session_key && args.session_key.length !== lengthKeyBytes) {
    throw new Error('ExpectedSessionPrivateKeyToEncodeOnionPacket');
  }

  if (!!args.session_key && !isPrivate(args.session_key)) {
    throw new Error('ExpectedValidSessionKeyToEncodeOnionPacket');
  }

  const sessionKey = args.session_key || randomPrivateKey({}).key;

  const associatedData = args.data || alloc(Number());

  const {secrets} = hopSharedSecrets({
    public_keys: args.hops.map(n => n.public_key),
    session_key: sessionKey,
  });

  // The hop data is the bigsize encoded payload length, payload, and an HMAC
  const hops = args.hops.map(({payload}) => {
    const {encoded} = encodeBigSize({number: payload.length.toString()});

    return {payload, prefix: hexAsBuffer(encoded)};
  });

  const lengths = hops.map(hop => {
    return hop.prefix.length + hop.payload.length + lengthHmacBytes;
  });

  // The payloads size is the smallest allowed size that fits all the hop data
  const size = lengthsHopPayloadsBytes.find(n => sum(lengths) <= n);

  if (!size) {
    throw new Error('ExpectedHopPayloadsToFitWithinMaximumOnionPacketSize');
  }

  const {filler} = generateFiller({lengths, secrets, size});

  const {key} = deriveKey({secret: sessionKey, type: typePadKey});

  // The payloads start off as pseudo random bytes derived from the session key
  const packet = {
    hmac: alloc(lengthHmacBytes),
    payloads: cipherStream({key, bytes: size}).stream,
  };

  // The layers are constructed in reverse, from the final hop to the first hop
  [...hops].reverse().forEach((hop, i) => {
    const index = hops.length - i - 1;

    const {key: mu} = deriveKey({secret: secrets[index], type: typeMuKey});
    const {key: rho} = deriveKey({secret: secrets[index], type: typeRhoKey});

    // Shift the payloads right to insert the hop data, dropping the excess
    const shifted = concat([
      hop.prefix,
      hop.payload,
      packet.hmac,
      packet.payloads,
    ]);

    const {stream} = cipherStream({key: rho, bytes: size});

    packet.payloads = xor(shifted.subarray(Number(), size), stream);

    // The final hop payloads end with the filler that the forwarding hops add
    if (index === hops.length - 1) {
      filler.copy(packet.payloads, size - filler.length);
    }

    const hmac = createHmac(hashAlgorithm, mu);

    packet.hmac = hmac.update(packet.payloads).update(associatedData).digest();
  });

  const ephemeralPublicKey = pointFromScalar(sessionKey, true);

  const onion = concat([
    from([version]),
    from(ephemeralPublicKey),
    packet.payloads,
    packet.hmac,
  ]);

  return {onion};
};
