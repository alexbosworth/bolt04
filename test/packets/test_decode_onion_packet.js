const {createHmac} = require('node:crypto');
const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {pointFromScalar} = require('tiny-secp256k1');

const blinded = require('./../fixtures/blinded_payment_onion.json');
const {cipherStream} = require('./../../keys');
const {decodeOnionPacket} = require('./../../packets');
const {deriveEphemeralKey} = require('./../../packets');
const {deriveKey} = require('./../../keys');
const message = require('./../fixtures/onion_message.json');
const payment = require('./../fixtures/payment_onion.json');
const {sharedSecret} = require('./../../keys');

const [alice] = payment.hops;
const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const messageHops = message.paths.flatMap(path => path.hops);
const nodeKey = Buffer.alloc(32, 0x42);
const publicKey = n => Buffer.from(pointFromScalar(n, true));
const sessionKey = Buffer.alloc(32, 0x41);
const xor = (a, b) => Buffer.from(a.map((byte, i) => byte ^ b[i]));

const blindedData = hexAsBuffer(blinded.associated_data);
const paymentData = hexAsBuffer(payment.associated_data);
const paymentOnion = hexAsBuffer(payment.onion);

// A decoded layer is compared to the test vector as hex
const asHex = decoded => ({
  ...(!decoded.onion ? {} : {onion: bufferAsHex(decoded.onion)}),
  payload: bufferAsHex(decoded.payload),
});

// Craft a single hop onion packet with a valid HMAC around plaintext payloads
const craft = ({data, plaintext}) => {
  const payloads = Buffer.alloc(1300);

  hexAsBuffer(plaintext).copy(payloads);

  const {secret} = sharedSecret({
    private_key: sessionKey,
    public_key: publicKey(nodeKey),
  });

  const {key: mu} = deriveKey({secret, type: 'mu'});
  const {key: rho} = deriveKey({secret, type: 'rho'});

  const {stream} = cipherStream({key: rho, bytes: payloads.length});

  const obfuscated = xor(payloads, stream);

  const hmac = createHmac('sha256', mu)
    .update(obfuscated)
    .update(data || Buffer.alloc(0));

  return Buffer.concat([
    Buffer.from([0]),
    publicKey(sessionKey),
    obfuscated,
    hmac.digest(),
  ]);
};

// The node derives the crafted onion shared secret with the session public key
const craftedSecret = sharedSecret({
  private_key: nodeKey,
  public_key: publicKey(sessionKey),
}).secret;

// Derive the shared secret for a hop to decode an onion with its private key
const hopSecret = ({onion, path_key, private_key}) => {
  const privateKey = hexAsBuffer(private_key);

  // A hop that has a path key tweaks the ephemeral key with the path key secret
  const path = !path_key ? {} : sharedSecret({
    private_key: privateKey,
    public_key: hexAsBuffer(path_key),
  });

  const {public_key} = deriveEphemeralKey({onion, secret: path.secret});

  return sharedSecret({private_key: privateKey, public_key}).secret;
};

const tests = [
  {
    args: {
      data: payment.associated_data,
      onion: paymentOnion,
      secret: craftedSecret,
    },
    description: 'Associated data must be a buffer',
    error: 'ExpectedDataBufferToDecodeOnionPacket',
  },
  {
    args: {secret: craftedSecret},
    description: 'An onion packet is required',
    error: 'ExpectedOnionPacketBufferToDecode',
  },
  {
    args: {onion: payment.onion, secret: craftedSecret},
    description: 'An onion packet must be a buffer',
    error: 'ExpectedOnionPacketBufferToDecode',
  },
  {
    args: {onion: Buffer.alloc(66), secret: craftedSecret},
    description: 'An onion packet must have payloads',
    error: 'ExpectedStandardPayloadsSizeInOnionPacketToDecode',
  },
  {
    args: {onion: Buffer.alloc(1367), secret: craftedSecret},
    description: 'An onion packet must have a standard payloads size',
    error: 'ExpectedStandardPayloadsSizeInOnionPacketToDecode',
  },
  {
    args: {onion: paymentOnion},
    description: 'A shared secret is required',
    error: 'ExpectedSharedSecretBufferToDecodeOnionPacket',
  },
  {
    args: {onion: paymentOnion, secret: alice.shared_secret},
    description: 'A shared secret must be a buffer',
    error: 'ExpectedSharedSecretBufferToDecodeOnionPacket',
  },
  {
    args: {onion: paymentOnion, secret: Buffer.alloc(1, 1)},
    description: 'A shared secret must be a full length secret',
    error: 'ExpectedSharedSecretByteLengthToDecodeOnionPacket',
  },
  {
    args: {
      onion: hexAsBuffer(`01${payment.onion.slice(2)}`),
      secret: craftedSecret,
    },
    description: 'An onion packet must be a known version',
    error: 'UnsupportedOnionPacketVersionToDecode',
  },
  {
    args: {
      onion: hexAsBuffer(`0002${'00'.repeat(32)}${payment.onion.slice(68)}`),
      secret: craftedSecret,
    },
    description: 'An onion packet must have a valid ephemeral public key',
    error: 'ExpectedValidEphemeralPublicKeyInOnionPacketToDecode',
  },
  {
    args: {data: paymentData, onion: paymentOnion, secret: craftedSecret},
    description: 'An onion packet must have been encoded to the shared secret',
    error: 'FailedToAuthenticateOnionPacketToDecode',
  },
  {
    args: {onion: paymentOnion, secret: hexAsBuffer(alice.shared_secret)},
    description: 'Associated data must match the encoded associated data',
    error: 'FailedToAuthenticateOnionPacketToDecode',
  },
  {
    args: {onion: craft({plaintext: 'fd0001'}), secret: craftedSecret},
    description: 'A payload length must be a valid bigsize number',
    error: 'ExpectedValidBigSizePrefixToDecodePayloadLength',
  },
  {
    args: {onion: craft({plaintext: 'fd05dc'}), secret: craftedSecret},
    description: 'A payload must fit within the payloads',
    error: 'UnexpectedHopPayloadLengthInOnionPacketToDecode',
  },
  {
    args: {onion: craft({plaintext: 'fd04f2'}), secret: craftedSecret},
    description: 'A payload and its HMAC must fit within the payloads',
    error: 'UnexpectedHopPayloadLengthInOnionPacketToDecode',
  },
  {
    args: {
      data: paymentData,
      onion: craft({data: paymentData, plaintext: '00'}),
      secret: craftedSecret,
    },
    description: 'A payment onion payload length must not be reserved',
    error: 'UnexpectedReservedPayloadLengthInOnionPacketToDecode',
  },
  {
    args: {onion: craft({plaintext: '00'}), secret: craftedSecret},
    description: 'An onion message payload may be empty',
    expected: {payload: ''},
  },
  {
    args: {onion: craft({plaintext: 'fd04f1'}), secret: craftedSecret},
    description: 'A payload may exactly fill the payloads',
    expected: {payload: '00'.repeat(1300 - 3 - 32)},
  },
  {
    args: {
      data: paymentData,
      hops: payment.hops.map(n => ({secret: hexAsBuffer(n.shared_secret)})),
      onion: paymentOnion,
    },
    description: 'A payment onion packet is peeled by every hop',
    expected: {payloads: payment.hops.map(n => n.payload)},
  },
  {
    args: {
      data: paymentData,
      hops: payment.hops.map(n => ({private_key: n.private_key})),
      onion: paymentOnion,
    },
    description: 'A payment onion hop derives its shared secret from its onion',
    expected: {payloads: payment.hops.map(n => n.payload)},
  },
  ...messageHops.map((hop, i) => ({
    args: {
      onion: hexAsBuffer(hop.onion),
      secret: hopSecret({...hop, onion: hexAsBuffer(hop.onion)}),
    },
    description: `An onion message packet is decoded by ${hop.alias}`,
    expected: {
      ...(!!messageHops[i + 1] ? {onion: messageHops[i + 1].onion} : {}),
      payload: hop.payload,
    },
  })),
  ...blinded.hops.map((hop, i) => ({
    args: {
      data: blindedData,
      onion: hexAsBuffer(hop.onion),
      secret: hopSecret({...hop, onion: hexAsBuffer(hop.onion)}),
    },
    description: `A blinded payment onion packet is decoded by ${hop.alias}`,
    expected: {
      ...(!!blinded.hops[i + 1] ? {onion: blinded.hops[i + 1].onion} : {}),
      payload: hop.payload,
    },
  })),
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decodeOnionPacket(args), new Error(error), 'Got error');

      return end();
    }

    // Exit early when a single layer is being decoded
    if (!args.hops) {
      strictSame(asHex(decodeOnionPacket(args)), expected, 'Got decoded');

      return end();
    }

    // Every hop peels a layer off of the onion to find its payload
    const peeled = args.hops.reduce((packet, hop, i) => {
      // A hop without a known shared secret derives it with its private key
      const secret = hop.secret || hopSecret({
        onion: packet.onion,
        private_key: hop.private_key,
      });

      const decoded = decodeOnionPacket({
        data: args.data,
        onion: packet.onion,
        secret,
      });

      strictSame(bufferAsHex(decoded.payload), expected.payloads[i], 'Payload');

      return decoded;
    }, {onion: args.onion});

    strictSame(peeled.onion, undefined, 'The final hop has no next onion');

    return end();
  });
});
