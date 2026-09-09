const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const blinded = require('./../fixtures/blinded_payment_onion.json');
const {decodeOnionPacket} = require('./../../packets');
const {deriveEphemeralKey} = require('./../../packets');
const {encodeOnionPacket} = require('./../../packets');
const message = require('./../fixtures/onion_message.json');
const payment = require('./../fixtures/payment_onion.json');
const {sharedSecret} = require('./../../keys');

const bufferAsHex = buffer => buffer.toString('hex');
const [firstHop] = payment.hops;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const largePacketLength = 1 + 33 + 32768 + 32;
const largePayloadLength = 32768 - 3 - 32;
const messageHops = message.paths.flatMap(path => path.hops);
const smallPacketLength = 1 + 33 + 1300 + 32;
const smallPayloadLength = 1300 - 3 - 32;

// Hops in the test vectors are given as hex
const asHop = ({payload, public_key}) => {
  return {payload: hexAsBuffer(payload), public_key: hexAsBuffer(public_key)};
};

const firstKey = hexAsBuffer(firstHop.public_key);
const paymentData = hexAsBuffer(payment.associated_data);
const paymentHops = payment.hops.map(asHop);
const paymentSessionKey = hexAsBuffer(payment.session_key);

const tests = [
  {
    args: undefined,
    description: 'Arguments are required',
    error: 'ExpectedArgumentsToEncodeOnionPacket',
  },
  {
    args: {data: payment.associated_data, hops: paymentHops},
    description: 'Associated data must be a buffer',
    error: 'ExpectedDataBufferToEncodeOnionPacket',
  },
  {
    args: {},
    description: 'Hops are required',
    error: 'ExpectedArrayOfHopsToEncodeOnionPacket',
  },
  {
    args: {hops: []},
    description: 'At least one hop is required',
    error: 'ExpectedArrayOfHopsToEncodeOnionPacket',
  },
  {
    args: {hops: [{public_key: firstKey}]},
    description: 'A hop payload is required',
    error: 'ExpectedPayloadBufferForHopToEncodeOnionPacket',
  },
  {
    args: {hops: [{payload: '00', public_key: firstKey}]},
    description: 'A hop payload must be a buffer',
    error: 'ExpectedPayloadBufferForHopToEncodeOnionPacket',
  },
  {
    args: {hops: [{payload: Buffer.alloc(1)}]},
    description: 'A hop public key is required',
    error: 'ExpectedPublicKeyBufferForHopToEncodeOnionPacket',
  },
  {
    args: {hops: [{payload: Buffer.alloc(1), public_key: firstHop.public_key}]},
    description: 'A hop public key must be a buffer',
    error: 'ExpectedPublicKeyBufferForHopToEncodeOnionPacket',
  },
  {
    args: {hops: [{payload: Buffer.alloc(1), public_key: Buffer.alloc(1, 2)}]},
    description: 'A hop public key must be a compressed public key',
    error: 'ExpectedCompressedPublicKeyForHopToEncodeOnionPacket',
  },
  {
    args: {
      hops: [{
        payload: Buffer.alloc(1),
        public_key: hexAsBuffer(`02${'00'.repeat(32)}`),
      }],
    },
    description: 'A hop public key must be a valid public key',
    error: 'ExpectedValidPublicKeyForHopToEncodeOnionPacket',
  },
  {
    args: {
      data: paymentData,
      hops: [{payload: Buffer.alloc(1), public_key: firstKey}],
    },
    description: 'A payment onion payload must be at least two bytes',
    error: 'ExpectedLongerPayloadForHopToEncodeOnionPacket',
  },
  {
    args: {hops: paymentHops, session_key: payment.session_key},
    description: 'A session key must be a buffer',
    error: 'ExpectedSessionKeyBufferToEncodeOnionPacket',
  },
  {
    args: {hops: paymentHops, session_key: Buffer.alloc(1, 1)},
    description: 'A session key must be a full length private key',
    error: 'ExpectedSessionPrivateKeyToEncodeOnionPacket',
  },
  {
    args: {hops: paymentHops, session_key: Buffer.alloc(32)},
    description: 'A session key must be a valid private key',
    error: 'ExpectedValidSessionKeyToEncodeOnionPacket',
  },
  {
    args: {
      hops: [{payload: Buffer.alloc(32768), public_key: firstKey}],
      session_key: paymentSessionKey,
    },
    description: 'Hop payloads must fit within the maximum packet size',
    error: 'ExpectedHopPayloadsToFitWithinMaximumOnionPacketSize',
  },
  {
    args: {
      data: paymentData,
      hops: paymentHops,
      session_key: paymentSessionKey,
    },
    description: 'A payment onion packet is encoded',
    expected: {onion: payment.onion},
  },
  {
    args: {
      hops: messageHops.map(hop => ({
        payload: hexAsBuffer(hop.payload),
        public_key: hexAsBuffer(hop.blinded_public_key),
      })),
      session_key: hexAsBuffer(message.session_key),
    },
    description: 'An onion message packet is encoded to blinded node keys',
    expected: {onion: message.onion},
  },
  {
    args: {
      data: hexAsBuffer(blinded.associated_data),
      hops: blinded.hops.map(asHop),
      session_key: hexAsBuffer(blinded.session_key),
    },
    description: 'A payment onion packet is encoded to a blinded path',
    expected: {onion: blinded.onion},
  },
  {
    args: {hops: paymentHops, session_key: paymentSessionKey},
    description: 'An onion packet is encoded without associated data',
    expected: {length: smallPacketLength, payloads: payment.hops},
  },
  {
    args: {hops: [{payload: Buffer.alloc(0), public_key: firstKey}]},
    description: 'An onion message packet is encoded with an empty payload',
    expected: {
      length: smallPacketLength,
      payloads: [{payload: '', private_key: firstHop.private_key}],
    },
  },
  {
    args: {
      hops: [{
        payload: Buffer.alloc(smallPayloadLength, 1),
        public_key: firstKey,
      }],
    },
    description: 'An onion packet is encoded with exactly fitting payloads',
    expected: {
      length: smallPacketLength,
      payloads: [{
        payload: '01'.repeat(smallPayloadLength),
        private_key: firstHop.private_key,
      }],
    },
  },
  {
    args: {
      hops: [{
        payload: Buffer.alloc(smallPayloadLength + 1, 1),
        public_key: firstKey,
      }],
    },
    description: 'A large onion packet is encoded when payloads do not fit',
    expected: {
      length: largePacketLength,
      payloads: [{
        payload: '01'.repeat(smallPayloadLength + 1),
        private_key: firstHop.private_key,
      }],
    },
  },
  {
    args: {
      hops: [{
        payload: Buffer.alloc(largePayloadLength, 1),
        public_key: firstKey,
      }],
    },
    description: 'A large onion packet is encoded with exactly fitting data',
    expected: {
      length: largePacketLength,
      payloads: [{
        payload: '01'.repeat(largePayloadLength),
        private_key: firstHop.private_key,
      }],
    },
  },
  {
    args: {hops: paymentHops},
    description: 'An onion packet is encoded with a random session key',
    expected: {length: smallPacketLength, payloads: payment.hops},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => encodeOnionPacket(args), new Error(error), 'Got error');

      return end();
    }

    const {onion} = encodeOnionPacket(args);

    if (!!expected.onion) {
      strictSame(bufferAsHex(onion), expected.onion, 'Got expected onion');

      return end();
    }

    strictSame(onion.length, expected.length, 'Got expected packet size');

    // Every hop peels a layer off of the onion to find its payload
    const peeled = expected.payloads.reduce((packet, hop) => {
      // The hop derives the shared secret with the ephemeral key of the onion
      const {public_key} = deriveEphemeralKey({onion: packet.onion});

      const decoded = decodeOnionPacket({
        data: args.data,
        onion: packet.onion,
        secret: sharedSecret({
          private_key: hexAsBuffer(hop.private_key),
          public_key,
        }).secret,
      });

      strictSame(bufferAsHex(decoded.payload), hop.payload, 'Got payload');

      return decoded;
    }, {onion});

    strictSame(peeled.onion, undefined, 'The final hop has no next onion');

    return end();
  });
});
