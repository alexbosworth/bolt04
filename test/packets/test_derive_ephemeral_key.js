const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const blinded = require('./../fixtures/blinded_payment_onion.json');
const {deriveEphemeralKey} = require('./../../packets');
const hopSharedSecrets = require('./../../packets/hop_shared_secrets');
const message = require('./../fixtures/onion_message.json');
const payment = require('./../fixtures/payment_onion.json');
const {sharedSecret} = require('./../../keys');

const [alice] = payment.hops;
const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const messageHops = message.paths.flatMap(path => path.hops);

const invalidEphemeral = `0002${'00'.repeat(32)}${payment.onion.slice(68)}`;
const paymentOnion = hexAsBuffer(payment.onion);

// A hop derives the shared secret with the path key using its private key
const pathSecret = ({path_key, private_key}) => {
  return sharedSecret({
    private_key: hexAsBuffer(private_key),
    public_key: hexAsBuffer(path_key),
  }).secret;
};

// The sender derives a shared secret for every hop key the onion is encoded to
const blindedSecrets = hopSharedSecrets({
  public_keys: blinded.hops.map(n => hexAsBuffer(n.public_key)),
  session_key: hexAsBuffer(blinded.session_key),
}).secrets;

const messageSecrets = hopSharedSecrets({
  public_keys: messageHops.map(n => hexAsBuffer(n.blinded_public_key)),
  session_key: hexAsBuffer(message.session_key),
}).secrets;

const tests = [
  {
    args: {},
    description: 'An onion packet is required',
    error: 'ExpectedOnionPacketBufferToDeriveEphemeralKey',
  },
  {
    args: {onion: payment.onion},
    description: 'An onion packet must be a buffer',
    error: 'ExpectedOnionPacketBufferToDeriveEphemeralKey',
  },
  {
    args: {onion: Buffer.alloc(66)},
    description: 'An onion packet must have payloads',
    error: 'ExpectedStandardPayloadsSizeToDeriveEphemeralKey',
  },
  {
    args: {onion: Buffer.alloc(1367)},
    description: 'An onion packet must have a standard payloads size',
    error: 'ExpectedStandardPayloadsSizeToDeriveEphemeralKey',
  },
  {
    args: {onion: paymentOnion, secret: alice.shared_secret},
    description: 'A path key secret must be a buffer',
    error: 'ExpectedPathKeySecretBufferToDeriveEphemeralKey',
  },
  {
    args: {onion: paymentOnion, secret: Buffer.alloc(1, 1)},
    description: 'A path key secret must be a full length secret',
    error: 'ExpectedPathKeySecretByteLengthToDeriveEphemeralKey',
  },
  {
    args: {onion: hexAsBuffer(`01${payment.onion.slice(2)}`)},
    description: 'An onion packet must be a known version',
    error: 'UnsupportedOnionPacketVersionToDeriveEphemeralKey',
  },
  {
    args: {onion: hexAsBuffer(invalidEphemeral)},
    description: 'An onion packet must have a valid ephemeral public key',
    error: 'ExpectedValidEphemeralPublicKeyToDeriveEphemeralKey',
  },
  {
    args: {onion: paymentOnion},
    description: 'A payment onion ephemeral key is the onion packet public key',
    expected: {
      private_key: alice.private_key,
      public_key: payment.onion.slice(2, 68),
      secret: alice.shared_secret,
    },
  },
  ...blinded.hops.map((hop, i) => ({
    args: {
      onion: hexAsBuffer(hop.onion),
      ...(!!hop.path_key ? {secret: pathSecret(hop)} : {}),
    },
    description: `A blinded payment ephemeral key is derived by ${hop.alias}`,
    expected: {
      private_key: hop.private_key,
      secret: bufferAsHex(blindedSecrets[i]),
    },
  })),
  ...messageHops.map((hop, i) => ({
    args: {onion: hexAsBuffer(hop.onion), secret: pathSecret(hop)},
    description: `An onion message ephemeral key is derived by ${hop.alias}`,
    expected: {
      private_key: hop.private_key,
      secret: bufferAsHex(messageSecrets[i]),
    },
  })),
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => deriveEphemeralKey(args), new Error(error), 'Got error');

      return end();
    }

    const {public_key} = deriveEphemeralKey(args);

    // An onion that is not encoded to a blinded key uses the packet public key
    if (!!expected.public_key) {
      strictSame(bufferAsHex(public_key), expected.public_key, 'Got key');
    }

    // The shared secret with the ephemeral key matches the sender's secret
    const {secret} = sharedSecret({
      private_key: hexAsBuffer(expected.private_key),
      public_key,
    });

    strictSame(bufferAsHex(secret), expected.secret, 'Got expected secret');

    return end();
  });
});
