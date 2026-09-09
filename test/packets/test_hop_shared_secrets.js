const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const hopSharedSecrets = require('./../../packets/hop_shared_secrets');
const payment = require('./../fixtures/payment_onion.json');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const publicKeys = payment.hops.map(n => hexAsBuffer(n.public_key));
const sessionKey = hexAsBuffer(payment.session_key);

const tests = [
  {
    args: {session_key: sessionKey},
    description: 'Hop public keys are required',
    error: 'ExpectedHopPublicKeysToDeriveHopSharedSecrets',
  },
  {
    args: {public_keys: [], session_key: sessionKey},
    description: 'At least one hop public key is required',
    error: 'ExpectedHopPublicKeysToDeriveHopSharedSecrets',
  },
  {
    args: {public_keys: publicKeys},
    description: 'A session key is required',
    error: 'ExpectedValidSessionKeyToDeriveHopSharedSecrets',
  },
  {
    args: {public_keys: publicKeys, session_key: payment.session_key},
    description: 'A buffer session key is required',
    error: 'ExpectedValidSessionKeyToDeriveHopSharedSecrets',
  },
  {
    args: {public_keys: publicKeys, session_key: Buffer.alloc(32)},
    description: 'A valid session key is required',
    error: 'ExpectedValidSessionKeyToDeriveHopSharedSecrets',
  },
  {
    args: {public_keys: publicKeys, session_key: sessionKey},
    description: 'Shared secrets are derived for every hop',
    expected: {secrets: payment.hops.map(n => hexAsBuffer(n.shared_secret))},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => hopSharedSecrets(args), new Error(error), 'Got error');

      return end();
    }

    strictSame(hopSharedSecrets(args), expected, 'Got expected secrets');

    return end();
  });
});
