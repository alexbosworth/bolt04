const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {cipherStream} = require('./../../keys');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

// The stream for a zero key and nonce is the ChaCha20 RFC 8439 test vector
const zeroKeyStream = [
  '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7',
  'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586',
];

const tests = [
  {
    args: {bytes: 64},
    description: 'A key is required',
    error: 'ExpectedKeyToGenerateCipherStream',
  },
  {
    args: {key: Buffer.alloc(1), bytes: 64},
    description: 'A full length key is required',
    error: 'ExpectedKeyToGenerateCipherStream',
  },
  {
    args: {key: '00'.repeat(32), bytes: 64},
    description: 'A buffer key is required',
    error: 'ExpectedKeyToGenerateCipherStream',
  },
  {
    args: {key: Buffer.alloc(32)},
    description: 'A byte length is required',
    error: 'ExpectedStreamLengthToGenerateCipherStream',
  },
  {
    args: {key: Buffer.alloc(32), bytes: 64},
    description: 'A pseudo random stream is generated',
    expected: {stream: hexAsBuffer(zeroKeyStream.join(''))},
  },
  {
    args: {key: Buffer.alloc(32), bytes: 8},
    description: 'A pseudo random stream is generated to a byte length',
    expected: {stream: hexAsBuffer(zeroKeyStream.join('').slice(0, 16))},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => cipherStream(args), new Error(error), 'Got expected error');

      return end();
    }

    strictSame(cipherStream(args), expected, 'Got expected stream');

    return end();
  });
});
