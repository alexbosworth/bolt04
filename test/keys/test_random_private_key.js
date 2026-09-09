const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');

const {isPrivate} = require('tiny-secp256k1');

const {randomPrivateKey} = require('./../../keys');

const isKey = n => Buffer.isBuffer(n) && n.length === 32 && isPrivate(n);

const tests = [
  {
    args: {},
    description: 'A random private key is generated',
  },
];

tests.forEach(({args, description}) => {
  return test(description, (t, end) => {
    const first = randomPrivateKey(args);
    const second = randomPrivateKey(args);

    strictSame(isKey(first.key), true, 'Got a valid private key');
    strictSame(isKey(second.key), true, 'Got another private key');
    strictSame(first.key.equals(second.key), false, 'Got different keys');

    return end();
  });
});
