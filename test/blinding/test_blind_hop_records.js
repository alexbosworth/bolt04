const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeTlvStream} = require('bolt01');

const {blindHopRecords} = require('./../../blinding');
const {decryptBlindedPath} = require('./../../');
const message = require('./../fixtures/onion_message.json');
const {sharedSecret} = require('./../../keys');

const [, recipientPath] = message.paths;
const [bob, carol] = recipientPath.hops;
const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const invalidPoint = `02${'00'.repeat(32)}`;
const isPublicKey = n => /^0[23][0-9a-f]{64}$/.test(n);
const typePadding = '1';
const uniq = arr => Array.from(new Set(arr));

const tests = [
  {
    args: {},
    description: 'Hops are required',
    error: 'ExpectedArrayOfHopsToBlindHopRecords',
  },
  {
    args: {hops: []},
    description: 'At least one hop is required',
    error: 'ExpectedArrayOfHopsToBlindHopRecords',
  },
  {
    args: {hops: [null]},
    description: 'A hop is required',
    error: 'ExpectedHexEncodedHopPublicKeyToBlindHopRecords',
  },
  {
    args: {hops: [{public_key: 'key', records: []}]},
    description: 'A hop public key must be hex encoded',
    error: 'ExpectedHexEncodedHopPublicKeyToBlindHopRecords',
  },
  {
    args: {hops: [{public_key: '02', records: []}]},
    description: 'A hop public key must be a compressed public key',
    error: 'ExpectedCompressedHopPublicKeyToBlindHopRecords',
  },
  {
    args: {hops: [{public_key: invalidPoint, records: []}]},
    description: 'A hop public key must be a valid public key',
    error: 'ExpectedValidHopPublicKeyToBlindHopRecords',
  },
  {
    args: {hops: [{public_key: bob.public_key}]},
    description: 'A hop must have records',
    error: 'ExpectedArrayOfRecordsForHopToBlindHopRecords',
  },
  {
    args: {
      hops: [
        {
          public_key: bob.public_key,
          records: [{type: '4', value: carol.public_key}],
        },
        {
          public_key: carol.public_key,
          records: [{type: '6', value: '00'}],
        },
      ],
    },
    description: 'Hop records are padded and blinded',
    expected: {private_keys: [bob.private_key, carol.private_key]},
  },
  {
    args: {hops: [{public_key: carol.public_key, records: []}]},
    description: 'A single hop with no records is blinded',
    expected: {private_keys: [carol.private_key]},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => blindHopRecords(args), new Error(error), 'Got error');

      return end();
    }

    const res = blindHopRecords(args);

    strictSame(Object.keys(res).sort(), ['key', 'path'], 'Got key and path');
    strictSame(isPublicKey(res.key), true, 'Got path key');
    strictSame(res.path.length, args.hops.length, 'Got a hop for every hop');

    // Padding gives every hop encrypted data of the same length
    strictSame(uniq(res.path.map(n => byteLength(n.encrypted_data))).length, 1);

    // Every hop decrypts its own records with the path key it receives
    expected.private_keys.reduce((pathKey, privateKey, i) => {
      strictSame(isPublicKey(res.path[i].relay_key), true, 'Got relay key');

      const {secret} = sharedSecret({
        private_key: hexAsBuffer(privateKey),
        public_key: hexAsBuffer(pathKey),
      });

      const decrypted = decryptBlindedPath({
        encrypted: res.path[i].encrypted_data,
        key: pathKey,
        secret: bufferAsHex(secret),
      });

      const {records} = decodeTlvStream({encoded: decrypted.data});

      strictSame(
        records
          .filter(n => n.type !== typePadding)
          .map(({type, value}) => ({type, value})),
        args.hops[i].records,
        'Got hop records'
      );

      return decrypted.next_path_key;
    }, res.key);

    return end();
  });
});
