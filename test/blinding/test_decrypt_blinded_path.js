const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {chanFormat} = require('bolt07');
const {decodeTlvStream} = require('bolt01');

const blinded = require('./../fixtures/blinded_payment_onion.json');
const blinding = require('./../fixtures/route_blinding.json');
const {createBlindedPath} = require('./../../blinding');
const {decodeFeatures} = require('./../../blinding');
const {decryptBlindedPath} = require('./../../');
const message = require('./../fixtures/onion_message.json');
const {sharedSecret} = require('./../../keys');

const [bob] = blinding.paths[0].hops;
const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const isPublicKey = n => /^0[23][0-9a-f]{64}$/.test(n);
const paths = [].concat(message.paths).concat(blinding.paths);
const secret = Buffer.alloc(32, 1);

const hops = paths.flatMap(n => n.hops);

// A hop derives the shared secret with the path key using its private key
const pathSecret = ({path_key, private_key}) => {
  return bufferAsHex(sharedSecret({
    private_key: hexAsBuffer(private_key),
    public_key: hexAsBuffer(path_key),
  }).secret);
};

const paymentHops = blinded.hops.filter(n => !!n.encrypted_data).map(hop => {
  // The introduction point receives its path key in its onion payload
  return {...hop, path_key: hop.path_key || hop.current_path_key};
});

// Blind data for Bob to test decryption of specific data
const blind = data => {
  const path = createBlindedPath({
    hops: [{data: hexAsBuffer(data), public_key: hexAsBuffer(bob.public_key)}],
    secret,
  });

  const [hop] = path.hops;

  const pathKey = bufferAsHex(path.key);

  return {
    encrypted: bufferAsHex(hop.encrypted_data),
    key: pathKey,
    secret: pathSecret({path_key: pathKey, private_key: bob.private_key}),
  };
};

const tests = [
  {
    args: {key: bob.path_key, secret: pathSecret(bob)},
    description: 'Encrypted data is required',
    error: 'ExpectedHexEncodedEncryptedDataToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: 'data',
      key: bob.path_key,
      secret: pathSecret(bob),
    },
    description: 'Encrypted data must be hex encoded',
    error: 'ExpectedHexEncodedEncryptedDataToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: '00',
      key: bob.path_key,
      secret: pathSecret(bob),
    },
    description: 'Encrypted data must include an authentication tag',
    error: 'ExpectedAuthenticatedEncryptedDataToDecryptBlindedPath',
  },
  {
    args: {encrypted: bob.encrypted_data, secret: pathSecret(bob)},
    description: 'A path key is required',
    error: 'ExpectedHexEncodedPathKeyToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: bob.encrypted_data,
      key: '02',
      secret: pathSecret(bob),
    },
    description: 'A path key must be a compressed public key',
    error: 'ExpectedCompressedPathKeyToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: bob.encrypted_data,
      key: `02${'00'.repeat(32)}`,
      secret: pathSecret(bob),
    },
    description: 'A path key must be a valid public key',
    error: 'ExpectedValidPathKeyToDecryptBlindedPath',
  },
  {
    args: {encrypted: bob.encrypted_data, key: bob.path_key},
    description: 'A shared secret is required',
    error: 'ExpectedHexEncodedSharedSecretToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: bob.encrypted_data,
      key: bob.path_key,
      secret: 'secret',
    },
    description: 'A shared secret must be hex encoded',
    error: 'ExpectedHexEncodedSharedSecretToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: bob.encrypted_data,
      key: bob.path_key,
      secret: '01',
    },
    description: 'A shared secret must be a full length secret',
    error: 'ExpectedSharedSecretByteLengthToDecryptBlindedPath',
  },
  {
    args: {
      encrypted: bob.encrypted_data,
      key: bob.path_key,
      secret: pathSecret({
        path_key: bob.path_key,
        private_key: '43'.repeat(32),
      }),
    },
    description: 'Encrypted data must be encrypted to the shared secret',
    error: 'FailedToAuthenticateEncryptedDataToDecryptHopData',
  },
  {
    args: blind('ff'),
    description: 'Decrypted data must be a valid TLV stream',
    error: 'ExpectedValidTlvStreamToDecodeHopData',
  },
  {
    args: blind('080100080100'),
    description: 'Decrypted data must not have repeated record types',
    error: 'ExpectedOrderedTlvStreamToDecodeHopData',
  },
  {
    args: blind('04000100'),
    description: 'Decrypted data must have ascending record types',
    error: 'ExpectedOrderedTlvStreamToDecodeHopData',
  },
  {
    args: blind('080100'),
    description: 'A next path key override must be a compressed public key',
    error: 'ExpectedCompressedNextPathKeyOverrideInBlindedPathData',
  },
  {
    args: blind(`082102${'00'.repeat(32)}`),
    description: 'A next path key override must be a valid public key',
    error: 'ExpectedValidNextPathKeyOverrideInBlindedPathData',
  },
  {
    args: blind('020100'),
    description: 'A short channel id must be eight bytes',
    error: 'ExpectedShortChannelIdInBlindedPathData',
  },
  {
    args: blind('040100'),
    description: 'A next node id must be a compressed public key',
    error: 'ExpectedCompressedNextNodeIdInBlindedPathData',
  },
  {
    args: blind(`042102${'00'.repeat(32)}`),
    description: 'A next node id must be a valid public key',
    error: 'ExpectedValidNextNodeIdInBlindedPathData',
  },
  {
    args: blind('0100060412345678'),
    description: 'Decrypted data records are decoded',
    expected: {
      data: '0100060412345678',
      id: '12345678',
      records: [{type: '1', value: ''}, {type: '6', value: '12345678'}],
    },
  },
  {
    args: blind('02080ebd480008a700000e020200'),
    description: 'A next channel id and allowed features are decoded',
    expected: {
      features: [9],
      data: '02080ebd480008a700000e020200',
      next_channel_id: '965960x2215x0',
      records: [
        {type: '2', value: '0ebd480008a70000'},
        {type: '14', value: '0200'},
      ],
    },
  },
  {
    args: blind('0e00'),
    description: 'Empty allowed features allow no features',
    expected: {
      features: [],
      data: '0e00',
      records: [{type: '14', value: ''}],
    },
  },
  ...hops.map(hop => ({
    args: {
      encrypted: hop.encrypted_data,
      key: hop.path_key,
      secret: pathSecret(hop),
    },
    description: `Blinded data is decrypted by ${hop.alias}`,
    expected: {data: hop.data, next_path_key: hop.next_path_key},
  })),
  ...paymentHops.map(hop => ({
    args: {
      encrypted: hop.encrypted_data,
      key: hop.path_key,
      secret: pathSecret(hop),
    },
    description: `Blinded payment data is decrypted by ${hop.alias}`,
    expected: {next_path_key: hop.next_path_key},
  })),
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => decryptBlindedPath(args), new Error(error), 'Got error');

      return end();
    }

    const decrypted = decryptBlindedPath(args);

    // The blinded payment vector does not specify the decrypted data
    if (!!expected.data) {
      strictSame(decrypted.data, expected.data, 'Got expected decrypted data');
    }

    const {records} = decodeTlvStream({encoded: decrypted.data});

    // The decrypted data records are decoded from the decrypted data
    if (!!expected.records) {
      strictSame(decrypted.records, expected.records, 'Got expected records');
    } else {
      strictSame(
        decrypted.records,
        records.map(({type, value}) => ({type, value})),
        'Got decoded records'
      );
    }

    // A forwarding hop is given the next node id to forward to
    const nextNodeId = records.find(n => n.type === '4');

    strictSame(
      decrypted.next_node_id,
      !nextNodeId ? undefined : nextNodeId.value,
      'Got expected next node id'
    );

    // A forwarding hop may instead be given the next channel to forward over
    const channel = records.find(n => n.type === '2');

    strictSame(
      decrypted.next_channel_id,
      !channel ? undefined : chanFormat({id: channel.value}).channel,
      'Got expected next channel id'
    );

    if (!!expected.next_channel_id) {
      strictSame(decrypted.next_channel_id, expected.next_channel_id, 'Chan');
    }

    // A hop may be told which features are allowed to be used over the path
    const features = records.find(n => n.type === '14');

    strictSame(
      decrypted.features,
      decodeFeatures({
        encoded: Buffer.from(!features ? '' : features.value, 'hex'),
      }).bits,
      'Got expected allowed features'
    );

    if (!!expected.features) {
      strictSame(decrypted.features, expected.features, 'Bits');
    }

    // A final hop is given the path id of the path
    const pathId = records.find(n => n.type === '6');

    strictSame(
      decrypted.id,
      !pathId ? undefined : pathId.value,
      'Got expected path id'
    );

    if (!!expected.id) {
      strictSame(decrypted.id, expected.id, 'Got expected path id');
    }

    // The final hop next path key is not specified in the test vectors
    if (!expected.next_path_key) {
      strictSame(isPublicKey(decrypted.next_path_key), true, 'Got next key');

      return end();
    }

    strictSame(decrypted.next_path_key, expected.next_path_key, 'Next key');

    return end();
  });
});
