const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decodeTlvStream} = require('bolt01');
const {pointFromScalar} = require('tiny-secp256k1');

const {blindedPathFromHops} = require('./../../');
const {decodeBlindedPath} = require('./../../blinding');
const {decodeOnionPacket} = require('./../../packets');
const {decryptBlindedPath} = require('./../../');
const {deriveEphemeralKey} = require('./../../packets');
const message = require('./../fixtures/onion_message.json');
const {onionForPath} = require('./../../');
const {sharedSecret} = require('./../../keys');

const [senderPath, recipientPath] = message.paths;
const [alice] = senderPath.hops;
const [bob, carol, dave] = recipientPath.hops;
const bufferAsHex = buffer => buffer.toString('hex');
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const invalidPoint = `02${'00'.repeat(32)}`;
const isPathId = n => /^[0-9a-f]{64}$/.test(n);
const isPublicKey = n => /^0[23][0-9a-f]{64}$/.test(n);
const publicKey = n => Buffer.from(pointFromScalar(hexAsBuffer(n), true));

// The recipient put a path id in the data of the final hop of its path
const daveData = decodeTlvStream({encoded: dave.data}).records;
const pathId = daveData.find(n => n.type === '6').value;

// A relaying node that is not in the test vectors
const relay = {private_key: '45'.repeat(32)};

relay.public_key = bufferAsHex(publicKey(relay.private_key));

// A published path with hop data that is longer than relaying hop data
const long = blindedPathFromHops({
  hops: [bob.public_key, carol.public_key, dave.public_key],
  id: '01'.repeat(100),
});

const inbound = recipientPath.hops.map(hop => ({
  encrypted_data: hop.encrypted_data,
  relay_key: hop.blinded_public_key,
}));

// Arguments to create the onion in the test vector, with overrides
const args = overrides => ({
  inbound,
  key: recipientPath.path_key,
  outbound: [alice.public_key, bob.public_key],
  records: [{type: '1', value: message.message}],
  secret: senderPath.secret,
  ...overrides,
});

// A node peels a layer off of the onion and decrypts its blinded data
const peel = ({onion, path_key, private_key}) => {
  const ecdh = public_key => {
    return sharedSecret({private_key: hexAsBuffer(private_key), public_key});
  };

  const packet = hexAsBuffer(onion);

  const pathSecret = ecdh(hexAsBuffer(path_key)).secret;

  const {public_key} = deriveEphemeralKey({onion: packet, secret: pathSecret});

  const peeled = decodeOnionPacket({
    onion: packet,
    secret: ecdh(public_key).secret,
  });

  const {records} = decodeTlvStream({encoded: bufferAsHex(peeled.payload)});

  const {data, next_path_key} = decryptBlindedPath({
    encrypted: records.find(n => n.type === '4').value,
    key: path_key,
    secret: bufferAsHex(pathSecret),
  });

  return {
    data: decodeTlvStream({encoded: data}).records,
    next_path_key,
    onion: !peeled.onion ? undefined : bufferAsHex(peeled.onion),
    records,
  };
};

// Every node peels a layer, decrypts its data, and forwards or finishes
const walk = ({hops, onion, path_key}) => {
  const encryptedLengths = [];

  const final = hops.reduce((delivery, hop) => {
    const peeled = peel({
      onion: delivery.onion,
      path_key: delivery.path_key,
      private_key: hop.private_key,
    });

    strictSame(
      peeled.records.map(n => n.type),
      hop.records.map(n => n.type),
      'Got payload record types'
    );

    // Additional records are expected to have their values in the payload
    hop.records.filter(n => !!n.value).forEach(record => {
      const got = peeled.records.find(n => n.type === record.type);

      strictSame(got.value, record.value, 'Got payload record value');
    });

    const encrypted = peeled.records.find(n => n.type === '4').value;

    encryptedLengths.push(encrypted.length);

    const nextNodeId = peeled.data.find(n => n.type === '4');
    const override = peeled.data.find(n => n.type === '8');
    const receivedPathId = peeled.data.find(n => n.type === '6');

    strictSame(
      !nextNodeId ? undefined : nextNodeId.value,
      hop.next_node_id,
      'Got expected next node id'
    );

    strictSame(
      !override ? undefined : override.value,
      hop.next_path_key,
      'Got expected next path key override'
    );

    strictSame(
      !receivedPathId ? undefined : receivedPathId.value,
      hop.path_id,
      'Got expected path id'
    );

    return {
      onion: peeled.onion,
      path_key: !override ? peeled.next_path_key : override.value,
      records: peeled.records,
    };
  }, {onion, path_key});

  return {encryptedLengths, final};
};

const tests = [
  {
    args: args({inbound: undefined}),
    description: 'Inbound hops are required',
    error: 'ExpectedArrayOfInboundHopsToCreatePathOnion',
  },
  {
    args: args({inbound: []}),
    description: 'At least one inbound hop is required',
    error: 'ExpectedArrayOfInboundHopsToCreatePathOnion',
  },
  {
    args: args({inbound: [null]}),
    description: 'An inbound hop is required',
    error: 'ExpectedHexEncodedInboundEncryptedDataToCreatePathOnion',
  },
  {
    args: args({inbound: [{relay_key: bob.blinded_public_key}]}),
    description: 'Inbound hop encrypted data is required',
    error: 'ExpectedHexEncodedInboundEncryptedDataToCreatePathOnion',
  },
  {
    args: args({inbound: [{encrypted_data: bob.encrypted_data}]}),
    description: 'An inbound hop relay key is required',
    error: 'ExpectedHexEncodedInboundHopRelayKeyToCreatePathOnion',
  },
  {
    args: args({inbound: [{encrypted_data: '00', relay_key: '02'}]}),
    description: 'An inbound hop relay key must be a compressed public key',
    error: 'ExpectedCompressedInboundHopRelayKeyToCreatePathOnion',
  },
  {
    args: args({inbound: [{encrypted_data: '', relay_key: invalidPoint}]}),
    description: 'An inbound hop relay key must be a valid public key',
    error: 'ExpectedValidInboundHopRelayKeyToCreatePathOnion',
  },
  {
    args: args({key: undefined}),
    description: 'An inbound path key is required',
    error: 'ExpectedHexEncodedInboundPathKeyToCreatePathOnion',
  },
  {
    args: args({key: '02'}),
    description: 'An inbound path key must be a compressed public key',
    error: 'ExpectedCompressedInboundPathKeyToCreatePathOnion',
  },
  {
    args: args({key: invalidPoint}),
    description: 'An inbound path key must be a valid public key',
    error: 'ExpectedValidInboundPathKeyToCreatePathOnion',
  },
  {
    args: args({outbound: undefined}),
    description: 'Outbound relay keys are required',
    error: 'ExpectedArrayOfOutboundRelayKeysToCreatePathOnion',
  },
  {
    args: args({outbound: []}),
    description: 'The landmark is required as the final outbound relay key',
    error: 'ExpectedArrayOfOutboundRelayKeysToCreatePathOnion',
  },
  {
    args: args({outbound: [null]}),
    description: 'An outbound relay key is required',
    error: 'ExpectedHexEncodedOutboundRelayKeyToCreatePathOnion',
  },
  {
    args: args({outbound: ['key']}),
    description: 'An outbound relay key must be hex encoded',
    error: 'ExpectedHexEncodedOutboundRelayKeyToCreatePathOnion',
  },
  {
    args: args({outbound: ['02']}),
    description: 'An outbound relay key must be a compressed public key',
    error: 'ExpectedCompressedOutboundRelayKeyToCreatePathOnion',
  },
  {
    args: args({outbound: [invalidPoint]}),
    description: 'An outbound relay key must be a valid public key',
    error: 'ExpectedValidOutboundRelayKeyToCreatePathOnion',
  },
  {
    args: args({records: 'records'}),
    description: 'Records must be an array',
    error: 'ExpectedArrayOfFinalHopRecordsToCreatePathOnion',
  },
  {
    args: args({records: [null]}),
    description: 'A record is required',
    error: 'ExpectedRecordTypeNumberStringToCreatePathOnion',
  },
  {
    args: args({records: [{type: 1, value: '00'}]}),
    description: 'A record type must be a number string',
    error: 'ExpectedRecordTypeNumberStringToCreatePathOnion',
  },
  {
    args: args({records: [{type: '1', value: 'value'}]}),
    description: 'A record value must be hex encoded',
    error: 'ExpectedHexEncodedRecordValueToCreatePathOnion',
  },
  {
    args: args({records: [{type: '4', value: '00'}]}),
    description: 'A record must not be an encrypted recipient data record',
    error: 'UnexpectedEncryptedDataRecordToCreatePathOnion',
  },
  {
    args: args({reply: 'reply'}),
    description: 'Reply path hops must be an array',
    error: 'ExpectedArrayOfReplyPathHopsToCreatePathOnion',
  },
  {
    args: args({reply: []}),
    description: 'Reply path hops must have at least one hop',
    error: 'ExpectedArrayOfReplyPathHopsToCreatePathOnion',
  },
  {
    args: args({reply: ['key']}),
    description: 'A reply path hop public key must be hex encoded',
    error: 'ExpectedHexEncodedReplyHopPublicKeyToCreatePathOnion',
  },
  {
    args: args({reply: ['02']}),
    description: 'A reply path hop public key must be a compressed public key',
    error: 'ExpectedCompressedReplyHopPublicKeyToCreatePathOnion',
  },
  {
    args: args({reply: [invalidPoint]}),
    description: 'A reply path hop public key must be a valid public key',
    error: 'ExpectedValidReplyHopPublicKeyToCreatePathOnion',
  },
  {
    args: args({
      records: [{type: '2', value: '00'}],
      reply: [alice.public_key, relay.public_key],
    }),
    description: 'A reply path record must not be given with a reply path',
    error: 'UnexpectedReplyPathRecordToCreatePathOnion',
  },
  {
    args: args({secret: 'secret'}),
    description: 'A path key secret must be hex encoded',
    error: 'ExpectedHexEncodedPathKeySecretToCreatePathOnion',
  },
  {
    args: args({secret: '01'}),
    description: 'A path key secret must be a full length private key',
    error: 'ExpectedPathKeySecretByteLengthToCreatePathOnion',
  },
  {
    args: args({secret: '00'.repeat(32)}),
    description: 'A path key secret must be a valid private key',
    error: 'ExpectedValidPathKeySecretToCreatePathOnion',
  },
  {
    args: args({}),
    description: 'An onion message is created for a published path',
    expected: {
      hops: [
        {
          next_node_id: bob.public_key,
          next_path_key: recipientPath.path_key,
          private_key: alice.private_key,
          records: [{type: '4', value: alice.encrypted_data}],
        },
        {
          next_node_id: carol.public_key,
          private_key: bob.private_key,
          records: [{type: '4', value: bob.encrypted_data}],
        },
        {
          next_node_id: dave.public_key,
          private_key: carol.private_key,
          records: [{type: '4', value: carol.encrypted_data}],
        },
        {
          path_id: pathId,
          private_key: dave.private_key,
          records: [
            {type: '1', value: message.message},
            {type: '4', value: dave.encrypted_data},
          ],
        },
      ],
      key: senderPath.path_key,
    },
  },
  {
    args: args({
      outbound: [bob.public_key],
      records: [{type: '65537', value: '00'}],
    }),
    description: 'An onion is created directly to the landmark of a path',
    expected: {
      hops: [
        {
          next_node_id: carol.public_key,
          private_key: bob.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: dave.public_key,
          private_key: carol.private_key,
          records: [{type: '4'}],
        },
        {
          path_id: pathId,
          private_key: dave.private_key,
          records: [{type: '4'}, {type: '65537', value: '00'}],
        },
      ],
      key: recipientPath.path_key,
    },
  },
  {
    args: args({
      outbound: [relay.public_key, alice.public_key, bob.public_key],
      records: [{type: '65537', value: '01'}, {type: '65539', value: '02'}],
      secret: undefined,
    }),
    description: 'An onion is created through multiple outbound hops',
    expected: {
      hops: [
        {
          next_node_id: alice.public_key,
          private_key: relay.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: bob.public_key,
          next_path_key: recipientPath.path_key,
          private_key: alice.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: carol.public_key,
          private_key: bob.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: dave.public_key,
          private_key: carol.private_key,
          records: [{type: '4'}],
        },
        {
          path_id: pathId,
          private_key: dave.private_key,
          records: [
            {type: '4'},
            {type: '65537', value: '01'},
            {type: '65539', value: '02'},
          ],
        },
      ],
    },
  },
  {
    args: args({
      inbound: long.path,
      key: long.key,
      outbound: [relay.public_key, alice.public_key, bob.public_key],
      secret: undefined,
    }),
    description: 'Relaying hop data is padded to the inbound hop data length',
    expected: {
      hops: [
        {
          next_node_id: alice.public_key,
          private_key: relay.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: bob.public_key,
          next_path_key: long.key,
          private_key: alice.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: carol.public_key,
          private_key: bob.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: dave.public_key,
          private_key: carol.private_key,
          records: [{type: '4'}],
        },
        {
          path_id: '01'.repeat(100),
          private_key: dave.private_key,
          records: [
            {type: '1', value: message.message},
            {type: '4'},
          ],
        },
      ],
      is_uniform: true,
    },
  },
  {
    args: args({
      records: [{type: '65537', value: '00'}],
      reply: [alice.public_key, relay.public_key],
    }),
    description: 'An onion is created with a reply path back to the sender',
    expected: {
      hops: [
        {
          next_node_id: bob.public_key,
          next_path_key: recipientPath.path_key,
          private_key: alice.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: carol.public_key,
          private_key: bob.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: dave.public_key,
          private_key: carol.private_key,
          records: [{type: '4'}],
        },
        {
          path_id: pathId,
          private_key: dave.private_key,
          records: [{type: '2'}, {type: '4'}, {type: '65537', value: '00'}],
        },
      ],
      key: senderPath.path_key,
      reply: {
        first_node_id: alice.public_key,
        hops: [
          {
            next_node_id: relay.public_key,
            private_key: alice.private_key,
            records: [{type: '4'}],
          },
          {private_key: relay.private_key, records: [{type: '4'}]},
        ],
      },
    },
  },
  {
    args: args({records: undefined}),
    description: 'An onion is created without additional final hop records',
    expected: {
      hops: [
        {
          next_node_id: bob.public_key,
          next_path_key: recipientPath.path_key,
          private_key: alice.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: carol.public_key,
          private_key: bob.private_key,
          records: [{type: '4'}],
        },
        {
          next_node_id: dave.public_key,
          private_key: carol.private_key,
          records: [{type: '4'}],
        },
        {
          path_id: pathId,
          private_key: dave.private_key,
          records: [{type: '4'}],
        },
      ],
      key: senderPath.path_key,
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => onionForPath(args), new Error(error), 'Got error');

      return end();
    }

    const created = onionForPath(args);

    // A random path key secret gives a random path key
    if (!expected.key) {
      strictSame(isPublicKey(created.key), true, 'Got random path key');
    } else {
      strictSame(created.key, expected.key, 'Got expected path key');
    }

    // A reply path id is returned when a reply path is added
    strictSame(!!created.id, !!expected.reply, 'Got reply path id presence');

    const {encryptedLengths, final} = walk({
      hops: expected.hops,
      onion: created.onion,
      path_key: created.key,
    });

    strictSame(final.onion, undefined, 'The final hop has no next onion');

    // The relaying hops end with the hop that has the next path key override
    const relaying = expected.hops.findIndex(n => !!n.next_path_key) + 1;

    const relayingLengths = new Set(encryptedLengths.slice(Number(), relaying));

    strictSame(relayingLengths.size <= 1, true, 'Relaying hop data is uniform');

    // Relaying hop data is padded to match the inbound hop data when shorter
    if (!!expected.is_uniform) {
      strictSame(new Set(encryptedLengths).size, 1, 'All hop data is uniform');
    }

    // Exit early when there is no reply path to send a reply over
    if (!expected.reply) {
      return end();
    }

    strictSame(isPathId(created.id), true, 'Got random reply path id');

    // The final hop decodes the reply path from its payload
    const replyPath = decodeBlindedPath({
      encoded: hexAsBuffer(final.records.find(n => n.type === '2').value),
    });

    const firstNodeId = bufferAsHex(replyPath.first_node_id);

    strictSame(firstNodeId, expected.reply.first_node_id, 'Got reply node');
    strictSame(replyPath.hops.length, expected.reply.hops.length, 'Reply hops');

    // The final hop sends a reply over the reply path, directly to its landmark
    const answer = onionForPath({
      inbound: replyPath.hops.map(hop => ({
        encrypted_data: bufferAsHex(hop.encrypted_data),
        relay_key: bufferAsHex(hop.blinded_public_key),
      })),
      key: bufferAsHex(replyPath.first_path_key),
      outbound: [firstNodeId],
    });

    const replied = walk({
      hops: expected.reply.hops.map((hop, i, hops) => ({
        ...hop,
        path_id: i === hops.length - 1 ? created.id : undefined,
      })),
      onion: answer.onion,
      path_key: answer.key,
    });

    strictSame(replied.final.onion, undefined, 'The sender is the final hop');

    return end();
  });
});
