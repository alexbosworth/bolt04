const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const {decryptBlindedPath} = require('./../../');
const {paymentPathFromChannels} = require('./../../');
const {sharedSecret} = require('./../../keys');
const vectors = require('./../fixtures/route_blinding.json');

const [bob, carol] = vectors.paths[0].hops;
const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const [dave, eve] = vectors.paths[1].hops;
const hexAsBuffer = hex => Buffer.from(hex, 'hex');
const invalidPoint = `02${'00'.repeat(32)}`;
const isPathId = n => /^[0-9a-f]{64}$/.test(n);
const isPublicKey = n => /^0[23][0-9a-f]{64}$/.test(n);
const pathId = 'c9cf92f45ade68345bc20ae672e2012f4af487ed4415';
const typePadding = '1';
const typePathId = '6';
const typePaymentConstraints = '12';
const typePaymentRelay = '10';
const typeShortChannelId = '2';
const uniq = arr => Array.from(new Set(arr));

const policy = (key, base, rate, cltv, min, max) => ({
  base_fee_mtokens: base,
  cltv_delta: cltv,
  fee_rate: rate,
  max_htlc_mtokens: max,
  min_htlc_mtokens: min,
  public_key: key,
});

// Policies of the BOLT 04 blinded payment onion test vector blinded route
const bobPolicy = policy(bob.public_key, '10000', 0, 50, '20', '1000000000');
const carolPolicy = policy(carol.public_key, '100', 150, 75, '30', '900000000');
const davePolicy = policy(dave.public_key, '0', 100, 25, '50', '950000000');

const evePolicy = {public_key: eve.public_key};

const bobToCarol = {id: '0x0x1', policies: [bobPolicy, carolPolicy]};
const carolToDave = {id: '0x0x2', policies: [carolPolicy, davePolicy]};
const daveToEve = {id: '0x0x3', policies: [davePolicy, evePolicy]};

const makeArgs = overrides => ({
  blocks_until_expiry: 982,
  channels: [bobToCarol, carolToDave, daveToEve],
  cltv_delta: 18,
  current_block_height: 749000,
  destination: eve.public_key,
  id: pathId,
  max_mtokens: '100000',
  ...overrides,
});

const tests = [
  {
    args: makeArgs({blocks_until_expiry: '982'}),
    description: 'A lifetime must be a number of blocks',
    error: 'ExpectedPathLifetimeBlocksToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: undefined}),
    description: 'Channels are required',
    error: 'ExpectedArrayOfChannelsToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: 'channels'}),
    description: 'Channels must be an array',
    error: 'ExpectedArrayOfChannelsToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: [{policies: daveToEve.policies}]}),
    description: 'A channel id is required',
    error: 'ExpectedStandardFormatChannelIdToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: [{id: '1x2', policies: daveToEve.policies}]}),
    description: 'A channel id must be in the standard format',
    error: 'ExpectedStandardFormatChannelIdToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: [{id: '0x0x3'}]}),
    description: 'Channel policies are required',
    error: 'ExpectedArrayOfChannelPoliciesToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: [{id: '0x0x3', policies: []}]}),
    description: 'At least one channel policy is required',
    error: 'ExpectedArrayOfChannelPoliciesToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: [{id: '0x0x3', policies: [davePolicy, {}]}]}),
    description: 'A public key is required for every channel policy',
    error: 'ExpectedPublicKeyForChannelPolicyToCreatePaymentPath',
  },
  {
    args: makeArgs({cltv_delta: undefined}),
    description: 'A final cltv delta is required',
    error: 'ExpectedFinalCltvDeltaToCreatePaymentPath',
  },
  {
    args: makeArgs({cltv_delta: -1}),
    description: 'A final cltv delta must not be negative',
    error: 'ExpectedFinalCltvDeltaToCreatePaymentPath',
  },
  {
    args: makeArgs({current_block_height: undefined}),
    description: 'A current block height is required',
    error: 'ExpectedCurrentBlockHeightToCreatePaymentPath',
  },
  {
    args: makeArgs({current_block_height: '749000'}),
    description: 'A current block height must be a number',
    error: 'ExpectedCurrentBlockHeightToCreatePaymentPath',
  },
  {
    args: makeArgs({destination: undefined}),
    description: 'A destination is required',
    error: 'ExpectedHexEncodedDestinationToCreatePaymentPath',
  },
  {
    args: makeArgs({destination: '02'}),
    description: 'A destination must be a compressed public key',
    error: 'ExpectedCompressedDestinationKeyToCreatePaymentPath',
  },
  {
    args: makeArgs({destination: invalidPoint}),
    description: 'A destination must be a valid public key',
    error: 'ExpectedValidDestinationPublicKeyToCreatePaymentPath',
  },
  {
    args: makeArgs({id: 'id'}),
    description: 'A path id must be hex encoded',
    error: 'ExpectedHexEncodedPathIdToCreatePaymentPath',
  },
  {
    args: makeArgs({hop_count: 1.5}),
    description: 'A hop count must be an integer',
    error: 'ExpectedHopCountToCreatePaymentPath',
  },
  {
    args: makeArgs({hop_count: 3}),
    description: 'A hop count must be at least the real path length',
    error: 'ExpectedHopCountAtLeastPathLengthToCreatePaymentPath',
  },
  {
    args: makeArgs({max_mtokens: undefined}),
    description: 'An amount is required',
    error: 'ExpectedAmountMillitokensToCreatePaymentPath',
  },
  {
    args: makeArgs({max_mtokens: 100000}),
    description: 'An amount must be a millitokens string',
    error: 'ExpectedAmountMillitokensToCreatePaymentPath',
  },
  {
    args: makeArgs({max_mtokens: '0'}),
    description: 'An amount must not be zero',
    error: 'ExpectedAmountMillitokensToCreatePaymentPath',
  },
  {
    args: makeArgs({channels: [bobToCarol, daveToEve]}),
    description: 'A channel must connect to the next node in the path',
    error: 'ExpectedForwardingPolicyForChannelToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{id: '0x0x3', policies: [{public_key: eve.public_key}]}],
    }),
    description: 'A channel must have the policy of the forwarding node',
    error: 'ExpectedForwardingPolicyForChannelToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{id: '0x0x3', policies: [{public_key: 'key'}]}],
    }),
    description: 'A forwarding node public key must be hex encoded',
    error: 'ExpectedHexEncodedForwardingPublicKeyToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{id: '0x0x3', policies: [{public_key: '02'}]}],
    }),
    description: 'A forwarding node public key must be a compressed key',
    error: 'ExpectedCompressedForwardingPublicKeyToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{id: '0x0x3', policies: [{public_key: invalidPoint}]}],
    }),
    description: 'A forwarding node public key must be a valid public key',
    error: 'ExpectedValidForwardingPublicKeyToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{
        id: '0x0x3',
        policies: [{...davePolicy, base_fee_mtokens: 0}],
      }],
    }),
    description: 'A forwarding policy must have a base fee',
    error: 'ExpectedForwardingPolicyBaseFeeToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{
        id: '0x0x3',
        policies: [{...davePolicy, cltv_delta: undefined}],
      }],
    }),
    description: 'A forwarding policy must have a cltv delta',
    error: 'ExpectedForwardingPolicyCltvDeltaToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{id: '0x0x3', policies: [{...davePolicy, fee_rate: '100'}]}],
    }),
    description: 'A forwarding policy must have a fee rate',
    error: 'ExpectedForwardingPolicyFeeRateToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{
        id: '0x0x3',
        policies: [{...davePolicy, max_htlc_mtokens: undefined}],
      }],
    }),
    description: 'A forwarding policy must have a maximum htlc',
    error: 'ExpectedForwardingPolicyMaxHtlcToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{
        id: '0x0x3',
        policies: [{...davePolicy, min_htlc_mtokens: undefined}],
      }],
    }),
    description: 'A forwarding policy must have a minimum htlc',
    error: 'ExpectedForwardingPolicyMinHtlcToCreatePaymentPath',
  },
  {
    args: makeArgs({max_mtokens: '49'}),
    description: 'An amount must not be below a forwarding policy minimum htlc',
    error: 'ExpectedAmountAboveForwardingMinHtlcToCreatePaymentPath',
  },
  {
    args: makeArgs({max_mtokens: '900000001'}),
    description: 'An amount must not be above a forwarding policy maximum htlc',
    error: 'ExpectedAmountWithinForwardingMaxHtlcToCreatePaymentPath',
  },
  {
    args: makeArgs({
      channels: [{id: '0x0x3', policies: [{...davePolicy, cltv_delta: 65536}]}],
    }),
    description: 'A forwarding policy cltv delta must fit in the relay data',
    error: 'ExpectedCltvDeltaWithinRangeToEncodePaymentRelay',
  },
  {
    args: makeArgs({current_block_height: 4294967295}),
    description: 'A path timeout height must fit in the payment constraints',
    error: 'ExpectedMaxHeightWithinRangeToEncodePaymentConstraints',
  },
  {
    args: makeArgs({}),
    description: 'A payment path is created through three channels',
    expected: {
      base_fee_mtokens: '10100',
      cltv_delta: 168,
      fee_rate: 251,
      hops: [
        {
          channel: '0x0x1',
          private_key: bob.private_key,
          records: [
            {type: typeShortChannelId, value: '0000000000000001'},
            {type: typePaymentRelay, value: '0032000000002710'},
            {type: typePaymentConstraints, value: '000b724632'},
          ],
        },
        {
          channel: '0x0x2',
          private_key: carol.private_key,
          records: [
            {type: typeShortChannelId, value: '0000000000000002'},
            {type: typePaymentRelay, value: '004b0000009664'},
            {type: typePaymentConstraints, value: '000b721432'},
          ],
        },
        {
          channel: '0x0x3',
          private_key: dave.private_key,
          records: [
            {type: typeShortChannelId, value: '0000000000000003'},
            {type: typePaymentRelay, value: '001900000064'},
            {type: typePaymentConstraints, value: '000b71c932'},
          ],
        },
        {
          private_key: eve.private_key,
          records: [
            {type: typePaymentConstraints, value: '000b71b032'},
          ],
        },
      ],
      id: pathId,
      introduction_node: bob.public_key,
      max_htlc_mtokens: '100000',
      min_htlc_mtokens: '50',
    },
  },
  {
    args: makeArgs({
      blocks_until_expiry: undefined,
      channels: [daveToEve],
      id: undefined,
    }),
    description: 'A payment path is created with a random id and lifetime',
    expected: {
      base_fee_mtokens: '0',
      cltv_delta: 43,
      fee_rate: 100,
      hops: [
        {
          channel: '0x0x3',
          private_key: dave.private_key,
          records: [
            {type: typeShortChannelId, value: '0000000000000003'},
            {type: typePaymentRelay, value: '001900000064'},
            {type: typePaymentConstraints, value: '000b75d332'},
          ],
        },
        {
          private_key: eve.private_key,
          records: [
            {type: typePaymentConstraints, value: '000b75ba32'},
          ],
        },
      ],
      introduction_node: dave.public_key,
      max_htlc_mtokens: '100000',
      min_htlc_mtokens: '50',
    },
  },
  {
    args: makeArgs({channels: []}),
    description: 'A payment path is created to the destination as a single hop',
    expected: {
      base_fee_mtokens: '0',
      cltv_delta: 18,
      fee_rate: 0,
      hops: [
        {
          private_key: eve.private_key,
          records: [
            {type: typePaymentConstraints, value: '000b71b001'},
          ],
        },
      ],
      id: pathId,
      introduction_node: eve.public_key,
      max_htlc_mtokens: '100000',
      min_htlc_mtokens: '1',
    },
  },
  {
    args: makeArgs({
      blocks_until_expiry: 1,
      channels: [
        {
          id: '16777215x16777215x65535',
          policies: [
            {public_key: carol.public_key},
            policy(bob.public_key, '1000', 500, 65535, '1', '2'),
          ],
        },
        {
          id: '0x0x0',
          policies: [
            policy(carol.public_key, '999', 0, 0, '1', '2'),
            {public_key: eve.public_key},
          ],
        },
      ],
      cltv_delta: 0,
      current_block_height: 0,
      id: '00',
      max_mtokens: '2',
    }),
    description: 'A payment path is created with fees rounded up',
    expected: {
      base_fee_mtokens: '2000',
      cltv_delta: 65535,
      fee_rate: 500,
      hops: [
        {
          channel: '16777215x16777215x65535',
          private_key: bob.private_key,
          records: [
            {type: typeShortChannelId, value: 'ffffffffffffffff'},
            {type: typePaymentRelay, value: 'ffff000001f403e8'},
            {type: typePaymentConstraints, value: '0001000001'},
          ],
        },
        {
          channel: '0x0x0',
          private_key: carol.private_key,
          records: [
            {type: typeShortChannelId, value: '0000000000000000'},
            {type: typePaymentRelay, value: '00000000000003e7'},
            {type: typePaymentConstraints, value: '0000000101'},
          ],
        },
        {
          private_key: eve.private_key,
          records: [
            {type: typePaymentConstraints, value: '0000000101'},
          ],
        },
      ],
      id: '00',
      introduction_node: bob.public_key,
      max_htlc_mtokens: '2',
      min_htlc_mtokens: '1',
    },
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => paymentPathFromChannels(args), new Error(error), 'Error');

      return end();
    }

    const path = paymentPathFromChannels(args);

    strictSame(path.base_fee_mtokens, expected.base_fee_mtokens, 'Base fee');
    strictSame(path.cltv_delta, expected.cltv_delta, 'Got total cltv delta');
    strictSame(path.fee_rate, expected.fee_rate, 'Got total fee rate');
    strictSame(path.hops.length, expected.hops.length, 'Got every hop');

    // The introduction node is the unblinded first hop that senders route to
    strictSame(
      path.introduction_node,
      expected.introduction_node,
      'Got introduction node'
    );
    strictSame(path.max_htlc_mtokens, expected.max_htlc_mtokens, 'Max htlc');
    strictSame(path.min_htlc_mtokens, expected.min_htlc_mtokens, 'Min htlc');
    strictSame(isPublicKey(path.key), true, 'Got path key');

    // A path id is randomly generated when it is not specified
    if (!expected.id) {
      strictSame(isPathId(path.id), true, 'Got random path id');
    } else {
      strictSame(path.id, expected.id, 'Got expected path id');
    }

    // Padding gives every hop encrypted data of the same length
    strictSame(
      uniq(path.hops.map(n => byteLength(n.encrypted_data))).length,
      1,
      'Got equal data lengths'
    );

    // The blinded keys are not the node keys
    strictSame(
      path.hops.map(n => isPublicKey(n.relay_key)).every(n => n),
      true,
      'Got blinded keys'
    );

    // Every hop decrypts its data with the path key it receives
    const final = expected.hops.reduce((pathKey, hop, i) => {
      const {secret} = sharedSecret({
        private_key: hexAsBuffer(hop.private_key),
        public_key: hexAsBuffer(pathKey),
      });

      const decrypted = decryptBlindedPath({
        encrypted: path.hops[i].encrypted_data,
        key: pathKey,
        secret: bufferAsHex(secret),
      });

      const isFinal = i === expected.hops.length - 1;

      // The path id record is only in the data of the final hop
      strictSame(decrypted.id, !isFinal ? undefined : path.id, 'Got path id');

      // The next channel record is in the data of the forwarding hops
      strictSame(decrypted.next_channel_id, hop.channel, 'Got next channel');

      strictSame(decrypted.features, [], 'Got no allowed features');

      const records = decrypted.records.filter(n => n.type !== typePadding);

      strictSame(
        records.filter(n => n.type !== typePathId),
        hop.records,
        'Got expected hop records'
      );

      return decrypted.next_path_key;
    }, path.key);

    strictSame(isPublicKey(final), true, 'Got final hop next path key');

    return end();
  });
});

test('A payment path is padded with dummy hops to a hop count', (t, end) => {
  const base = paymentPathFromChannels(makeArgs({channels: [daveToEve]}));

  const padded = paymentPathFromChannels(makeArgs({
    channels: [daveToEve],
    hop_count: 4,
  }));

  strictSame(base.hops.length, 2, 'The real path has two hops');
  strictSame(padded.hops.length, 4, 'The padded path has four hops');
  strictSame(padded.introduction_node, dave.public_key, 'Same intro node');

  // Dummy hops do not change the advertised fees, cltv or htlc range
  strictSame(padded.base_fee_mtokens, base.base_fee_mtokens, 'Same base fee');
  strictSame(padded.cltv_delta, base.cltv_delta, 'Same total cltv delta');
  strictSame(padded.fee_rate, base.fee_rate, 'Same total fee rate');
  strictSame(padded.max_htlc_mtokens, base.max_htlc_mtokens, 'Same max htlc');
  strictSame(padded.min_htlc_mtokens, base.min_htlc_mtokens, 'Same min htlc');

  // Every hop still has encrypted data of the same length
  const lengths = padded.hops.map(n => byteLength(n.encrypted_data));

  strictSame(uniq(lengths).length, 1, 'Got equal encrypted data lengths');

  const keys = [dave, eve, eve, eve].map(n => n.private_key);
  const pathIds = [];
  let key = padded.key;

  padded.hops.forEach((hop, i) => {
    const {secret} = sharedSecret({
      private_key: hexAsBuffer(keys[i]),
      public_key: hexAsBuffer(key),
    });

    const decrypted = decryptBlindedPath({
      encrypted: hop.encrypted_data,
      key,
      secret: bufferAsHex(secret),
    });

    // Dummy hops point back to the destination and carry no path id
    if (!!i && i < padded.hops.length - 1) {
      strictSame(decrypted.next_node_id, eve.public_key, 'Dummy hop');
      strictSame(decrypted.id, undefined, 'A dummy hop has no path id');
    }

    if (!!decrypted.id) {
      pathIds.push(decrypted.id);
    }

    key = decrypted.next_path_key;
  });

  strictSame(pathIds, [padded.id], 'Only the final hop carries the path id');

  return end();
});
