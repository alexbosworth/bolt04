const {randomBytes} = require('node:crypto');

const {isPoint} = require('tiny-secp256k1');
const {rawChanId} = require('bolt07');

const blindHopRecords = require('./blind_hop_records');
const {defaultLifetimeBlocks} = require('./constants');
const encodePaymentConstraints = require('./encode_payment_constraints');
const encodePaymentRelay = require('./encode_payment_relay');
const {lengthPathIdBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {minHtlcMtokens} = require('./constants');
const {typeNextNodeId} = require('./constants');
const {typePathId} = require('./constants');
const {typePaymentConstraints} = require('./constants');
const {typePaymentRelay} = require('./constants');
const {typeShortChannelId} = require('./constants');

const bufferAsHex = buffer => buffer.toString('hex');
const byteLength = hex => hex.length / 2;
const {from} = Buffer;
const hasFee = n => !!BigInt(n.base_fee_mtokens) || !!n.fee_rate;
const {isArray} = Array;
const isChannelId = n => typeof n === 'string' && /^\d+x\d+x\d+$/.test(n);
const isHex = n => !(n.length % 2) && /^[0-9A-F]*$/i.test(n);
const isHexString = n => typeof n === 'string' && isHex(n);
const isNumeric = n => typeof n === 'string' && /^\d+$/.test(n);
const isPublicKey = n => isPoint(from(n, 'hex'));
const {isSafeInteger} = Number;
const isUnsigned = n => isSafeInteger(n) && n >= Number();
const larger = (a, b) => b > a ? b : a;
const million = BigInt(1e6);
const noBaseFee = '0';
const noFees = {base: BigInt(Number()), rate: BigInt(Number())};
const roundUp = n => (n + million - BigInt(1)) / million;
const sumOf = arr => arr.reduce((sum, n) => sum + n, Number());

/** Create a blinded payment path from a series of channels to a destination

  For BLIP 39 set the `id` to the `payment` identifier of the invoice

  {
    [blocks_until_expiry]: <Blocks Until Path Expires Number>
    channels: [{
      id: <Standard Format Channel Id String>
      policies: [{
        base_fee_mtokens: <Base Fee Millitokens String>
        cltv_delta: <Locktime Delta Number>
        fee_rate: <Fees Charged in Millitokens Per Million Number>
        max_htlc_mtokens: <Maximum HTLC Millitokens Value String>
        min_htlc_mtokens: <Minimum HTLC Millitokens Value String>
        public_key: <Node Identity Public Key Hex String>
      }]
    }]
    cltv_delta: <Final Hop CLTV Delta Number>
    current_block_height: <Current Block Height Number>
    destination: <Destination Node Public Key Hex String>
    [receiver_base_fee_mtokens]: <Receiver Base Fee Millitokens String>
    [receiver_fee_rate]: <Receiver Fee Rate Millitokens Per Million Number>
    [hop_count]: <Total Padding Inclusive Blinded Hop Count Number>
    [id]: <Path Identifier Hex String>
    max_mtokens: <Maximum Millitokens Number Allowed Through Path String>
  }

  @throws
  <Error>

  @returns
  {
    base_fee_mtokens: <Accumulated Base Fee Millitokens String>
    cltv_delta: <Accumulated CLTV Expiry Delta Number>
    fee_rate: <Accumulated Fee Rate Millitokens Per Million Number>
    hops: [{
      encrypted_data: <Encrypted Recipient Data Hex String>
      relay_key: <Blinded Node Public Key Hex String>
    }]
    id: <Path Identifier Hex String>
    introduction_node: <Introduction Node Public Key Hex String>
    key: <First Hop Path Key Public Key Hex String>
    max_htlc_mtokens: <Maximum HTLC Millitokens String>
    min_htlc_mtokens: <Minimum HTLC Millitokens String>
  }
*/
module.exports = args => {
  if (!isArray(args.channels)) {
    throw new Error('ExpectedArrayOfChannelsToCreatePaymentPath');
  }

  if (!args.channels.every(n => !!n && isChannelId(n.id))) {
    throw new Error('ExpectedStandardFormatChannelIdToCreatePaymentPath');
  }

  if (!args.channels.every(n => isArray(n.policies) && !!n.policies.length)) {
    throw new Error('ExpectedArrayOfChannelPoliciesToCreatePaymentPath');
  }

  if (!args.channels.every(n => n.policies.every(p => !!p && !!p.public_key))) {
    throw new Error('ExpectedPublicKeyForChannelPolicyToCreatePaymentPath');
  }

  if (!isUnsigned(args.cltv_delta)) {
    throw new Error('ExpectedFinalCltvDeltaToCreatePaymentPath');
  }

  if (!isUnsigned(args.current_block_height)) {
    throw new Error('ExpectedCurrentBlockHeightToCreatePaymentPath');
  }

  if (!isHexString(args.destination)) {
    throw new Error('ExpectedHexEncodedDestinationToCreatePaymentPath');
  }

  if (byteLength(args.destination) !== lengthPointBytes) {
    throw new Error('ExpectedCompressedDestinationKeyToCreatePaymentPath');
  }

  if (!isPublicKey(args.destination)) {
    throw new Error('ExpectedValidDestinationPublicKeyToCreatePaymentPath');
  }

  if (!!args.id && !isHexString(args.id)) {
    throw new Error('ExpectedHexEncodedPathIdToCreatePaymentPath');
  }

  if (!!args.blocks_until_expiry && !isUnsigned(args.blocks_until_expiry)) {
    throw new Error('ExpectedPathLifetimeBlocksToCreatePaymentPath');
  }

  if (!!args.hop_count && !isUnsigned(args.hop_count)) {
    throw new Error('ExpectedHopCountToCreatePaymentPath');
  }

  if (!isNumeric(args.max_mtokens) || !BigInt(args.max_mtokens)) {
    throw new Error('ExpectedAmountMillitokensToCreatePaymentPath');
  }

  // Receiver fees are the relay policy of a padding hop, which is the receiver
  const receiverFee = {
    base_fee_mtokens: args.receiver_base_fee_mtokens || noBaseFee,
    cltv_delta: Number(),
    fee_rate: args.receiver_fee_rate || Number(),
  };

  if (!isNumeric(receiverFee.base_fee_mtokens)) {
    throw new Error('ExpectedReceiverBaseFeeMillitokensToCreatePaymentPath');
  }

  if (!isUnsigned(receiverFee.fee_rate)) {
    throw new Error('ExpectedReceiverFeeRateToCreatePaymentPath');
  }

  // Walking back from the destination, each channel is forwarded across by the
  // node on the channel that is not the next node towards the destination
  const forwards = args.channels.reduceRight((hops, channel) => {
    const [next] = hops;

    const nextNodeId = !next ? args.destination : next.public_key;

    const policies = channel.policies.filter(n => n.public_key !== nextNodeId);

    // The forwarding node is unknown when its policy is missing or ambiguous
    if (policies.length !== 1) {
      throw new Error('ExpectedForwardingPolicyForChannelToCreatePaymentPath');
    }

    const [policy] = policies;

    const hop = {channel: channel.id, policy, public_key: policy.public_key};

    return [hop].concat(hops);
  }, []);

  if (!forwards.every(n => isHexString(n.public_key))) {
    throw new Error('ExpectedHexEncodedForwardingPublicKeyToCreatePaymentPath');
  }

  if (!forwards.every(n => byteLength(n.public_key) === lengthPointBytes)) {
    throw new Error('ExpectedCompressedForwardingPublicKeyToCreatePaymentPath');
  }

  if (!forwards.every(n => isPublicKey(n.public_key))) {
    throw new Error('ExpectedValidForwardingPublicKeyToCreatePaymentPath');
  }

  if (!forwards.every(n => isNumeric(n.policy.base_fee_mtokens))) {
    throw new Error('ExpectedForwardingPolicyBaseFeeToCreatePaymentPath');
  }

  if (!forwards.every(n => isUnsigned(n.policy.cltv_delta))) {
    throw new Error('ExpectedForwardingPolicyCltvDeltaToCreatePaymentPath');
  }

  if (!forwards.every(n => isUnsigned(n.policy.fee_rate))) {
    throw new Error('ExpectedForwardingPolicyFeeRateToCreatePaymentPath');
  }

  if (!forwards.every(n => isNumeric(n.policy.max_htlc_mtokens))) {
    throw new Error('ExpectedForwardingPolicyMaxHtlcToCreatePaymentPath');
  }

  if (!forwards.every(n => isNumeric(n.policy.min_htlc_mtokens))) {
    throw new Error('ExpectedForwardingPolicyMinHtlcToCreatePaymentPath');
  }

  const isTakingFees = hasFee(receiverFee);
  const lifetime = args.blocks_until_expiry || defaultLifetimeBlocks;
  const realHops = forwards.length + 1;

  // A padding hop is added to charge receiver fees when no hop count is given
  const defaultHops = !isTakingFees ? realHops : realHops + 1;

  const hopCount = args.hop_count === undefined ? defaultHops : args.hop_count;

  const dummies = hopCount - realHops;

  if (dummies < Number()) {
    throw new Error('ExpectedHopCountAtLeastPathLengthToCreatePaymentPath');
  }

  // The final hop has no relay data, so receiver fees need a padding hop
  if (isTakingFees && !dummies) {
    throw new Error('ExpectedPaddingHopToCreatePaymentPath');
  }

  const amount = BigInt(args.max_mtokens);

  const forwardMins = forwards.map(n => BigInt(n.policy.min_htlc_mtokens));

  // A path without forwards has the minimum of a millitoken that any HTLC has
  const mins = !forwardMins.length ? [BigInt(minHtlcMtokens)] : forwardMins;

  // The payment must be at least the largest minimum HTLC along the path
  const minHtlc = mins.reduce(larger);

  if (minHtlc > amount) {
    throw new Error('ExpectedAmountAboveForwardingMinHtlcToCreatePaymentPath');
  }

  // The payment is the maximum HTLC of the path so every forward must allow it
  if (forwards.some(n => BigInt(n.policy.max_htlc_mtokens) < amount)) {
    throw new Error('ExpectedAmountWithinForwardingMaxHtlcToCreatePaymentPath');
  }

  const pathId = args.id || bufferAsHex(randomBytes(lengthPathIdBytes));

  // The destination accepts payments up until the expiry plus its final delta
  const expiryHeight = args.current_block_height + lifetime;

  const constraints = timeoutHeight => bufferAsHex(encodePaymentConstraints({
    max_timeout_height: timeoutHeight + args.cltv_delta,
    min_htlc_mtokens: minHtlc.toString(),
  }).encoded);

  // Forwarding hops are told the channel, the relay policy and constraints
  const relayingRecords = forwards.map((hop, i) => {
    // The incoming timeout to a hop includes the deltas of all hops after it
    const deltas = forwards.slice(i).map(n => n.policy.cltv_delta);

    const timeout = expiryHeight + sumOf(deltas);

    const relay = encodePaymentRelay({
      base_fee_mtokens: hop.policy.base_fee_mtokens,
      cltv_delta: hop.policy.cltv_delta,
      fee_rate: hop.policy.fee_rate,
    });

    return [
      {type: typeShortChannelId, value: rawChanId({channel: hop.channel}).id},
      {type: typePaymentRelay, value: bufferAsHex(relay.encoded)},
      {type: typePaymentConstraints, value: constraints(timeout)},
    ];
  });

  // Dummy hops loop back to the destination to obscure the true path length
  const noFeePolicy = {
    base_fee_mtokens: noBaseFee,
    cltv_delta: Number(),
    fee_rate: Number(),
  };

  // The first dummy hop charges the receiver fees and the rest charge nothing
  const dummyPolicies = [...Array(dummies)].map((n, i) => {
    return !i ? receiverFee : noFeePolicy;
  });

  const dummyRecords = dummyPolicies.map(policy => {
    const relay = encodePaymentRelay(policy);

    return [
      {type: typeNextNodeId, value: args.destination},
      {type: typePaymentRelay, value: bufferAsHex(relay.encoded)},
      {type: typePaymentConstraints, value: constraints(expiryHeight)},
    ];
  });

  // The final hop is given the path id and the constraints on the payment
  const finalRecords = [
    {type: typePathId, value: pathId},
    {type: typePaymentConstraints, value: constraints(expiryHeight)},
  ];

  const records = relayingRecords.concat(dummyRecords).concat([finalRecords]);

  // Dummy hops repeat the destination so it peels and ignores them on receipt
  const dummyKeys = [...Array(dummies)].map(() => args.destination);

  const publicKeys = forwards.map(n => n.public_key)
    .concat(dummyKeys)
    .concat(args.destination);

  // The introduction node is the first forwarding node, reached unblinded
  const [introductionNode] = publicKeys;

  const blinded = blindHopRecords({
    hops: publicKeys.map((publicKey, i) => ({
      public_key: publicKey,
      records: records[i],
    })),
  });

  // The relaying hops are the forwarding hops followed by the dummy hops
  const relays = forwards.map(n => n.policy).concat(dummyPolicies);

  // Fees accumulate from the last relaying hop back to the introduction node
  const fees = relays.reduceRight((total, policy) => {
    const base = BigInt(policy.base_fee_mtokens);
    const rate = BigInt(policy.fee_rate);

    return {
      base: roundUp(base * million + total.base * (million + rate)),
      rate: roundUp((total.rate + rate) * million + total.rate * rate),
    };
  }, noFees);

  return {
    base_fee_mtokens: fees.base.toString(),
    cltv_delta: sumOf(relays.map(n => n.cltv_delta)) + args.cltv_delta,
    fee_rate: Number(fees.rate),
    hops: blinded.path,
    id: pathId,
    introduction_node: introductionNode,
    key: blinded.key,
    max_htlc_mtokens: amount.toString(),
    min_htlc_mtokens: minHtlc.toString(),
  };
};
