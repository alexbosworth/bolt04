const strictSame = require('node:assert').strict.deepStrictEqual;
const test = require('node:test');
const {throws} = require('node:assert').strict;

const generateFiller = require('./../../packets/generate_filler');
const payment = require('./../fixtures/payment_onion.json');

const hexAsBuffer = hex => Buffer.from(hex, 'hex');

const secrets = payment.hops.map(n => hexAsBuffer(n.shared_secret));

// The filler for the BOLT 04 payment onion test vector hops
const paymentFiller = [
  '51c30cc8f20da0153ca3839b850bcbc8fefc7fd84802f3e78cb35a660e747b57',
  'aa5b0de555cbcf1e6f044a718cc34219b96597f3684eee7a0232e1754f638006',
  'cb15a14788217abdf1bdd67910dc1ca74a05dcce8b5ad841b0f939fca8935f6a',
  '3ff660e0efb409f1a24ce4aa16fc7dc074cd84422c10cc4dd4fc150dd6d1e4f5',
  '0b36ce10fef29248dd0cec85c72eb3e4b2f4a7c03b5c9e0c9dd12976553ede3d',
  '0e295f842187b33ff743e6d685075e98e1bcab8a46bff0102ca8b2098ae91798',
  'd370b01ca7076d3d626952a03663fe8dc700d1358263b73ba30e36731a0b7209',
  '2f8d5bc8cd346762e93b2bf203d00264e4bc136fc142de8f7b69154deb05854e',
  'a88e2d7506222c95ba1aab06',
];

const tests = [
  {
    args: {secrets, size: 1300},
    description: 'Hop data lengths are required',
    error: 'ExpectedHopDataLengthsToGenerateFiller',
  },
  {
    args: {lengths: [], secrets, size: 1300},
    description: 'At least one hop data length is required',
    error: 'ExpectedHopDataLengthsToGenerateFiller',
  },
  {
    args: {lengths: ['51'], secrets, size: 1300},
    description: 'Hop data lengths must be numbers',
    error: 'ExpectedHopDataLengthsToGenerateFiller',
  },
  {
    args: {lengths: [51], size: 1300},
    description: 'Shared secrets are required',
    error: 'ExpectedHopSharedSecretsToGenerateFiller',
  },
  {
    args: {lengths: [51], secrets, size: 1300},
    description: 'A shared secret is required for every hop',
    error: 'ExpectedHopSharedSecretsToGenerateFiller',
  },
  {
    args: {lengths: [51], secrets: secrets.slice(0, 1)},
    description: 'A payloads size is required',
    error: 'ExpectedHopPayloadsSizeToGenerateFiller',
  },
  {
    args: {lengths: [51], secrets: secrets.slice(0, 1), size: 1300},
    description: 'A single hop has no forwarding hops so there is no filler',
    expected: {filler: ''},
  },
  {
    args: {lengths: [51, 115, 51, 51, 307], secrets, size: 1300},
    description: 'Filler is generated for the forwarding hops',
    expected: {filler: paymentFiller.join('')},
  },
];

tests.forEach(({args, description, error, expected}) => {
  return test(description, (t, end) => {
    if (!!error) {
      throws(() => generateFiller(args), new Error(error), 'Got error');

      return end();
    }

    const {filler} = generateFiller(args);

    strictSame(filler.toString('hex'), expected.filler, 'Got expected filler');

    return end();
  });
});
