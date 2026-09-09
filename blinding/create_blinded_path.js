const {isPoint} = require('tiny-secp256k1');
const {isPrivate} = require('tiny-secp256k1');
const {pointFromScalar} = require('tiny-secp256k1');

const blindHop = require('./blind_hop');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {randomPrivateKey} = require('./../keys');

const {from} = Buffer;
const {isArray} = Array;
const {isBuffer} = Buffer;
const pathKeyFromSecret = secret => from(pointFromScalar(secret, true));

/** Create a blinded path

  The `secret` path private key is generated when not specified.

  {
    hops: [{
      data: <Data TLV Stream To Encrypt Buffer Object>
      public_key: <Node Identity Public Key Buffer Object>
    }]
    [secret]: <Path Key Secret Private Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    hops: [{
      blinded_public_key: <Blinded Node Public Key Buffer Object>
      encrypted_data: <Encrypted Data Buffer Object>
    }]
    key: <First Hop Path Key Public Key Buffer Object>
  }
*/
module.exports = ({hops, secret}) => {
  if (!isArray(hops) || !hops.length) {
    throw new Error('ExpectedArrayOfHopsToCreateBlindedPath');
  }

  if (!hops.every(n => !!n && isBuffer(n.data))) {
    throw new Error('ExpectedDataBufferForHopToCreateBlindedPath');
  }

  if (!hops.every(n => isBuffer(n.public_key))) {
    throw new Error('ExpectedPublicKeyBufferForHopToCreateBlindedPath');
  }

  if (!hops.every(n => n.public_key.length === lengthPointBytes)) {
    throw new Error('ExpectedCompressedPublicKeyForHopToCreateBlindedPath');
  }

  if (!hops.every(n => isPoint(n.public_key))) {
    throw new Error('ExpectedValidPublicKeyForHopToCreateBlindedPath');
  }

  if (!!secret && !isBuffer(secret)) {
    throw new Error('ExpectedSecretBufferToCreateBlindedPath');
  }

  if (!!secret && secret.length !== lengthKeyBytes) {
    throw new Error('ExpectedPathKeySecretByteLengthToCreateBlindedPath');
  }

  if (!!secret && !isPrivate(secret)) {
    throw new Error('ExpectedValidPathKeySecretToCreateBlindedPath');
  }

  const path = {secret: secret || randomPrivateKey({}).key};

  // The path key for the first hop is the public key of the first hop secret
  const pathKey = pathKeyFromSecret(path.secret);

  // Each hop is blinded with the secret derived by the hop before it
  const blinded = hops.map(hop => {
    const blindedHop = blindHop({
      data: hop.data,
      id: hop.public_key,
      secret: path.secret,
    });

    path.secret = blindedHop.next_secret;

    return {
      blinded_public_key: blindedHop.blinded_public_key,
      encrypted_data: blindedHop.encrypted_data,
    };
  });

  return {hops: blinded, key: pathKey};
};
