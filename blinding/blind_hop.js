const {createCipheriv} = require('node:crypto');
const {createHash} = require('node:crypto');

const {isPoint} = require('tiny-secp256k1');
const {isPrivate} = require('tiny-secp256k1');
const {pointFromScalar} = require('tiny-secp256k1');
const {pointMultiply} = require('tiny-secp256k1');

const {cipherAlgorithm} = require('./constants');
const {deriveKey} = require('./../keys');
const {hashAlgorithm} = require('./constants');
const {lengthAuthTagBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthNonceBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');
const {multiplyPrivateKey} = require('./../keys');
const {sharedSecret} = require('./../keys');
const {typeBlindedNodeIdKey} = require('./constants');
const {typeRhoKey} = require('./constants');

const {alloc} = Buffer;
const {concat} = Buffer;
const {from} = Buffer;
const {isBuffer} = Buffer;
const isCompressed = n => isBuffer(n) && n.length === lengthPointBytes;
const isKey = n => isBuffer(n) && n.length === lengthKeyBytes;
const pathKeyFromSecret = secret => from(pointFromScalar(secret, true));
const sha256 = data => createHash(hashAlgorithm).update(data).digest();

/** Blind a hop of a blinded path with the path key secret for the hop

  {
    data: <Data TLV Stream To Encrypt Buffer Object>
    id: <Node Identity Public Key Buffer Object>
    secret: <Hop Path Key Secret Private Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    blinded_public_key: <Blinded Node Public Key Buffer Object>
    encrypted_data: <Encrypted Data Buffer Object>
    next_secret: <Next Hop Path Key Secret Private Key Buffer Object>
  }
*/
module.exports = ({data, id, secret}) => {
  if (!isBuffer(data)) {
    throw new Error('ExpectedDataBufferToBlindHop');
  }

  if (!isCompressed(id)) {
    throw new Error('ExpectedCompressedNodeIdToBlindHop');
  }

  if (!isPoint(id)) {
    throw new Error('ExpectedValidNodeIdToBlindHop');
  }

  if (!isKey(secret)) {
    throw new Error('ExpectedPathKeySecretToBlindHop');
  }

  if (!isPrivate(secret)) {
    throw new Error('ExpectedValidPathKeySecretToBlindHop');
  }

  const shared = sharedSecret({private_key: secret, public_key: id});

  const blinding = deriveKey({
    secret: shared.secret,
    type: typeBlindedNodeIdKey,
  });

  // The node id is blinded by multiplying it with the blinding factor
  const blindedPublicKey = pointMultiply(id, blinding.key, true);

  // BOLT 04 names the key derived from the shared secret that encrypts the
  // hop data "rho", the derivation is an HMAC of the shared secret keyed by it
  const {key} = deriveKey({secret: shared.secret, type: typeRhoKey});

  // BOLT 04 defines data encrypted with ChaCha20-Poly1305 using all zero nonce
  const cipher = createCipheriv(
    cipherAlgorithm,
    key,
    alloc(lengthNonceBytes),
    {authTagLength: lengthAuthTagBytes}
  );

  // The Poly1305 authentication tag is appended to the encrypted data
  const encrypted = concat([
    cipher.update(data),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  // The next hop path key secret is derived from the path key and the secret
  const next = multiplyPrivateKey({
    key: secret,
    multiplier: sha256(concat([pathKeyFromSecret(secret), shared.secret])),
  });

  return {
    blinded_public_key: from(blindedPublicKey),
    encrypted_data: encrypted,
    next_secret: next.key,
  };
};
