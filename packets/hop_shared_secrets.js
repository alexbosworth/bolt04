const {createHash} = require('node:crypto');

const {isPrivate} = require('tiny-secp256k1');
const {pointFromScalar} = require('tiny-secp256k1');

const {hashAlgorithm} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {multiplyPrivateKey} = require('./../keys');
const {sharedSecret} = require('./../keys');

const {concat} = Buffer;
const {from} = Buffer;
const {isArray} = Array;
const {isBuffer} = Buffer;
const isKey = n => isBuffer(n) && n.length === lengthKeyBytes && isPrivate(n);
const sha256 = data => createHash(hashAlgorithm).update(data).digest();

/** Derive the shared secrets between a session key and each hop in a path

  The ephemeral key is blinded for every subsequent hop by multiplying it with
  the hash of the current ephemeral public key and the current shared secret.

  {
    public_keys: [<Hop Public Key Buffer Object>]
    session_key: <Session Private Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    secrets: [<Hop Shared Secret Buffer Object>]
  }
*/
module.exports = ({public_keys, session_key}) => {
  if (!isArray(public_keys) || !public_keys.length) {
    throw new Error('ExpectedHopPublicKeysToDeriveHopSharedSecrets');
  }

  if (!isKey(session_key)) {
    throw new Error('ExpectedValidSessionKeyToDeriveHopSharedSecrets');
  }

  const secrets = [];

  const ephemeral = {private_key: session_key};

  public_keys.forEach(publicKey => {
    const ephemeralPublicKey = pointFromScalar(ephemeral.private_key, true);

    const {secret} = sharedSecret({
      private_key: ephemeral.private_key,
      public_key: publicKey,
    });

    // The blinding factor is the hash of the ephemeral public key and secret
    const blinding = sha256(concat([from(ephemeralPublicKey), secret]));

    // The ephemeral key for the next hop is blinded by the blinding factor
    const next = multiplyPrivateKey({
      key: ephemeral.private_key,
      multiplier: blinding,
    });

    ephemeral.private_key = next.key;

    return secrets.push(secret);
  });

  return {secrets};
};
