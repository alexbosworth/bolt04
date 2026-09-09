const {createHash} = require('node:crypto');

const {isPoint} = require('tiny-secp256k1');
const {isPrivate} = require('tiny-secp256k1');
const {pointMultiply} = require('tiny-secp256k1');

const {hashAlgorithm} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthPointBytes} = require('./constants');

const {isBuffer} = Buffer;
const isKey = n => isBuffer(n) && n.length === lengthKeyBytes && isPrivate(n);

/** Derive an ECDH shared secret

  The shared secret is the hash of the compressed shared point

  {
    private_key: <Private Key Buffer Object>
    public_key: <Public Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    secret: <Shared Secret Buffer Object>
  }
*/
module.exports = args => {
  if (!args) {
    throw new Error('ExpectedArgumentsToDeriveSharedSecret');
  }

  if (!isKey(args.private_key)) {
    throw new Error('ExpectedValidPrivateKeyToDeriveSharedSecret');
  }

  if (!isBuffer(args.public_key)) {
    throw new Error('ExpectedPublicKeyBufferToDeriveSharedSecret');
  }

  if (args.public_key.length !== lengthPointBytes) {
    throw new Error('ExpectedCompressedPublicKeyToDeriveSharedSecret');
  }

  if (!isPoint(args.public_key)) {
    throw new Error('ExpectedValidPublicKeyToDeriveSharedSecret');
  }

  const point = pointMultiply(args.public_key, args.private_key, true);

  return {secret: createHash(hashAlgorithm).update(point).digest()};
};
