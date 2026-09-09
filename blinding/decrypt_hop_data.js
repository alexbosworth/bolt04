const {createDecipheriv} = require('node:crypto');

const {cipherAlgorithm} = require('./constants');
const {deriveKey} = require('./../keys');
const {lengthAuthTagBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthNonceBytes} = require('./constants');
const {typeRhoKey} = require('./constants');

const {alloc} = Buffer;
const {concat} = Buffer;
const {isBuffer} = Buffer;

/** Decrypt the encrypted data of a blinded path hop

  The secret is the ECDH shared secret between the hop and the path key.

  {
    encrypted: <Encrypted Data Buffer Object>
    secret: <Path Key Shared Secret Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    data: <Decrypted Data Buffer Object>
  }
*/
module.exports = ({encrypted, secret}) => {
  if (!isBuffer(encrypted)) {
    throw new Error('ExpectedEncryptedDataBufferToDecryptHopData');
  }

  if (encrypted.length < lengthAuthTagBytes) {
    throw new Error('ExpectedAuthenticatedEncryptedDataToDecryptHopData');
  }

  if (!isBuffer(secret)) {
    throw new Error('ExpectedSharedSecretBufferToDecryptHopData');
  }

  if (secret.length !== lengthKeyBytes) {
    throw new Error('ExpectedSharedSecretByteLengthToDecryptHopData');
  }

  // BOLT 04 names the key derived from the shared secret that encrypts the
  // hop data "rho", the derivation is an HMAC of the shared secret keyed by it
  const {key} = deriveKey({secret, type: typeRhoKey});

  // BOLT 04 defines data encrypted with ChaCha20-Poly1305 using all zero nonce
  const decipher = createDecipheriv(
    cipherAlgorithm,
    key,
    alloc(lengthNonceBytes),
    {authTagLength: lengthAuthTagBytes}
  );

  // The Poly1305 authentication tag is appended to the encrypted data
  decipher.setAuthTag(encrypted.subarray(-lengthAuthTagBytes));

  try {
    const data = concat([
      decipher.update(encrypted.subarray(Number(), -lengthAuthTagBytes)),
      decipher.final(),
    ]);

    return {data};
  } catch (err) {
    throw new Error('FailedToAuthenticateEncryptedDataToDecryptHopData');
  }
};
