const {createHmac} = require('node:crypto');

const {hashAlgorithm} = require('./constants');
const {lengthKeyBytes} = require('./constants');

const {isBuffer} = Buffer;
const isSecret = n => isBuffer(n) && n.length === lengthKeyBytes;
const isType = n => typeof n === 'string' && !!n.length;

/** Derive a key of a specific type from a secret

  The key type is used as the HMAC key and the secret is the HMAC message

  {
    secret: <Secret Buffer Object>
    type: <Key Type String>
  }

  @throws
  <Error>

  @returns
  {
    key: <Derived Key Buffer Object>
  }
*/
module.exports = ({secret, type}) => {
  if (!isSecret(secret)) {
    throw new Error('ExpectedSecretBufferToDeriveKey');
  }

  if (!isType(type)) {
    throw new Error('ExpectedKeyTypeToDeriveKey');
  }

  return {key: createHmac(hashAlgorithm, type).update(secret).digest()};
};
