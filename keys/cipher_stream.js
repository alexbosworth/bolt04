const {createCipheriv} = require('node:crypto');

const {cipherAlgorithm} = require('./constants');
const {lengthCipherIvBytes} = require('./constants');
const {lengthKeyBytes} = require('./constants');

const {alloc} = Buffer;
const {isBuffer} = Buffer;
const isKey = n => isBuffer(n) && n.length === lengthKeyBytes;
const {isSafeInteger} = Number;

/** Generate a pseudo random byte stream from a key

  The stream is the ChaCha20 encryption of zero bytes with a zero nonce

  {
    bytes: <Stream Byte Length Number>
    key: <Stream Key Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    stream: <Pseudo Random Byte Stream Buffer Object>
  }
*/
module.exports = ({bytes, key}) => {
  if (!isKey(key)) {
    throw new Error('ExpectedKeyToGenerateCipherStream');
  }

  if (!bytes || !isSafeInteger(bytes) || bytes < Number()) {
    throw new Error('ExpectedStreamLengthToGenerateCipherStream');
  }

  const iv = alloc(lengthCipherIvBytes);

  const cipher = createCipheriv(cipherAlgorithm, key, iv);

  return {stream: cipher.update(alloc(bytes))};
};
