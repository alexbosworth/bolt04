const {randomBytes} = require('node:crypto');

const {isPrivate} = require('tiny-secp256k1');

const {lengthKeyBytes} = require('./constants');

/** Generate a random private key

  {}

  @returns
  {
    key: <Private Key Buffer Object>
  }
*/
module.exports = () => {
  const key = {bytes: randomBytes(lengthKeyBytes)};

  // Random bytes have a negligible chance of not being a valid private key
  while (!isPrivate(key.bytes)) {
    key.bytes = randomBytes(lengthKeyBytes);
  }

  return {key: key.bytes};
};
