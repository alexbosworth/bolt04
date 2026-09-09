const {isPrivate} = require('tiny-secp256k1');

const {curveOrder} = require('./constants');
const {hexBase} = require('./constants');
const {lengthKeyBytes} = require('./constants');
const {lengthKeyHex} = require('./constants');

const asHex = n => n.toString(hexBase).padStart(lengthKeyHex, '0');
const bufferAsBigInt = buffer => BigInt(`0x${buffer.toString('hex')}`);
const {from} = Buffer;
const hexAsBigInt = hex => BigInt(`0x${hex}`);
const hexAsBuffer = hex => from(hex, 'hex');
const {isBuffer} = Buffer;
const isKeyBytes = n => isBuffer(n) && n.length === lengthKeyBytes;

/** Multiply a private key by a scalar multiplier, modulo the curve order

  {
    key: <Private Key Buffer Object>
    multiplier: <Scalar Multiplier Buffer Object>
  }

  @throws
  <Error>

  @returns
  {
    key: <Multiplied Private Key Buffer Object>
  }
*/
module.exports = ({key, multiplier}) => {
  if (!isKeyBytes(multiplier)) {
    throw new Error('ExpectedMultiplierToMultiplyPrivateKey');
  }

  if (!isKeyBytes(key) || !isPrivate(key)) {
    throw new Error('ExpectedValidPrivateKeyToMultiply');
  }

  const order = hexAsBigInt(curveOrder);

  const product = bufferAsBigInt(key) * bufferAsBigInt(multiplier);

  const multiplied = hexAsBuffer(asHex(product % order));

  // A product that is not a valid private key cannot be used to derive keys
  if (!isPrivate(multiplied)) {
    throw new Error('UnexpectedInvalidPrivateKeyMultiplicationProduct');
  }

  return {key: multiplied};
};
