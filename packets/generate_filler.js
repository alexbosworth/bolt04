const {cipherStream} = require('./../keys');
const {deriveKey} = require('./../keys');
const {typeRhoKey} = require('./constants');

const {alloc} = Buffer;
const {isArray} = Array;
const isLength = n => Number.isSafeInteger(n) && n > Number();
const streamLengthMultiplier = 2;
const sum = numbers => numbers.reduce((total, n) => total + n, Number());

/** Generate the filler that pads the hop payloads for the final hop

  Every forwarding hop appends zero bytes to the payloads to replace the bytes
  it removed, then obfuscates them with its stream. The filler is the result of
  this process, that the sender must pre-compute to be able to calculate HMACs.

  {
    lengths: [<Hop Data Byte Length Number>]
    secrets: [<Hop Shared Secret Buffer Object>]
    size: <Hop Payloads Byte Length Number>
  }

  @throws
  <Error>

  @returns
  {
    filler: <Filler Buffer Object>
  }
*/
module.exports = ({lengths, secrets, size}) => {
  if (!isArray(lengths) || !lengths.length || !lengths.every(isLength)) {
    throw new Error('ExpectedHopDataLengthsToGenerateFiller');
  }

  if (!isArray(secrets) || secrets.length !== lengths.length) {
    throw new Error('ExpectedHopSharedSecretsToGenerateFiller');
  }

  if (!size) {
    throw new Error('ExpectedHopPayloadsSizeToGenerateFiller');
  }

  // The final hop does not add padding since it does not forward the packet
  const forwarding = lengths.slice(Number(), -1);

  const filler = alloc(sum(forwarding));

  const consumed = {bytes: Number()};

  forwarding.forEach((hopBytes, i) => {
    const {key} = deriveKey({secret: secrets[i], type: typeRhoKey});

    const {stream} = cipherStream({key, bytes: size * streamLengthMultiplier});

    // The padding added by this hop lands past the end of the payloads and is
    // shifted forward by the bytes that all prior hops have consumed
    const start = size - consumed.bytes;

    for (let j = Number(); j < consumed.bytes + hopBytes; j++) {
      filler[j] ^= stream[start + j];
    }

    consumed.bytes += hopBytes;
  });

  return {filler};
};
