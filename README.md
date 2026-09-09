# BOLT04

Utilities for working with Lightning Network [BOLT 04](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)

## Methods

- [blindedPathFromHops](#blindedpathfromhops) - Blind a path of nodes to a
    destination that ends with a path id
- [decryptBlindedPath](#decryptblindedpath) - Decrypt the data of a hop in a
    blinded path
- [onionForPath](#onionforpath) - Construct an onion message packet to send
    into a published blinded path

### blindedPathFromHops

Create a blinded path from a series of hops to a destination

The final hop is the destination, which is given a path `id` for reference.

    {
      hops: [<Relaying Node Public Key Id Hex String>]
      [id]: <Path Identifier Hex String>
    }

    @throws
    <Error>

    @returns
    {
      id: <Path Identifier Hex String>
      key: <Path Key Hex String>
      path: [{
        encrypted_data: <Encrypted Data Hex String>
        relay_key: <Blinded Node Public Key Hex String>
      }]
    }

Example:

```node
const {blindedPathFromHops} = require('bolt04');

// Blind a path through a forwarding node to the destination with a path id
const {id, key, path} = blindedPathFromHops({
  hops: [forwardingNodePublicKey, destinationNodePublicKey],
});
```

### decryptBlindedPath

Decrypt the data of a hop in a blinded path

`secret` is a shared secret computed from the node identity and the path key

`features` are a total whitelist of feature bits allowed on the path

    {
      encrypted: <Encrypted Data Hex String>
      key: <Path Key Public Key Hex String>
      secret: <Path Key Shared Secret Hex String>
    }

    @throws
    <Error>

    @returns
    {
      data: <Decrypted Data TLV Stream Hex String>
      features: [<Allowed Feature Bit Number>]
      [id]: <Path Identifier Hex String>
      [next_channel_id]: <Next Hop Standard Format Channel Id String>
      [next_node_id]: <Next Node Public Key Hex String>
      next_path_key: <Next Hop Path Key Public Key Hex String>
      records: [{
        type: <Record Type Number String>
        value: <Record Value Hex String>
      }]
    }

Example:

```node
const {decryptBlindedPath} = require('bolt04');

// The node derives the shared secret with the path key using its private key
const {secret} = await ecdh({public_key: receivedPathKey});

// A forwarding hop forwards to the next node id with the next path key
const {id, next_node_id, next_path_key} = decryptBlindedPath({
  encrypted: encryptedRecipientData,
  key: receivedPathKey,
  secret,
});
```

### onionForPath

Create an onion for a given path

`inbound` are the blinded hops of the published blinded path

`outbound` are nodes to reach the blinded path, ending with its introduction

`records` are added to the payload of the final hop

`reply` is a route back to the sender that ends with the sender's node id

Send the `onion` to the first `outbound` node with the path's `key`

    {
      inbound: [{
        encrypted_data: <Encrypted Data Hex String>
        relay_key: <Blinded Relaying Public Key Into Destination Hex String>
      }]
      key: <Inbound Path Key Public Key Hex String>
      outbound: [<Relaying Node Public Key Out of Source Hex String>]
      [records]: [{
        type: <Final Hop Additional Record Type Number String>
        value: <Final Hop Additional Record Value Hex String>
      }]
      [reply]: [<Reply Path Relaying Node Public Key Back To Sender Hex String>]
      [secret]: <Outbound Path Key Secret Private Key Hex String>
    }

    @throws
    <Error>

    @returns
    {
      [id]: <Reply Path Identifier Hex String>
      key: <Path Key To Send With Onion Public Key Hex String>
      onion: <Onion Packet Hex String>
    }

Example:

```node
const {onionForPath} = require('bolt04');

// Send through a relaying peer into a published blinded path with a message,
// with a reply path back through the relaying peer to get an answer over
const {id, key, onion} = onionForPath({
  inbound: publishedHops.map(hop => ({
    encrypted_data: hop.encrypted_data,
    relay_key: hop.blinded_public_key,
  })),
  key: publishedFirstPathKey,
  outbound: [relayingPeerPublicKey, publishedFirstNodeId],
  records: [{type: '65537', value: message}],
  reply: [relayingPeerPublicKey, ownPublicKey],
});
```
