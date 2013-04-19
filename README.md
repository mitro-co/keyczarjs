Keyczar JS
==========

A partial Javascript implementation of Google Keyczar (http://www.keyczar.org/)

Implemented using primitives from Forge (https://github.com/digitalbazaar/forge/)


Example use (Node)
------------------

```javascript
var keyczar = require('./keyczar');

// Create a new keyset and serialize it
var keyset = keyczar.create(keyczar.TYPE_AES);
var keysetSerialized = keyset.toJson();

// Load the keyset and use it
var plaintext = 'hello message';
keyset = keyczar.fromJson(keysetSerialized);
var encrypted = keyset.encrypt(plaintext);
var decrypted = keyset.decrypt(encrypted);
console.log('plaintext:', plaintext);
console.log('encrypted:', encrypted);
console.log('decrypted:', decrypted);

// Create an asymmetric key
var private = keyczar.create(keyczar.TYPE_RSA_PRIVATE);
var public = private.exportPublicKey();
var privateSerialized = private.toJson();

// encrypt some data in a "session" to avoid asymmetric length limits
var session = keyczar.createSessionCrypter(public);
encrypted = session.encrypt(plaintext);
var sessionMaterial = session.sessionMaterial;

// take the private key and the session material to decrypt the data
private = keyczar.fromJson(privateSerialized);
session = keyczar.createSessionCrypter(private, sessionMaterial);
decrypted = session.decrypt(encrypted);
console.log('plaintext:', plaintext);
console.log('sessionMaterial:', sessionMaterial);
console.log('encrypted:', encrypted);
console.log('decrypted:', decrypted);

// convenience method to pack session material together with the message
encrypted = keyczar.encryptWithSession(public, plaintext);
decrypted = keyczar.decryptWithSession(private, encrypted);
console.log('plaintext:', plaintext);
console.log('encrypted:', encrypted);
console.log('decrypted:', decrypted);
```


Using KeyczarJS
-------------------------

Each script in this package is defined to be usable both by node's require()
statement and in a browser. In the browser, it creates a global keyczar
namespace for all the exported functions. In a browser, you must load the
following script files:

* Forge: rsa.js asn1.js oids.js pki.js jsbn.js util.js sha1.js prng.js aes.js
  random.js
* Keyczar: keyczar_util.js aes_oaep.js keyczar.js


Differences
-----------

* Reads and writes key sets as JSON strings. The structure is the same as
  Keyczar's directories, just as a JSON object.


Additions to Java Keyczar
-------------------------

To use Keyczar JS with Java Keyczar, we wrote some additional support
classes. Ideally we would like to push some changes upstream:

* Creating a new keyset without writing it to disk, and adding a key to it.
  Right now, this involves passing around a KeyczarReader, creating a
  GenericKeyczar to add keys, writing it out, then re-reading it to create a
  Crypter. WTF?
