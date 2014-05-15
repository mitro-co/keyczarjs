Keyczar JS
==========

A partial Javascript implementation of
[Google Keyczar](http://www.keyczar.org/).
It is a wrapper around the [Forge](https://github.com/digitalbazaar/forge/)
Javascript crypto library. Released under the Apache 2.0 license, like
the official Keyczar library.


Quick Start
-----------

1. Run `npm install` in the `keyczarjs` directory to download Forge using NPM.
2. Run `./runtests.sh` to run all the unit tests.
3. Open `browser_test.html` for an example of Keyczar JS in a web browser.
4. (OPTIONAL): Run `make` to run the Closure compiler to type check all JavaScript (you will probably need to editg the Makefile to provide the location of the Closure Compiler .jar file)


Example use (NodeJS)
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


Differences from the original Keyczar implementation
----------------------------------------------------

* Input is treated as a Javascript string (Unicode). It is encoded as UTF-8
  before encryption, and decoded back to a Javascript Unicode string after
  decryption. This can cause exceptions to be thrown if decrypting binary data
  that is not valid UTF-8. In this case, use `encryptBinary()`/`decryptBinary()`.

* Key sets are read and written as JSON strings. The structure is the same as
  Keyczar's directories, just as a JSON object.


Password-Protected Keys
-----------------------

KeyczarJS supports reading and writing keys that are encrypted by a password.
The format is compatible with the C++ implementation, which is based on
OpenSSL's password-based encryption.

To make it difficult to accidentally "leak" an unencrypted key, `toJson()`
does not work for password protected keys. Instead, you should use
`toJsonEncrypted()`. In rare cases where you must access the serialized key,
you can use `exportDecryptedJson()`.


Adding KeyczarJS to your project
--------------------------------

Each script in this package is usable both by NodeJS (`require()`) and in a
browser. In the browser, all exported functions are in the global `keyczar`
namespace. In a browser, you must load the following script files:

* From Forge: `aes.js sha1.js sha256.js md.js util.js prng.js random.js jsbn.js
  pbkdf2.js hmac.js asn1.js oids.js pkcs1.js rsa.js pki.js`
* From Keyczar JS: `keyczar_util.js keyczar.js`


Additions to Java Keyczar
-------------------------

To use Keyczar JS with Java Keyczar, we wrote some additional support
classes. Ideally we would like to push some changes upstream:

* Creating a new keyset without writing it to disk, and adding a key to it.
  Right now, this involves passing around a KeyczarReader, creating a
  GenericKeyczar to add keys, writing it out, then re-reading it to create a
  Crypter.
