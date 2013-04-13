Keyczar JS
==========

A partial Javascript implementation of Google Keyczar (http://www.keyczar.org/)

Implemented using primitives from Forge (https://github.com/digitalbazaar/forge/)


Example use
-----------

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


Differences
-----------

* Reads and writes key sets as JSON strings. The structure is the same as
  Keyczar's directories, just as a JSON object.


Changes to Java Keyczar
-----------------------

In order to use Keyczar JS with Java Keyczar, we wrote some additional support
classes. Ideally we would like to push some changes upstream:

* Creating a new keyset without writing it to disk, and adding a key to it.
  Right now, this involves passing around a KeyczarReader, creating a
  GenericKeyczar to add keys, writing it out, then re-reading it to create a
  Crypter. WTF?
