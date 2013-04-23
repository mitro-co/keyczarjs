var assert = require('assert');
var fs = require('fs');

var keyczar = require('./keyczar');
var test_util = require('./test_util');

function readTestData(name) {
    return fs.readFileSync('testdata/' + name, {encoding: 'utf-8'});
}

function readKey(name) {
    return keyczar.fromJson(readTestData(name));
}

// the message as written by Java Keyczar
var EXAMPLE_MESSAGE = 'hello world message';

function testKeyczarRsa() {
    var privatekey = readKey('privatekey.json');
    var encrypted = readTestData('privatekey_encrypted');
    var decrypted = privatekey.decrypt(encrypted);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    // round trip the message
    var encrypted2 = privatekey.encrypt(EXAMPLE_MESSAGE);
    assert(encrypted2 != encrypted);
    decrypted = privatekey.decrypt(encrypted2);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    // round trip the message using the public key
    var publickey = readKey('publickey.json');
    encrypted3 = publickey.encrypt(EXAMPLE_MESSAGE);
    // there is a very small probability these will be the same; if the same seed is generated
    assert(encrypted3 != encrypted);
    assert(encrypted3 != encrypted2);
    decrypted = privatekey.decrypt(encrypted3);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    assert.throws(function() { publickey.decrypt(encrypted3); }, TypeError);
}

// Round trip every possible byte to ensure JS encoding doesn't screw things up
function testEncryptAllBytes() {
    var message = '';
    for (var i = 0; i < 256; i++) {
        message += String.fromCharCode(i);
    }
    assert.equal(256, message.length);

    var privateKey = readKey('privatekey.json');
    assert.equal(message, privateKey.decrypt(privateKey.encrypt(message)));
}

function testSerializeKeys() {
    // round trip the keys to/from JSON
    var privateKey = readKey('privatekey.json');
    var publicKey = privateKey.exportPublicKey();

    var json = publicKey.toJson();
    serializedKey = keyczar.fromJson(json);
    encrypted = serializedKey.encrypt(EXAMPLE_MESSAGE);
    var serializedKey = keyczar.fromJson(privateKey.toJson());
    assert.equal(EXAMPLE_MESSAGE, serializedKey.decrypt(encrypted));
}

function testMaxLengthData() {
    var privateKey = readKey('privatekey.json');

    // Round trip maximum length data
    var maxEncryptLength = Math.ceil(privateKey.primary.size / 8) - 2 * 20 - 2;
    var maxLengthData = '';
    for (var i = 0; i < maxEncryptLength; i++) {
        maxLengthData += 'a';
    }
    var encrypted = privateKey.encrypt(maxLengthData);
    assert.equal(maxLengthData, privateKey.decrypt(encrypted));

    // any extra byte should throw
    assert.throws(function() { privateKey.encrypt(maxLengthData + 'a'); });
}

function testMakeExportRsa() {
    // generate a small key to make this fast
    var options = {
        size: 1024
    };
    var privateKey = keyczar.create(keyczar.TYPE_RSA_PRIVATE, options);
    assert.equal(keyczar.TYPE_RSA_PRIVATE, privateKey.metadata.type);
    var publicKey = privateKey.exportPublicKey();
    assert.equal(keyczar.TYPE_RSA_PUBLIC, publicKey.metadata.type);

    // Test round tripping using the exported key
    var encrypted = publicKey.encrypt(EXAMPLE_MESSAGE);
    assert.equal(EXAMPLE_MESSAGE, privateKey.decrypt(encrypted));
}

function testSymmetric() {
    var key = readKey('symmetric.json');
    var encrypted = readTestData('symmetric_encrypted');
    var decrypted = key.decrypt(encrypted);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    var encrypted2 = key.encrypt(EXAMPLE_MESSAGE);
    decrypted = key.decrypt(encrypted2);
    assert(encrypted2 != encrypted);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    // round trip the key
    key = keyczar.fromJson(key.toJson());
    var encrypted3 = key.encrypt(EXAMPLE_MESSAGE);
    assert.equal(EXAMPLE_MESSAGE, key.decrypt(encrypted));
    assert.equal(EXAMPLE_MESSAGE, key.decrypt(encrypted2));
    assert.equal(EXAMPLE_MESSAGE, key.decrypt(encrypted3));

    // create a new key
    key = keyczar.create(keyczar.TYPE_AES);
    assert.equal(keyczar.TYPE_AES, key.metadata.type);
    encrypted = key.encrypt(EXAMPLE_MESSAGE);
    assert.equal(EXAMPLE_MESSAGE, key.decrypt(encrypted));
}

function testRaw() {
    var key = readKey('symmetric.json');
    // not base64 encoded
    var encrypted = key.encrypt(EXAMPLE_MESSAGE, null);
    assert.equal(0x00, encrypted.charCodeAt(0));
    var decrypted = key.decrypt(encrypted, null);
    assert.equal(EXAMPLE_MESSAGE, decrypted);
}

function testSession() {
    var publickey = readKey('publickey.json');
    var session = keyczar.createSessionCrypter(publickey);
    var ciphertext = session.encrypt(EXAMPLE_MESSAGE);
    var material = session.sessionMaterial;

    var privatekey = readKey('privatekey.json');
    session = keyczar.createSessionCrypter(privatekey, material);
    assert.equal(EXAMPLE_MESSAGE, session.decrypt(ciphertext));

    var longMessage = 'long message ';
    for (var i = 0; i < 6; i++) {
        longMessage += longMessage;
    }
    assert(longMessage.length > 500);
    ciphertext = keyczar.encryptWithSession(publickey, longMessage);
    assert.equal(longMessage, keyczar.decryptWithSession(privatekey, ciphertext));
}

function testStringEncoding() {
    var unicodeMessage = 'Emoji key: \ud83d\udd11';
    var key = readKey('symmetric.json');
    var encrypted = key.encrypt(unicodeMessage);
    assert.equal(unicodeMessage, key.decrypt(encrypted));

    var binaryMessage = '';
    for (var i = 0; i < 256; i++) {
        binaryMessage += String.fromCharCode(i);
    }
    encrypted = key.encrypt(binaryMessage);
    assert.equal(binaryMessage, key.decrypt(encrypted));
}

var ENCRYPTED_KEYCZAR = {
   encrypted: true,
   name: "Test",
   purpose: "DECRYPT_AND_ENCRYPT",
   type: "AES",
   versions: [ {
      "exportable": false,
      "status": "PRIMARY",
      "versionNumber": 1
   } ]
};

var ENCRYPTED_JSON = {
    "cipher": "AES128",
    "hmac": "HMAC_SHA1",
    "iterationCount": 4096,
    "iv": "z3BdMSyqfrh-qmv1YLXvFg",
    "key": "ZoavQvg_IRDGG57NQIn4kjuBRyRsX3p6JPWX1jnNUBtUQyAHTd381CzKyqOZIIVt8nIkkzdN3JjtTyYMQSEE9ZTVZ_RVC1enTzLZuEL5gZCbmJyRzX1eBdpTN1bFbIt3aOMiFxjFzP-O67ErGnUHpBHmmCxmau-MBUpCd6Su-eum3SIERsaMzsMDEcivCrd5SW20HokMWCxu_GImVxyQuA",
    "salt": "EwDMYR65XcUmvggvoW1GMw"
};

function testEncryptedKey() {
    var encryptedKey = JSON.stringify({
        "1": JSON.stringify(ENCRYPTED_JSON),
        "meta": JSON.stringify(ENCRYPTED_KEYCZAR)
    });

    assert.throws(function() { keyczar.fromJson(encryptedKey); });

    // TODO: test round tripping this to/from Java
    var decryptedKey = keyczar.fromJson(encryptedKey, "pass");
    assert.equal('hello', decryptedKey.decrypt(decryptedKey.encrypt('hello')));
    assert.throws(function() { decryptedKey.toJson(); });

    var key = keyczar.create(keyczar.TYPE_AES);
    var encryptedKey2 = key.toJsonEncrypted('hellopassword');
    assert.throws(function() { keyczar.fromJson(encryptedKey2); });
    var key2 = keyczar.fromJson(encryptedKey2, 'hellopassword');
    assert(key2.metadata.encrypted);
    assert.equal('hello', key2.decrypt(key.encrypt('hello')));
    assert.throws(function() { key2.toJson(); });
}

test_util.runTests([testKeyczarRsa, testEncryptAllBytes, testSerializeKeys, testMaxLengthData,
    testMakeExportRsa, testSymmetric, testRaw, testSession, testStringEncoding, testEncryptedKey]);
