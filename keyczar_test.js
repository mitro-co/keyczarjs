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
    decrypted = key.decrypt(encrypted);
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

test_util.runTests([testKeyczarRsa, testEncryptAllBytes, testSerializeKeys, testMaxLengthData,
    testMakeExportRsa, testSymmetric, testRaw]);
