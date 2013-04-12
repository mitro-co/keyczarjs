var assert = require('assert');
var fs = require('fs');

var keyczar = require('./keyczar');

function readTestData(name) {
    return fs.readFileSync('testdata/' + name, {encoding: 'utf-8'});
}

function loadPrivateKey() {
    return keyczar.fromJson(readTestData('privatekey.json'));
}

// the message as written by Java Keyczar
var EXAMPLE_MESSAGE = 'hello world message';

function testKeyczarRsa() {
    var privatekey = loadPrivateKey();
    var encrypted = readTestData('privatekey_encrypted');
    var decrypted = privatekey.decrypt(encrypted);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    // round trip the message
    var encrypted2 = privatekey.encrypt(EXAMPLE_MESSAGE);
    assert(encrypted2 != encrypted);
    decrypted = privatekey.decrypt(encrypted2);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    // round trip the message using the public key
    var publickey = keyczar.fromJson(readTestData('publickey.json'));
    encrypted3 = privatekey.encrypt(EXAMPLE_MESSAGE);
    // there is a very small probability these will be the same; if the same seed is generated
    assert(encrypted3 != encrypted);
    assert(encrypted3 != encrypted2);
    decrypted = privatekey.decrypt(encrypted3);
    assert.equal(EXAMPLE_MESSAGE, decrypted);
}

// Round trip every possible byte to ensure JS encoding doesn't screw things up
function testEncryptAllBytes() {
    message = ''
    for (var i = 0; i < 256; i++) {
        message += String.fromCharCode(i);
    }
    assert.equal(256, message.length);

    var privateKey = loadPrivateKey();
    assert.equal(message, privateKey.decrypt(privateKey.encrypt(message)));
}

function testSerializeKeys() {
    // round trip the keys to/from JSON
    var privateKey = loadPrivateKey();
    var publicKey = keyczar.exportPublicKey(privateKey);

    var json = publicKey.toJson();
    serializedKey = keyczar.fromJson(json);
    encrypted = serializedKey.encrypt(EXAMPLE_MESSAGE);
    var serializedKey = keyczar.fromJson(privateKey.toJson());
    assert.equal(EXAMPLE_MESSAGE, serializedKey.decrypt(encrypted));
}

function testMaxLengthData() {
    var privateKey = loadPrivateKey();

    // Round trip maximum length data
    var maxEncryptLength = Math.ceil(privateKey.primary.n.bitLength() / 8) - 2 * 20 - 2;
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
    var privateKey = keyczar.create(options);
    var publicKey = keyczar.exportPublicKey(privateKey);

    // Test round tripping using the exported key
    var encrypted = publicKey.encrypt(EXAMPLE_MESSAGE);
    assert.equal(EXAMPLE_MESSAGE, privateKey.decrypt(encrypted));
}

var tests = [testKeyczarRsa, testEncryptAllBytes, testSerializeKeys, testMaxLengthData, testMakeExportRsa];
for (var i = 0; i < tests.length; i++) {
    tests[i]();
    process.stdout.write('.');
}
console.log('success');
