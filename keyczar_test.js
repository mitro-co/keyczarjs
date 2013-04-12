var assert = require('assert');
var fs = require('fs');

var keyczar = require('./keyczar');

function readTestData(name) {
    return fs.readFileSync('testdata/' + name, {encoding: 'utf-8'});
}

function loadPrivateKey() {
    return keyczar.fromJson(readTestData('privatekey.json'));
}

function testKeyczarRsa() {
    // decrypt the message as written by Java Keyczar
    var message = 'hello world message';
    var privatekey = loadPrivateKey();
    var encrypted = readTestData('privatekey_encrypted');
    var decrypted = privatekey.decrypt(encrypted);
    assert.equal(message, decrypted);

    // round trip the message
    var encrypted2 = privatekey.encrypt(message);
    assert(encrypted2 != encrypted);
    decrypted = privatekey.decrypt(encrypted2);
    assert.equal(message, decrypted);

    // round trip the message using the public key
    var publickey = keyczar.fromJson(readTestData('publickey.json'));
    encrypted3 = privatekey.encrypt(message);
    // there is a very small probability these will be the same; if the same seed is generated
    assert(encrypted3 != encrypted);
    assert(encrypted3 != encrypted2);
    decrypted = privatekey.decrypt(encrypted3);
    assert.equal(message, decrypted);

    // round trip the keys to/from JSON
    // serializedKey = keyczar.fromJson(publickey.toJson());
    // encrypted = serializedKey.encrypt(message);
    // var serializedKey = keyczar.fromJson(privatekey.toJson());
    // assert.equal(message, serializedKey.decrypt(encrypted));
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
    var message = 'sample \x00 message';
    var encrypted = publicKey.encrypt(message);
    assert.equal(message, privateKey.decrypt(encrypted));
}

var tests = [testKeyczarRsa, testMaxLengthData, testMakeExportRsa];
for (var i = 0; i < tests.length; i++) {
    tests[i]();
    process.stdout.write('.');
}
console.log('success');
