var assert = require('assert');
var fs = require('fs');

var keyczar = require ('./keyczar');

function readTestData(name) {
    return fs.readFileSync('testdata/' + name, {encoding: 'utf-8'});
}

function testKeyczarRsa() {
    // decrypt the message as written by Java Keyczar
    var message = 'hello world message';
    var privatekey_json = readTestData('privatekey.json');
    var privatekey = keyczar.fromJson(privatekey_json);
    var encrypted = readTestData('privatekey_encrypted');
    var decrypted = privatekey.decrypt(encrypted);
    assert.equal(message, decrypted);

    // // round trip the message
    // var encrypted2 = privatekey.encrypt(message);
    // console.log(encrypted2);
    // assert(encrypted2 != encrypted);
    // decrypted = privatekey.decrypt(encrypted2);
    // assert.equal(message, decrypted);

    // // round trip the message using the public key
    // var publickey = keyczar.fromJson(readTestData('publickey.json'));
    // encrypted3 = privatekey.encrypt(message);
    // console.log(encrypted3);
    // assert.assert(encrypted3 != encrypted);
    // assert.assert(encrypted3 != encrypted2);
    // decrypted = privatekey.decrypt(encrypted3);
    // assert.equal(message, decrypted);
}

var tests = [testKeyczarRsa];
for (var i = 0; i < tests.length; i++) {
    tests[i]();
    console.log('.');
}
console.log('success');
