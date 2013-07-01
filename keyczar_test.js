var assert = require('assert');
var fs = require('fs');

var keyczar = require('./keyczar');
var keyczar_util = require('./keyczar_util');
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
    var encrypted3 = publickey.encrypt(EXAMPLE_MESSAGE);
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
    var serializedKey = keyczar.fromJson(json);
    var encrypted = serializedKey.encrypt(EXAMPLE_MESSAGE);
    serializedKey = keyczar.fromJson(privateKey.toJson());
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
        size: 512
    };
    var privateKey = keyczar.create(
        keyczar.TYPE_RSA_PRIVATE, keyczar.PURPOSE_ENCRYPT_DECRYPT, options);
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

function testRawBinary() {
    var key = readKey('symmetric.json');
    // not base64 encoded
    var encrypted = key.encryptBinary(EXAMPLE_MESSAGE);
    assert.equal(0x00, encrypted.charCodeAt(0));
    var decrypted = key.decryptBinary(encrypted);
    assert.equal(EXAMPLE_MESSAGE, decrypted);

    // it must be possible to encrypt/decrypt this invalid utf-8 string: it
    // can be generated by Keyczar's session encryption
    key = readKey('symmetric_binary.json');
    encrypted = keyczar_util.decodeBase64Url(readTestData('symmetric_binary_encrypted'));
    decrypted = key.decryptBinary(encrypted);
    // '\x96' cannot be decoded from UTF-8: it is an invalid UTF-8 sequence
    assert.equal('\x96', decrypted.charAt(decrypted.length-1));
}

function testSession() {
    var publickey = readKey('publickey.json');
    var session = keyczar.createSessionCrypter(publickey);
    var ciphertext = session.encryptBinary(EXAMPLE_MESSAGE);
    var material = session.sessionMaterial;

    var privatekey = readKey('privatekey.json');
    session = keyczar.createSessionCrypter(privatekey, material);
    assert.equal(EXAMPLE_MESSAGE, session.decryptBinary(ciphertext));

    var longMessage = 'long message ';
    while (longMessage.length < 500) {
        longMessage += longMessage;
    }

    // repeat this multiple times to ensure random binary data passes through okay
    // this caught the invalid UTF-8 decoding bug
    for (var j = 0; j < 5; j++) {
        ciphertext = keyczar.encryptWithSession(publickey, longMessage);
        assert.equal(longMessage, keyczar.decryptWithSession(privatekey, ciphertext));
        process.stdout.write('!');
    }
}

function testStringEncoding() {
    var unicodeMessage = 'Emoji key: \ud83d\udd11';
    var key = readKey('symmetric.json');
    var encrypted = key.encrypt(unicodeMessage);
    assert.equal(unicodeMessage, key.decrypt(encrypted));

    // pass the unicode data through a session
    var privateKey = readKey('privatekey.json');
    encrypted = keyczar.encryptWithSession(privateKey, unicodeMessage);
    assert.equal(unicodeMessage, keyczar.decryptWithSession(privateKey, encrypted));

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
    versions: [{
        "exportable": false,
        "status": "PRIMARY",
        "versionNumber": 1
    }]
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

function testSigning() {
    // private key can sign and verify
    var key = keyczar.fromJson(readTestData('privatekey_sign.json'));
    var signature = readTestData('privatekey_sign_signed');
    assert(key.verify(EXAMPLE_MESSAGE, signature));

    // simple RSA signatures are deterministic (no random padding)
    assert.equal(signature, key.sign(EXAMPLE_MESSAGE));

    // public key can verify
    var publicKey = keyczar.fromJson(readTestData('publickey_sign.json'));
    assert(publicKey.verify(EXAMPLE_MESSAGE, signature));

    // round trip the keys
    key = keyczar.fromJson(key.toJson());
    assert.equal(signature, key.sign(EXAMPLE_MESSAGE));
    publicKey = keyczar.fromJson(publicKey.toJson());
    assert(publicKey.verify(EXAMPLE_MESSAGE, signature));

    // generate a key
    var options = {
        size: 512
    };
    key = keyczar.create(keyczar.TYPE_RSA_PRIVATE, keyczar.PURPOSE_SIGN_VERIFY, options);
    signature = key.sign(EXAMPLE_MESSAGE);
    publicKey = keyczar.fromJson(key.exportPublicKey().toJson());
    assert(publicKey.verify(EXAMPLE_MESSAGE, signature));

    // test encrypting the signing key
    var encrypted = key.toJsonEncrypted('password');
    var decrypted = keyczar.fromJson(encrypted, 'password');
    assert.equal(signature, decrypted.sign(EXAMPLE_MESSAGE));
}

test_util.runTests([testKeyczarRsa, testEncryptAllBytes, testSerializeKeys, testMaxLengthData,
    testMakeExportRsa, testSymmetric, testRawBinary, testSession, testStringEncoding,
    testEncryptedKey, testSigning]);
