var assert = require('assert');
var forge = require('node-forge');

var keyczar_util = require('./keyczar_util');
var test_util = require('./test_util');

var pubkeyPem = '-----BEGIN PUBLIC KEY-----' +
'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCjvkkLWNTeYXqEsqGiVCW/pDt' +
'3/qAodNMHcU9gOU2rxeWwiRuOhhLqmMxXHLi0oP5Xmg0m7zdOiLMEyzzyRzdp21a' +
'qp3k5qtuSDkZcf1prsp1jpYm6z9EGpaSHb64BCuUsQGmUPKutd5RERKHGZXtiRuv' +
'vIyue7ETq6VjXrOUHQIDAQAB' +
'-----END PUBLIC KEY-----';

var privateKeyPem = '-----BEGIN RSA PRIVATE KEY-----' +
'MIICWwIBAAKBgQDCjvkkLWNTeYXqEsqGiVCW/pDt3/qAodNMHcU9gOU2rxeWwiRu' +
'OhhLqmMxXHLi0oP5Xmg0m7zdOiLMEyzzyRzdp21aqp3k5qtuSDkZcf1prsp1jpYm' +
'6z9EGpaSHb64BCuUsQGmUPKutd5RERKHGZXtiRuvvIyue7ETq6VjXrOUHQIDAQAB' +
'AoGAOKeBjTNaVRhyEnNeXkbmHNIMSfiK7aIx8VxJ71r1ZDMgX1oxWZe5M29uaxVM' +
'rxg2Lgt7tLYVDSa8s0hyMptBuBdy3TJUWruDx85uwCrWnMerCt/iKVBS22fv5vm0' +
'LEq/4gjgIVTZwgqbVxGsBlKcY2VzxAfYqYzU8EOZBeNhZdECQQDy+PJAPcUN2xOs' +
'6qy66S91x6y3vMjs900OeX4+bgT4VSVKmLpqRTPizzcL07tT4+Y+pAAOX6VstZvZ' +
'6iFDL5rPAkEAzP1+gaRczboKoJWKJt0uEMUmztcY9NXJFDmjVLqzKwKjcAoGgIal' +
'h+uBFT9VJ16QajC7KxTRLlarzmMvspItUwJAeUMNhEpPwm6ID1DADDi82wdgiALM' +
'NJfn+UVhYD8Ac//qsKQwxUDseFH6owh1AZVIIBMxg/rwUKUCt2tGVoW3uQJAIt6M' +
'Aml/D8+xtxc45NuC1n9y1oRoTl1/Ut1rFyKbD5nnS0upR3uf9LruvjqDtaq0Thvz' +
'+qQT4RoFJ5pfprSO2QJAdMkfNWRqECfAhZyQuUrapeWU3eQ0wjvktIynCIwiBDd2' +
'MfjmVXzBJhMk6dtINt+vBEITVQEOdtyTgDt0y3n2Lw==' +
'-----END RSA PRIVATE KEY-----';

function testKeyczarConversion() {
    // load a known public key; format it as a keyczar key
    var rsa = forge.pki.publicKeyFromPem(pubkeyPem);
    var keyczarSerialized = keyczar_util._rsaPublicKeyToKeyczarJson(rsa);
    var publicKey = keyczar_util.publicKeyFromKeyczar(keyczarSerialized);

    // load the known private key; format it as a keyczar key
    var rsa = forge.pki.privateKeyFromPem(privateKeyPem);
    keyczarSerialized = keyczar_util._rsaPrivateKeyToKeyczarJson(rsa);
    var privateKey = keyczar_util.privateKeyFromKeyczar(keyczarSerialized);

    // Encrypt message with the key 
    var message = 'hello this is a message';
    var ciphertext = publicKey.encrypt(message);
    var decoded = privateKey.decrypt(ciphertext);
    assert.equal(decoded, message);
}

function testBase64Url() {
    binary = '\x8co\xbf\xfd';
    keyczar_out = keyczar_util.encodeBase64Url(binary);
    assert.equal('jG-__Q', keyczar_out);
    keyczar_out = keyczar_util.decodeBase64Url(keyczar_out);
    assert.equal(binary, keyczar_out);

    assert.equal('a', keyczar_util.decodeBase64Url('YQ'));
    assert.equal('aa', keyczar_util.decodeBase64Url('YWE'));
    assert.equal('aaa', keyczar_util.decodeBase64Url('YWFh'));
    assert.equal('aaaa', keyczar_util.decodeBase64Url('YWFhYQ'));

    // invalid data (not enough bytes)
    assert.throws(function() {
        keyczar_util.decodeBase64Url('Y');
    });
}

var KEYCZAR_AES = '{"aesKeyString":"Fg9MqSniawfwlXb0BwvBfQ","hmacKey":{"hmacKeyString":"2UP8uP9UuHxjHnZyF3GxnJ-BIO0M-_5qYfQy2SvCZ9w","size":256},"mode":"CBC","size":128}';
function testAesKeyczarConversion() {
    var aes = keyczar_util.aesFromKeyczar(KEYCZAR_AES);

    // Roundtrip with the key
    var message = 'hello this is a message';
    var ciphertext = aes.encrypt(message);
    assert(ciphertext != message);
    var decoded = aes.decrypt(ciphertext);
    assert.equal(decoded, message);

    var roundtripped = keyczar_util.aesFromKeyczar(aes.toJson());
    assert.equal(message, roundtripped.decrypt(ciphertext));
    var ciphertext2 = roundtripped.encrypt(message);
    assert.equal(message, roundtripped.decrypt(ciphertext2));

    // original key can decrypt the roundtripped key's message
    assert.equal(message, aes.decrypt(ciphertext2));
}

function testBigEndianEncoding() {
    // round trip a random value
    assert.equal('\x00\x00\x00\x01', keyczar_util._encodeBigEndian(1));
    assert.equal('\x0c\xa8\xae\x3e', keyczar_util._encodeBigEndian(212381246));
    assert.equal(212381246, keyczar_util._decodeBigEndian('\x0c\xa8\xae\x3e'));

    // check limits
    assert.throws(function() {keyczar_util._encodeBigEndian(-1);});
    assert.throws(function() {keyczar_util._encodeBigEndian(2147483648);});
    assert.throws(function() {keyczar_util._decodeBigEndian('\x80\x00\x00\x00');});
    assert.throws(function() {keyczar_util._decodeBigEndian('\x00\x00\x00');});

    var assertRoundtrip = function(i) {
        var encoded = keyczar_util._encodeBigEndian(i);
        assert.equal(4, encoded.length);
        var roundtrip = keyczar_util._decodeBigEndian(encoded);
        assert.equal(i, roundtrip);
    };

    // round trip small integers
    for (var i = 0; i < 260; i++) {
        assertRoundtrip(i);
    }

    // round trip big integers
    var max = 2147483647;
    for (i = max - 260; i <= max; i++) {
        assertRoundtrip(i);
    }
}

function testPackByteStrings() {
    // test a known value
    var strings = ['a', 'bc'];
    var serialized = '\x00\x00\x00\x02\x00\x00\x00\x01a\x00\x00\x00\x02bc';
    assert.equal(serialized, keyczar_util._packByteStrings(strings));
    assert.deepEqual(strings, keyczar_util._unpackByteStrings(serialized));

    var roundtrip = function(l) {
        return keyczar_util._unpackByteStrings(keyczar_util._packByteStrings(l));
    };
    strings = [];
    assert.deepEqual(strings, roundtrip(strings));
    strings = ['\x00\x00\x00\x00', ''];
    assert.deepEqual(strings, roundtrip(strings));

    // test some errors
    assert.throws(function() {keyczar_util._unpackByteStrings('\x00\x00\x00\x02\x00\x00\x00\x01a\x00\x00\x00\x02b');});
    assert.throws(function() {keyczar_util._unpackByteStrings('\x00\x00\x00\x02\x00\x00\x00\x01a');});
    assert.throws(function() {keyczar_util._unpackByteStrings('\x00\x00\x00\x02\x00\x00');});
    assert.throws(function() {keyczar_util._unpackByteStrings('\x00\x00\x00');});
    assert.throws(function() {keyczar_util._packByteStrings([null]);});
    assert.throws(function() {keyczar_util._packByteStrings([undefined]);});
    assert.throws(function() {keyczar_util._packByteStrings([5]);});
}

test_util.runTests([testBase64Url, testKeyczarConversion, testAesKeyczarConversion,
    testBigEndianEncoding, testPackByteStrings]);
