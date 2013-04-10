var assert = require('assert');
var forge = require('forge');

var keyczar_util = require('./keyczar_util')

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
    var pubkey = forge.pki.publicKeyFromPem(pubkeyPem);
    var keyczarSerialized = keyczar_util.publicKeyToKeyczar(pubkey);
    var roundtripped = keyczar_util.publicKeyFromKeyczar(keyczarSerialized);

    // load the known private key; format it as a keyczar key
    var privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

    // Encrypt message with the key 
    var message = 'hello this is a message';
    var ciphertext = pubkey.encrypt(message);
    var decoded = privateKey.decrypt(ciphertext);
    assert.equal(decoded, message);

    // Encrypt it with the roundtripped public key
    ciphertext = roundtripped.encrypt(message);
    decoded = privateKey.decrypt(ciphertext);
    assert.equal(decoded, message);

    // Round trip the private key
    keyczarSerialized = keyczar_util.privateKeyToKeyczar(privateKey);
    roundtripped = keyczar_util.privateKeyFromKeyczar(keyczarSerialized);

    // decrypt the message with the roundtripped key
    decoded = roundtripped.decrypt(ciphertext);
    assert.equal(decoded, message);
}

testKeyczarConversion();
console.log('success');
