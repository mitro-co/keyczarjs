var assert = require('assert');
var forge = require('forge');

assert.equal('hello', 'hello');

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


/** Copied from forge.pki.js because it is not public */
var _bnToBytes = function(b) {
  // prepend 0x00 if first byte >= 0x80
  var hex = b.toString(16);
  if(hex[0] >= '8') {
    hex = '00' + hex;
  }
  return forge.util.hexToBytes(hex);
};

function _bnToBase64(b) {
    return forge.util.encode64(_bnToBytes(b));
}

function _publicKeyToKeyczarJson(key) {
    return {
        modulus: _bnToBase64(key.n),
        publicExponent: _bnToBase64(key.e),
        size: key.n.bitLength()
    };
}

function publicKeyToKeyczar(key) {
    return JSON.stringify(_publicKeyToKeyczarJson(key));
}

function _base64ToBn(s) {
    var decoded = forge.util.decode64(s);
    var buffer = forge.util.createBuffer(decoded);
    var hex = buffer.toHex();
    return new BigInteger(hex, 16);
}

function publicKeyFromKeyczar(serialized) {
    var obj = JSON.parse(serialized);
    var modulus = _base64ToBn(obj.modulus);
    var exponent = _base64ToBn(obj.publicExponent);
    return forge.pki.setRsaPublicKey(modulus, exponent);
}

function privateKeyToKeyczar(key) {
    var obj = {
        publicKey: _publicKeyToKeyczarJson(key),

        privateExponent: _bnToBase64(key.d),
        primeP: _bnToBase64(key.p),
        primeQ: _bnToBase64(key.q),
        primeExponentP: _bnToBase64(key.dP),
        primeExponentQ: _bnToBase64(key.dQ),
        crtCoefficient: _bnToBase64(key.qInv),

        size: key.q.bitLength() + key.p.bitLength()
    };

    if (obj.size != obj.publicKey.size) {
        throw "Incorrect calculation of private key size? " + obj.size + " != " + obj.publicKey.size;
    }

    return JSON.stringify(obj);
}

function privateKeyFromKeyczar(serialized) {
    obj = JSON.parse(serialized);

    // public key parts
    var n = _base64ToBn(obj.publicKey.modulus);
    var e = _base64ToBn(obj.publicKey.publicExponent);

    // private key parts
    var d = _base64ToBn(obj.privateExponent);
    var p = _base64ToBn(obj.primeP);
    var q = _base64ToBn(obj.primeQ);
    var dP = _base64ToBn(obj.primeExponentP);
    var dQ = _base64ToBn(obj.primeExponentQ);
    var qInv = _base64ToBn(obj.crtCoefficient);

    return forge.pki.setRsaPrivateKey(n, e, d, p, q, dP, dQ, qInv);
}

// RSA OAEP implementation based on
// https://github.com/davedoesdev/jsjws/commit/4a2d8958c82100bf0fecfda9933bb399a83b8b14
// http://webrsa.cvs.sourceforge.net/viewvc/webrsa/Client/RSAES-OAEP.js?content-type=text%2Fplain
// See http://www.rsa.com/rsalabs/node.asp?id=2125

// RSAES-OAEP-ENCRYPT message (M), with optional label (L)
function rsa_es_oaep_encrypt(key, message, label, seed) {
    // hash function hard-coded to SHA-1
    var md = forge.md.sha1.create();

    // length check
    var keyLength = key.n.bitLength() / 8;
    var maxLength = keyLength - 2 * md.digestLength - 2;
    if (message.length > maxLength) {
        throw "input message too long (max: " + maxLength +
                " message: " + message.length + ")";
    }

    if (!label) label = '';
    md.update(label);
    var lHash = md.digest();

    var PS = '';
    var PS_length = maxLength - message.length;
    for (var i = 0; i < PS_length; i++) {
        PS += '\x00';
    }
    // console.log(JSON.stringify(PS));

    var DB = lHash.getBytes() + PS + '\x01' + message;

    if (!seed) {
        seed = forge.random.getBytes(md.digestLength);
    } else if (seed.length != md.digestLength) {
        throw "Invalid seed";
    }

    var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, md);
    var maskedDB = xorString(DB, dbMask);

    var seedMask = rsa_mgf1(maskedDB, md.digestLength, md);
    var maskedSeed = xorString(seed, seedMask);

    var EM = '\x00' + maskedSeed + maskedDB;

    // true = public key; do not pad
    var C = forge.pki.rsa.encrypt(EM, key, true);
    return C;
}

function xorString(string1, string2) {
    if (string1.length != string2.length) {
        throw "mismatched string lengths: "+  string1.length + ", " + string2.length;
    }

    var out = '';
    for (i = 0; i < string1.length; i++) {
        out += String.fromCharCode(string1.charCodeAt(i) ^ string2.charCodeAt(i));
    }
    return out;
}

function rsa_mgf1(seed, maskLength, hash) {
   var t = '';
   var count = Math.ceil(maskLength / hash.digestLength);
   for (var i = 0; i < count; i++) {
      c = String.fromCharCode((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
      hash.start();
      hash.update(seed + c);
      t += hash.digest().getBytes();
   }

   return t.substring(0, maskLength);
}

function testKeyczarConversion() {
    // load a known public key; format it as a keyczar key
    var pubkey = forge.pki.publicKeyFromPem(pubkeyPem);
    var keyczarSerialized = publicKeyToKeyczar(pubkey);
    var roundtripped = publicKeyFromKeyczar(keyczarSerialized);

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
    keyczarSerialized = privateKeyToKeyczar(privateKey);
    roundtripped = privateKeyFromKeyczar(keyczarSerialized);

    // decrypt the message with the roundtripped key
    decoded = roundtripped.decrypt(ciphertext);
    assert.equal(decoded, message);
}

function testOAEP() {
    var modulus = _base64ToBn('qLOyhK+OtQs4cDSoYPFGxJGfMYdjzWxVmMiuSBGh4KvEx+CwgtaTpef87Wdc9GaFEncsDLxkp0LGxjD1M8jMcvYq6DPEC/JYQumEu3i9v5fAEH1VvbZi9cTg+rmEXLUUjvc5LdOq/5OuHmtme7PUJHYW1PW6ENTP0ibeiNOfFvs=');
    var exponent = _base64ToBn('AQAB');
    var pubkey = forge.pki.setRsaPublicKey(modulus, exponent);

    // RSA's test vector 1.1
    var message = forge.util.decode64('ZigZThIHPbA7qUzanvlTI5fVDbp5uYcASv7+NA==');
    var seed = forge.util.decode64('GLd26iEGnWl3ajPpa61I4d2gpe8=');
    var expected = 'NU/me0oSbV01/jbHd3kaP3uhPe9ITi05CK/3IvrUaPshaW3pXQvpEcLTF0+K/MIBA197bY5pQC3lRRYYwhpTX6nXv8W43Z/CQ/jPkn2zEyLW6IHqqRqZYXDmV6BaJmQm2YyIAD+Ed8EicJSg2foejEAkMJzh7My1IQA11HrHLoo=';

    var ciphertext = rsa_es_oaep_encrypt(pubkey, message, '', seed);
    assert.equal(expected, forge.util.encode64(ciphertext));
}

var tests = [testKeyczarConversion, testOAEP];

for (var i = 0; i < tests.length; i++) {
    tests[i]();
    console.log('.');
}
console.log('success');
