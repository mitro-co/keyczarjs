var forge = require('forge');

var rsa_oaep = require('./rsa_oaep');

var KEYHASH_LENGTH = 4;
var MODE_CBC = 'CBC';

var VERSION_BYTE = '\x00';

// Unpacks Keyczar's output format
function _unpackOutput(message) {
    if (message.charAt(0) != VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + message.charCodeAt(0));
    }

    keyhash = message.substr(1, KEYHASH_LENGTH);
    message = message.substr(1 + KEYHASH_LENGTH);
    return {keyhash: keyhash, message: message};
}

function _packOutput(keyhash, message) {
    if (keyhash.length != KEYHASH_LENGTH) {
        throw new Error('Invalid keyhash length: ' + keyhash.length);
    }

    return VERSION_BYTE + keyhash + message;
}

function _checkKeyHash(keyhash, unpackedMessage) {
    if (unpackedMessage.keyhash != keyhash) {
        var primaryHex = forge.util.bytesToHex(keyhash);
        var actualHex = forge.util.bytesToHex(unpackedMessage.keyhash);
        throw new Error('Mismatched keyhash (primary: ' +
            primaryHex + ' actual: ' + actualHex + ')');
    }
}

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
    return encodeBase64Url(_bnToBytes(b));
}

// Hack to support URL-safe base64 (base64url) from:
// http://tools.ietf.org/html/rfc4648
// TODO: Directly encode/decode this alphabet instead of search and replacing?
// TODO: Patch Forge to use window.btoa/atob if available?
function decodeBase64Url(message) {
    message = message.replace(/-/g, '+').replace(/_/g, '/');

    // Add missing padding (=): 3 bytes of padding is an error, but if
    // length % 4 == 1, add 3 bytes of padding; the error is caught later
    var padding = '!!==';
    var remainder_bytes = message.length % 4;
    if (remainder_bytes > 0) {
        if (remainder_bytes == 1) {
            throw new Error("Invalid base64: incorrect input length");
        }
        message += padding.substring(remainder_bytes);
    }

    return forge.util.decode64(message);
}

function encodeBase64Url(message) {
    message = forge.util.encode64(message);

    // remove padding
    var endIndex = message.length-1;
    while (message.charAt(endIndex) == '=') {
        endIndex -= 1;
    }
    message = message.substring(0, endIndex+1);

    return message.replace(/\+/g, '-').replace(/\//g, '_');
}

function _stripLeadingZeros(bytes) {
    var nonZeroIndex = 0;
    while (nonZeroIndex < bytes.length && bytes.charAt(nonZeroIndex) == '\x00') {
        nonZeroIndex += 1;
    }
    return bytes.substring(nonZeroIndex);
}

function _encodeBigEndian(number) {
    b1 = String.fromCharCode((number >> 24) & 0xff);
    b2 = String.fromCharCode((number >> 16) & 0xff);
    b3 = String.fromCharCode((number >> 8) & 0xff);
    b4 = String.fromCharCode(number & 0xff);
    return b1 + b2 + b3 + b4;
}

function _hashBigNumber(md, bigNumber) {
    var bytes = _bnToBytes(bigNumber);
    bytes = _stripLeadingZeros(bytes);

    md.update(_encodeBigEndian(bytes.length));
    md.update(bytes);
}

// Returns the keyhash for an RSA public key.
function _rsaHash(publicKey) {
    var md = forge.md.sha1.create();

    // hash:
    // 4-byte big endian length
    // "magnitude" of the public modulus (trim all leading zero bytes)
    // same for the exponent
    _hashBigNumber(md, publicKey.n);
    _hashBigNumber(md, publicKey.e);
    var digest = md.digest();
    return digest.data.substring(0, KEYHASH_LENGTH);
}

function _rsaPublicKeyToKeyczarObject(publicKey) {
    return {
        modulus: _bnToBase64(publicKey.n),
        publicExponent: _bnToBase64(publicKey.e),
        size: publicKey.n.bitLength()
    };
}

// Returns the JSON string representing publicKey in Keyczar's format.
function _rsaPublicKeyToKeyczarJson(publicKey) {
    var obj = _rsaPublicKeyToKeyczarObject(publicKey);
    return JSON.stringify(obj);
}

function _bytesToBigInteger(bytes) {
    var buffer = forge.util.createBuffer(bytes);
    var hex = buffer.toHex();
    return new BigInteger(hex, 16);
}

function _base64ToBn(s) {
    var decoded = decodeBase64Url(s);
    return _bytesToBigInteger(decoded);
}

function _privateKeyToKeyczarObject(key) {
    var obj = {
        publicKey: _rsaPublicKeyToKeyczarObject(key),

        privateExponent: _bnToBase64(key.d),
        primeP: _bnToBase64(key.p),
        primeQ: _bnToBase64(key.q),
        primeExponentP: _bnToBase64(key.dP),
        primeExponentQ: _bnToBase64(key.dQ),
        crtCoefficient: _bnToBase64(key.qInv),

        size: key.q.bitLength() + key.p.bitLength()
    };

    if (obj.size != obj.publicKey.size) {
        throw new Error("Incorrect calculation of private key size? " + obj.size + " != " + obj.publicKey.size);
    }

    return obj;
}

function _rsaPrivateKeyToKeyczarJson(key) {
    var obj = _privateKeyToKeyczarObject(key);
    return JSON.stringify(obj);
}

// Returns a key object for an RSA key.
function _makeRsaKey(rsaKey) {
    var key = {
        keyhash: _rsaHash(rsaKey),
        size: rsaKey.n.bitLength()
    };

    key.encrypt = function(plaintext) {
        ciphertext = rsa_oaep.rsa_oaep_encrypt(rsaKey, plaintext);
        return _packOutput(key.keyhash, ciphertext);
    };
    return key;
}

function publicKeyFromKeyczar(serialized) {
    var obj = JSON.parse(serialized);
    var modulus = _base64ToBn(obj.modulus);
    var exponent = _base64ToBn(obj.publicExponent);
    var rsaKey = forge.pki.setRsaPublicKey(modulus, exponent);

    var key = _makeRsaKey(rsaKey);

    key.toJson = function() {
        return _rsaPublicKeyToKeyczarJson(rsaKey);
    };
    return key;
}

function privateKeyFromKeyczar(serialized) {
    var obj = JSON.parse(serialized);

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
    var rsaKey = forge.pki.setRsaPrivateKey(n, e, d, p, q, dP, dQ, qInv);

    var key = _makeRsaKey(rsaKey);

    key.decrypt = function(message) {
        message = _unpackOutput(message);
        _checkKeyHash(key.keyhash, message);
        return rsa_oaep.rsa_oaep_decrypt(rsaKey, message.message);
    };

    /** Returns a JSON string containing the public part of this key. */
    key.exportPublicKeyJson = function() {
        return _rsaPublicKeyToKeyczarJson(rsaKey);
    };

    key.toJson = function() {
        return _rsaPrivateKeyToKeyczarJson(rsaKey);
    };

    return key;
}

function constantTimeEquals(s1, s2) {
    if (s1.length != s2.length) {
        throw new Error('Invalid arguments: strings must be the same length');
    }

    var equals = 1;
    for (var i = 0; i < s1.length; i++) {
        equals &= s1.charAt(i) == s2.charAt(i);
    }
    return equals;
}

// Returns a Keyczar AES key object from the serialized JSON representation.
function aesFromKeyczar(serialized) {
    var obj = JSON.parse(serialized);
    if (obj.mode != MODE_CBC) {
        throw new Error('Unsupported cipher mode: ' + obj.mode);
    }

    var keyBytes = decodeBase64Url(obj.aesKeyString);
    if (keyBytes.length != obj.size/8) {
        throw new Error('Mismatched key sizes: ' + keyBytes.length + ' != ' + (obj.size/8));
    }

    var hmacBytes = decodeBase64Url(obj.hmacKey.hmacKeyString);
    if (hmacBytes.length != obj.hmacKey.size/8) {
        throw new Error('Mismatched hmac key sizes: ' +
            hmacBytes.length + ' != ' + (obj.hmacKey.size/8));
    }

    return _aesFromBytes(keyBytes, hmacBytes);
}

function _aesFromBytes(keyBytes, hmacBytes) {
    var aesObject = forge.aes.createEncryptionCipher(keyBytes);
    var mdObject = forge.md.sha1.create();
    var hmacObject = forge.hmac.create();
    hmacObject.start(mdObject, hmacBytes);

    // calculate the keyhash
    var md = forge.md.sha1.create();
    md.update(_encodeBigEndian(keyBytes.length));
    md.update(keyBytes);
    md.update(hmacBytes);
    var keyhash = md.digest().data.substring(0, KEYHASH_LENGTH);

    var key = {
        keyhash: keyhash
    };
    key.encrypt = function(input) {
        // generate a random IV
        iv = forge.random.getBytes(keyBytes.length);

        // TODO: cache the cipher object?
        cipher = forge.aes.startEncrypting(keyBytes, iv, null);
        cipher.update(new forge.util.ByteBuffer(input));
        success = cipher.finish();
        if (!success) {
            throw new Error('AES encryption failed');
        }

        output = _packOutput(key.keyhash, iv + cipher.output.getBytes());

        // compute the HMAC over the entire message
        hmacObject.start(null, null);
        hmacObject.update(output);
        hmac = hmacObject.getMac();
        return output + hmac.data;
    };

    key.decrypt = function(message) {
        unpacked = _unpackOutput(message);
        _checkKeyHash(key.keyhash, unpacked);

        // check the HMAC over the entire message
        var hmac = message.substring(message.length - mdObject.digestLength);
        hmacObject.start(null, null);
        hmacObject.update(message.substring(0, message.length - mdObject.digestLength));
        hmacPrime = hmacObject.getMac().data;

        if (!constantTimeEquals(hmac, hmacPrime)) {
            throw new Error('Decryption failed: HMAC does not match');
        }

        // split the message into parts
        var iv = unpacked.message.substring(0, keyBytes.length);
        var ciphertext = unpacked.message.substring(keyBytes.length, unpacked.message.length - mdObject.digestLength);

        cipher = forge.aes.startDecrypting(keyBytes, iv, null);
        cipher.update(new forge.util.ByteBuffer(ciphertext));
        success = cipher.finish();
        if (!success) {
            throw new Error('Decryption failed: AES error?');
        }
        return cipher.output.getBytes();
    };

    key.toJson = function() {
        data = {
            aesKeyString: encodeBase64Url(keyBytes),
            size: keyBytes.length*8,
            mode: MODE_CBC,

            hmacKey: {
                hmacKeyString: encodeBase64Url(hmacBytes),
                size: hmacBytes.length*8
            }
        };
        return JSON.stringify(data);
    };

    return key;
}

module.exports.KEYHASH_LENGTH = KEYHASH_LENGTH;
module.exports._bnToBytes = _bnToBytes;
module.exports._base64ToBn = _base64ToBn;
module.exports.decodeBase64Url = decodeBase64Url;
module.exports.encodeBase64Url = encodeBase64Url;
module.exports._rsaPrivateKeyToKeyczarJson = _rsaPrivateKeyToKeyczarJson;
module.exports._rsaPublicKeyToKeyczarJson = _rsaPublicKeyToKeyczarJson;
module.exports.publicKeyFromKeyczar = publicKeyFromKeyczar;
module.exports.privateKeyFromKeyczar = privateKeyFromKeyczar;
module.exports._privateKeyToKeyczarObject = _privateKeyToKeyczarObject;
module.exports._aesFromBytes = _aesFromBytes;
module.exports.aesFromKeyczar = aesFromKeyczar;
