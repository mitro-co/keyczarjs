// Define keyczar_util as a module that can be loaded both by node require and a browser
var forge;
var keyczar;
(function() {
'use strict';
// define node.js module
if (typeof module !== 'undefined' && module.exports) {
    keyczar = {
        rsa_oaep: require('./rsa_oaep')
    };
    module.exports = keyczar.keyczar_util = {};
    // forge must be global and loaded before any functions here are called
    forge = require('node-forge');
} else {
    if (typeof keyczar === 'undefined') {
        keyczar = {};
    }
    keyczar.keyczar_util = {};
}
var keyczar_util = keyczar.keyczar_util;

var KEYHASH_LENGTH = 4;
var MODE_CBC = 'CBC';

var VERSION_BYTE = '\x00';

// Unpacks Keyczar's output format
function _unpackOutput(message) {
    if (message.charAt(0) != VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + message.charCodeAt(0));
    }

    var keyhash = message.substr(1, KEYHASH_LENGTH);
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
    if (!(0 <= number && number <= 2147483647)) {
        throw new Error('number is out of range: ' + number);
    }
    if ((number & 0xffffffff) != number) {
        throw new Error('number is not a 32-bit integer? ' + number);
    }
    var b1 = String.fromCharCode((number >> 24) & 0xff);
    var b2 = String.fromCharCode((number >> 16) & 0xff);
    var b3 = String.fromCharCode((number >> 8) & 0xff);
    var b4 = String.fromCharCode(number & 0xff);
    return b1 + b2 + b3 + b4;
}

function _decodeBigEndian(byteString) {
    if (byteString.length < 4) {
        throw new Error('byteString too short: ' + byteString.length);
    }
    var firstByte = byteString.charCodeAt(0);
    if (firstByte & 0x80) {
        throw new Error('Cannot decode negative number; initial byte = ' + firstByte.toString(16));
    }

    var b1 = firstByte << 24;
    var b2 = byteString.charCodeAt(1) << 16;
    var b3 = byteString.charCodeAt(2) << 8;
    var b4 = byteString.charCodeAt(3);
    return b1 | b2 | b3 | b4;
}

// Returns an Array of byte strings from an input byte string.
// Equivalent to org.keyczar.util.Util.lenPrefixUnpack
function _unpackByteStrings(bytes) {
    var numByteStrings = _decodeBigEndian(bytes);
    var index = 4;

    var output = [];
    for (var i = 0; i < numByteStrings; i++) {
        var length = _decodeBigEndian(bytes.substring(index));
        index += 4;
        output.push(bytes.substring(index, index + length));
        index += length;
    }

    // checks if the final string was truncated
    if (index > bytes.length) {
        throw new Error('Malformed input: not enough data!');
    }
    return output;
}

// Packs an Array of byte strings into a byte string, length prefixed (32-bit big endian)
// Equivalent to org.keyczar.util.Util.lenPrefixUnpack
function _packByteStrings(listOfBytes) {
    var output = [];
    // total number of strings
    output.push(_encodeBigEndian(listOfBytes.length));

    for (var i = 0; i < listOfBytes.length; i++) {
        // string length
        output.push(_encodeBigEndian(listOfBytes[i].length));
        // the string itself
        // TODO: Check that the string doesn't include out of range values?
        output.push(listOfBytes[i]);
    }

    return output.join('');
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

function _mdForSignature(message) {
    var mdObject = forge.md.sha1.create();
    mdObject.update(message);
    // Keyczar signature format appends the version byte
    // https://code.google.com/p/keyczar/wiki/SignatureFormat
    mdObject.update(VERSION_BYTE);
    return mdObject;
}

// Returns a key object for an RSA key.
function _makeRsaKey(rsaKey) {
    var key = {
        keyhash: _rsaHash(rsaKey),
        size: rsaKey.n.bitLength()
    };

    key.encrypt = function(plaintext) {
        var ciphertext = keyczar.rsa_oaep.rsa_oaep_encrypt(rsaKey, plaintext);
        return _packOutput(key.keyhash, ciphertext);
    };

    key.verify = function(message, signature) {
        signature = _unpackOutput(signature);
        _checkKeyHash(key.keyhash, signature);

        var digest = _mdForSignature(message).digest().getBytes();

        // needed to make this work with private keys
        var tempKey = forge.pki.setRsaPublicKey(rsaKey.n, rsaKey.e);
        return tempKey.verify(digest, signature.message);
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
        return keyczar.rsa_oaep.rsa_oaep_decrypt(rsaKey, message.message);
    };

    key.sign = function(message) {
        var md = _mdForSignature(message);
        var signature = rsaKey.sign(md);

        return _packOutput(key.keyhash, signature);
    }

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
        var iv = forge.random.getBytes(keyBytes.length);

        // TODO: cache the cipher object?
        var cipher = forge.aes.startEncrypting(keyBytes, iv, null);
        cipher.update(new forge.util.ByteBuffer(input));
        var success = cipher.finish();
        if (!success) {
            throw new Error('AES encryption failed');
        }

        var output = _packOutput(key.keyhash, iv + cipher.output.getBytes());

        // compute the HMAC over the entire message
        hmacObject.start(null, null);
        hmacObject.update(output);
        var hmac = hmacObject.getMac();
        return output + hmac.data;
    };

    key.decrypt = function(message) {
        var unpacked = _unpackOutput(message);
        _checkKeyHash(key.keyhash, unpacked);

        // check the HMAC over the entire message
        var hmac = message.substring(message.length - mdObject.digestLength);
        hmacObject.start(null, null);
        hmacObject.update(message.substring(0, message.length - mdObject.digestLength));
        var hmacPrime = hmacObject.getMac().data;

        if (!constantTimeEquals(hmac, hmacPrime)) {
            throw new Error('Decryption failed: HMAC does not match');
        }

        // split the message into parts
        var iv = unpacked.message.substring(0, keyBytes.length);
        var ciphertext = unpacked.message.substring(keyBytes.length, unpacked.message.length - mdObject.digestLength);

        var cipher = forge.aes.startDecrypting(keyBytes, iv, null);
        cipher.update(new forge.util.ByteBuffer(ciphertext));
        var success = cipher.finish();
        if (!success) {
            throw new Error('Decryption failed: AES error?');
        }
        return cipher.output.getBytes();
    };

    key.toJson = function() {
        var data = {
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

    // Returns a byte string containing the key/hmac bytes, using _packByteStrings.
    // Used by keyczar.createSessionCrypter().
    key.pack = function() {
        return _packByteStrings([keyBytes, hmacBytes]);
    };

    return key;
}

keyczar_util.KEYHASH_LENGTH = KEYHASH_LENGTH;
keyczar_util.VERSION_BYTE = VERSION_BYTE;
keyczar_util._bnToBytes = _bnToBytes;
keyczar_util._base64ToBn = _base64ToBn;
keyczar_util.decodeBase64Url = decodeBase64Url;
keyczar_util.encodeBase64Url = encodeBase64Url;
keyczar_util._rsaPrivateKeyToKeyczarJson = _rsaPrivateKeyToKeyczarJson;
keyczar_util._rsaPublicKeyToKeyczarJson = _rsaPublicKeyToKeyczarJson;
keyczar_util.publicKeyFromKeyczar = publicKeyFromKeyczar;
keyczar_util.privateKeyFromKeyczar = privateKeyFromKeyczar;
keyczar_util._privateKeyToKeyczarObject = _privateKeyToKeyczarObject;
keyczar_util._aesFromBytes = _aesFromBytes;
keyczar_util.aesFromKeyczar = aesFromKeyczar;
keyczar_util._encodeBigEndian = _encodeBigEndian;
keyczar_util._decodeBigEndian = _decodeBigEndian;
keyczar_util._unpackByteStrings = _unpackByteStrings;
keyczar_util._packByteStrings = _packByteStrings;

// end module
})();
