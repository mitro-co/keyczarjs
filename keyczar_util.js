/*
Copyright 2003 Lectorius, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/** @suppress {duplicate} */
var forge = forge || require('node-forge');

// Define keyczar_util as a module that can be loaded both by node require and a browser
var keyczar_util = {};

(function() {
'use strict';

keyczar_util.KEYHASH_LENGTH = 4;
var MODE_CBC = 'CBC';

keyczar_util.VERSION_BYTE = '\x00';

// Unpacks Keyczar's output format
function _unpackOutput(message) {
    if (message.charAt(0) != keyczar_util.VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + message.charCodeAt(0));
    }

    var keyhash = message.substr(1, keyczar_util.KEYHASH_LENGTH);
    message = message.substr(1 + keyczar_util.KEYHASH_LENGTH);
    return {keyhash: keyhash, message: message};
}

function _packOutput(keyhash, message) {
    if (keyhash.length != keyczar_util.KEYHASH_LENGTH) {
        throw new Error('Invalid keyhash length: ' + keyhash.length);
    }

    return keyczar_util.VERSION_BYTE + keyhash + message;
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
keyczar_util._bnToBytes = function(b) {
    // prepend 0x00 if first byte >= 0x80
    var hex = b.toString(16);
    if(hex[0] >= '8') {
        hex = '00' + hex;
    }
    return forge.util.hexToBytes(hex);
};

function _bnToBase64(b) {
    return keyczar_util.encodeBase64Url(keyczar_util._bnToBytes(b));
}

// Hack to support URL-safe base64 (base64url) from:
// http://tools.ietf.org/html/rfc4648
// TODO: Directly encode/decode this alphabet instead of search and replacing?
// TODO: Patch Forge to use window.btoa/atob if available?
keyczar_util.decodeBase64Url = function(message) {
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
};

keyczar_util.encodeBase64Url = function(message) {
    message = forge.util.encode64(message);

    // remove padding
    var endIndex = message.length-1;
    while (message.charAt(endIndex) == '=') {
        endIndex -= 1;
    }
    message = message.substring(0, endIndex+1);

    return message.replace(/\+/g, '-').replace(/\//g, '_');
};

function _stripLeadingZeros(bytes) {
    var nonZeroIndex = 0;
    while (nonZeroIndex < bytes.length && bytes.charAt(nonZeroIndex) == '\x00') {
        nonZeroIndex += 1;
    }
    return bytes.substring(nonZeroIndex);
}

keyczar_util._encodeBigEndian = function(number) {
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
};

keyczar_util._decodeBigEndian = function(byteString) {
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
};

// Returns an Array of byte strings from an input byte string.
// Equivalent to org.keyczar.util.Util.lenPrefixUnpack
keyczar_util._unpackByteStrings = function(bytes) {
    var numByteStrings = keyczar_util._decodeBigEndian(bytes);
    var index = 4;

    var output = [];
    for (var i = 0; i < numByteStrings; i++) {
        var length = keyczar_util._decodeBigEndian(bytes.substring(index));
        index += 4;
        output.push(bytes.substring(index, index + length));
        index += length;
    }

    // checks if the final string was truncated
    if (index > bytes.length) {
        throw new Error('Malformed input: not enough data!');
    }
    return output;
};

// Packs an Array of byte strings into a byte string, length prefixed (32-bit big endian)
// Equivalent to org.keyczar.util.Util.lenPrefixUnpack
keyczar_util._packByteStrings = function(listOfBytes) {
    var output = [];
    // total number of strings
    output.push(keyczar_util._encodeBigEndian(listOfBytes.length));

    for (var i = 0; i < listOfBytes.length; i++) {
        // string length
        output.push(keyczar_util._encodeBigEndian(listOfBytes[i].length));
        // the string itself
        // TODO: Check that the string doesn't include out of range values?
        output.push(listOfBytes[i]);
    }

    return output.join('');
};

function _hashBigNumber(md, bigNumber) {
    var bytes = keyczar_util._bnToBytes(bigNumber);
    bytes = _stripLeadingZeros(bytes);

    md.update(keyczar_util._encodeBigEndian(bytes.length));
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
    return digest.getBytes(keyczar_util.KEYHASH_LENGTH);
}

function _rsaPublicKeyToKeyczarObject(publicKey) {
    return {
        modulus: _bnToBase64(publicKey.n),
        publicExponent: _bnToBase64(publicKey.e),
        size: publicKey.n.bitLength()
    };
}

// Returns the JSON string representing publicKey in Keyczar's format.
keyczar_util._rsaPublicKeyToKeyczarJson = function(publicKey) {
    var obj = _rsaPublicKeyToKeyczarObject(publicKey);
    return JSON.stringify(obj);
};

function _bytesToBigInteger(bytes) {
    var buffer = forge.util.createBuffer(bytes);
    var hex = buffer.toHex();
    return new forge.jsbn.BigInteger(hex, 16);
}

keyczar_util._base64ToBn = function(s) {
    var decoded = keyczar_util.decodeBase64Url(s);
    return _bytesToBigInteger(decoded);
};

keyczar_util._privateKeyToKeyczarObject = function(key) {
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
};

keyczar_util._rsaPrivateKeyToKeyczarJson = function(key) {
    var obj = keyczar_util._privateKeyToKeyczarObject(key);
    return JSON.stringify(obj);
};

function _mdForSignature(message) {
    var mdObject = forge.md.sha1.create();
    mdObject.update(message);
    // Keyczar signature format appends the version byte
    // https://code.google.com/p/keyczar/wiki/SignatureFormat
    mdObject.update(keyczar_util.VERSION_BYTE);
    return mdObject;
}

// Returns a key object for an RSA key.
function _makeRsaKey(rsaKey) {
    var key = {
        keyhash: _rsaHash(rsaKey),
        size: rsaKey.n.bitLength()
    };

    key.encrypt = function(plaintext) {
        // needed to make this work with private keys
        var tempKey = forge.pki.setRsaPublicKey(rsaKey.n, rsaKey.e);
        var ciphertext = tempKey.encrypt(plaintext, 'RSA-OAEP');
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

keyczar_util.publicKeyFromKeyczar = function(serialized) {
    var obj = JSON.parse(serialized);
    var modulus = keyczar_util._base64ToBn(obj.modulus);
    var exponent = keyczar_util._base64ToBn(obj.publicExponent);
    var rsaKey = forge.pki.setRsaPublicKey(modulus, exponent);

    var key = _makeRsaKey(rsaKey);

    key.toJson = function() {
        return keyczar_util._rsaPublicKeyToKeyczarJson(rsaKey);
    };
    return key;
};

keyczar_util.privateKeyFromKeyczar = function(serialized) {
    var obj = JSON.parse(serialized);

    // public key parts
    var n = keyczar_util._base64ToBn(obj.publicKey.modulus);
    var e = keyczar_util._base64ToBn(obj.publicKey.publicExponent);

    // private key parts
    var d = keyczar_util._base64ToBn(obj.privateExponent);
    var p = keyczar_util._base64ToBn(obj.primeP);
    var q = keyczar_util._base64ToBn(obj.primeQ);
    var dP = keyczar_util._base64ToBn(obj.primeExponentP);
    var dQ = keyczar_util._base64ToBn(obj.primeExponentQ);
    var qInv = keyczar_util._base64ToBn(obj.crtCoefficient);
    var rsaKey = forge.pki.setRsaPrivateKey(n, e, d, p, q, dP, dQ, qInv);

    var key = _makeRsaKey(rsaKey);

    key.decrypt = function(message) {
        message = _unpackOutput(message);
        _checkKeyHash(key.keyhash, message);
        return rsaKey.decrypt(message.message, 'RSA-OAEP');
    };

    key.sign = function(message) {
        var md = _mdForSignature(message);
        var signature = rsaKey.sign(md);

        return _packOutput(key.keyhash, signature);
    };

    /** Returns a JSON string containing the public part of this key. */
    key.exportPublicKeyJson = function() {
        return keyczar_util._rsaPublicKeyToKeyczarJson(rsaKey);
    };

    key.toJson = function() {
        return keyczar_util._rsaPrivateKeyToKeyczarJson(rsaKey);
    };

    return key;
};

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
keyczar_util.aesFromKeyczar = function(serialized) {
    var obj = JSON.parse(serialized);
    if (obj.mode != MODE_CBC) {
        throw new Error('Unsupported cipher mode: ' + obj.mode);
    }

    var keyBytes = keyczar_util.decodeBase64Url(obj.aesKeyString);
    if (keyBytes.length != obj.size/8) {
        throw new Error('Mismatched key sizes: ' + keyBytes.length + ' != ' + (obj.size/8));
    }

    var hmacBytes = keyczar_util.decodeBase64Url(obj.hmacKey.hmacKeyString);
    if (hmacBytes.length != obj.hmacKey.size/8) {
        throw new Error('Mismatched hmac key sizes: ' +
            hmacBytes.length + ' != ' + (obj.hmacKey.size/8));
    }

    return keyczar_util._aesFromBytes(keyBytes, hmacBytes);
};

keyczar_util._aesFromBytes = function(keyBytes, hmacBytes) {
    var aesObject = forge.aes.createEncryptionCipher(keyBytes);
    var mdObject = forge.md.sha1.create();
    var hmacObject = forge.hmac.create();
    hmacObject.start(mdObject, hmacBytes);

    // calculate the keyhash
    var md = forge.md.sha1.create();
    md.update(keyczar_util._encodeBigEndian(keyBytes.length));
    md.update(keyBytes);
    md.update(hmacBytes);
    var keyhash = md.digest().getBytes(keyczar_util.KEYHASH_LENGTH);

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
        return output + hmac.getBytes();
    };

    key.decrypt = function(message) {
        var unpacked = _unpackOutput(message);
        _checkKeyHash(key.keyhash, unpacked);

        // check the HMAC over the entire message
        var hmac = message.substring(message.length - mdObject.digestLength);
        hmacObject.start(null, null);
        hmacObject.update(message.substring(0, message.length - mdObject.digestLength));
        var hmacPrime = hmacObject.getMac().getBytes();

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
            aesKeyString: keyczar_util.encodeBase64Url(keyBytes),
            size: keyBytes.length*8,
            mode: MODE_CBC,

            hmacKey: {
                hmacKeyString: keyczar_util.encodeBase64Url(hmacBytes),
                size: hmacBytes.length*8
            }
        };
        return JSON.stringify(data);
    };

    // Returns a byte string containing the key/hmac bytes, using _packByteStrings.
    // Used by keyczar.createSessionCrypter().
    key.pack = function() {
        return keyczar_util._packByteStrings([keyBytes, hmacBytes]);
    };

    return key;
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = keyczar_util;
}
})();
