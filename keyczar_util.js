var forge = require('forge');

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

function _bytesToBigInteger(bytes) {
    var buffer = forge.util.createBuffer(bytes);
    var hex = buffer.toHex();
    return new BigInteger(hex, 16);
}

function _base64ToBn(s) {
    var decoded = decodeBase64Url(s);
    return _bytesToBigInteger(decoded);
}

function publicKeyFromKeyczar(serialized) {
    var obj = JSON.parse(serialized);
    var modulus = _base64ToBn(obj.modulus);
    var exponent = _base64ToBn(obj.publicExponent);
    return forge.pki.setRsaPublicKey(modulus, exponent);
}

function _privateKeyToKeyczarObject(key) {
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
        throw new Error("Incorrect calculation of private key size? " + obj.size + " != " + obj.publicKey.size);
    }

    return obj;
}

// TODO: Rename this privateKeyToKeyczarJson?
function privateKeyToKeyczar(key) {
    var obj = _privateKeyToKeyczarObject(key);
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

module.exports._bnToBytes = _bnToBytes;
module.exports._base64ToBn = _base64ToBn;
module.exports.decodeBase64Url = decodeBase64Url;
module.exports.encodeBase64Url = encodeBase64Url;
module.exports.publicKeyToKeyczar = publicKeyToKeyczar;
module.exports.publicKeyFromKeyczar = publicKeyFromKeyczar;
module.exports.privateKeyToKeyczar = privateKeyToKeyczar;
module.exports.privateKeyFromKeyczar = privateKeyFromKeyczar;
module.exports._privateKeyToKeyczarObject = _privateKeyToKeyczarObject;
