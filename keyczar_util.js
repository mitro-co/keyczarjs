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

function _bytesToBigInteger(bytes) {
    var buffer = forge.util.createBuffer(bytes);
    var hex = buffer.toHex();
    return new BigInteger(hex, 16);
}

function _base64ToBn(s) {
    var decoded = forge.util.decode64(s);
    return _bytesToBigInteger(decoded);
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
        throw new Error("Incorrect calculation of private key size? " + obj.size + " != " + obj.publicKey.size);
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

module.exports._base64ToBn = _base64ToBn;
module.exports.publicKeyToKeyczar = publicKeyToKeyczar;
module.exports.publicKeyFromKeyczar = publicKeyFromKeyczar;
module.exports.privateKeyToKeyczar = privateKeyToKeyczar;
module.exports.privateKeyFromKeyczar = privateKeyFromKeyczar;
