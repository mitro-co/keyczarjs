var forge = require('forge');

var keyczar_util = require('./keyczar_util');
var rsa_oaep = require('./rsa_oaep');

var TYPE_RSA_PRIVATE = 'RSA_PRIV';
var PURPOSE_DECRYPT_ENCRYPT = 'DECRYPT_AND_ENCRYPT';
var STATUS_PRIMARY = 'PRIMARY';

var VERSION_BYTE = '\x00';
var KEYHASH_LENGTH = 4;

// Unpacks Keyczar's output format
function _unpackEncoded(encoded) {
    messageBytes = keyczar_util.decodeBase64Url(encoded);
    if (messageBytes.charAt(0) != VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + messageBytes.charCodeAt(0));
    }

    keyhash = messageBytes.substr(1, KEYHASH_LENGTH);
    message = messageBytes.substr(1+KEYHASH_LENGTH);
    return {keyhash: keyhash, message: message};
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
    bytes = keyczar_util._bnToBytes(bigNumber);
    bytes = _stripLeadingZeros(bytes);

    md.update(_encodeBigEndian(bytes.length));
    md.update(bytes);
}

// Returns the keyhash for an RSA public key.
function _rsaHash(publickey) {
    md = forge.md.sha1.create();

    // hash:
    // 4-byte big endian length
    // "magnitude" of the public modulus (trim all leading zero bytes)
    // same for the exponent
    _hashBigNumber(md, publickey.primary.n);
    _hashBigNumber(md, publickey.primary.e);
    var digest = md.digest();
    return digest.data.substring(0, KEYHASH_LENGTH);
}

function fromJson(serialized) {
    var keyczar = {};
    var data = JSON.parse(serialized);

    function rsa_decrypt(message) {
        message = _unpackEncoded(message);
        if (message.keyhash != keyczar.primaryHash) {
            primaryHex = forge.util.bytesToHex(keyczar.primaryHash);
            actualHex = forge.util.bytesToHex(message.keyhash);
            throw new Error('Mismatched keyhash (primary: ' +
                primaryHex + ' actual: ' + actualHex + ')');
        }
        return rsa_oaep.rsa_oaep_decrypt(keyczar.primary, message.message);
    }

    function rsa_encrypt(message) {
        // var ciphertext = rsa_oeap.rsa_oaep_decrypt(keyczar.primary, message);
        // return _pack_output();
    }

    keyczar.metadata = JSON.parse(data.meta);
    if (keyczar.metadata.encrypted !== false) {
        throw new Error('Encrypted keys not supported');
    }

    var primaryVersion = null;
    for (var i = 0; i < keyczar.metadata.versions.length; i++) {
        if (keyczar.metadata.versions[i].status == STATUS_PRIMARY) {
            primaryVersion = keyczar.metadata.versions[i].versionNumber;
            break;
        }
    }

    if (primaryVersion === null) {
        throw new Error('No primary key');
    }

    var t = keyczar.metadata.type;
    var p = keyczar.metadata.purpose;
    if (t == TYPE_RSA_PRIVATE && p == PURPOSE_DECRYPT_ENCRYPT) {
        keyczar.encrypt = rsa_encrypt;
        keyczar.decrypt = rsa_decrypt;
        keyczar.primary = keyczar_util.privateKeyFromKeyczar(data[String(primaryVersion)]);
        keyczar.primaryHash = _rsaHash(keyczar);
    } else {
        throw new Error('Unsupported key type/purpose: ' + t + '/' + m);
    }

    return keyczar;
}

module.exports.fromJson = fromJson;
