var forge = require('forge');

var keyczar_util = require('./keyczar_util');
var rsa_oaep = require('./rsa_oaep');

var TYPE_RSA_PRIVATE = 'RSA_PRIV';
var TYPE_RSA_PUBLIC = 'RSA_PUB';
var PURPOSE_DECRYPT_ENCRYPT = 'DECRYPT_AND_ENCRYPT';
var PURPOSE_ENCRYPT = 'ENCRYPT';
var STATUS_PRIMARY = 'PRIMARY';

var RSA_DEFAULT_BITS = 4096;

var VERSION_BYTE = '\x00';
var KEYHASH_LENGTH = 4;

// Unpacks Keyczar's output format
function _unpackOutput(encoded) {
    messageBytes = keyczar_util.decodeBase64Url(encoded);
    if (messageBytes.charAt(0) != VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + messageBytes.charCodeAt(0));
    }

    keyhash = messageBytes.substr(1, KEYHASH_LENGTH);
    message = messageBytes.substr(1+KEYHASH_LENGTH);
    return {keyhash: keyhash, message: message};
}

function _packOutput(keyhash, message) {
    if (keyhash.length != KEYHASH_LENGTH) {
        throw new Error('Invalid keyhash length: ' + keyhash.length);
    }

    return VERSION_BYTE + keyhash + message;
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

// Returns a new Keyczar key. Note: this is slow for RSA keys.
// TODO: Support different types. Right now it generates asymmetric RSA keys.
// TODO: Possibly generate the key in steps to avoid hanging a browser?
function create(options) {
    if (!options) {
        options = {};
    }
    // TODO: Enforce a list of acceptable sizes
    if (!options.size) {
        options.size = RSA_DEFAULT_BITS;
    }
    if (!options.name) {
        options.name = '';
    }

    var generator = forge.pki.rsa.createKeyPairGenerationState(options.size);
    // run until done
    forge.pki.rsa.stepKeyPairGenerationState(generator, 0);

    // Create the initial metadata
    var metadata = {
        name: options.name,
        purpose: PURPOSE_DECRYPT_ENCRYPT,
        type: TYPE_RSA_PRIVATE,
        encrypted: false,
        versions: [{
            exportable: false,
            status: STATUS_PRIMARY,
            versionNumber: 1
        }]
    };

    // TODO: This serializes/deserializes the keys; change _makeKeyczar to not parse strings?
    var data = {
        meta: JSON.stringify(metadata),
        "1": keyczar_util.privateKeyToKeyczar(generator.keys.privateKey)
    };

    return _makeKeyczar(data);
}

// Return a new keyczar containing the public part of key, which must be an asymmetric key.
function exportPublicKey(key) {
    if (key.metadata.type != TYPE_RSA_PRIVATE && key.metadata.purpose != PURPOSE_DECRYPT_ENCRYPT) {
        throw new Error('Unsupported key type/purpose:' +
            key.metadata.type + '/' + key.metadata.purpose);
    }

    var metadata = {
        name: key.metadata.name,
        purpose: PURPOSE_ENCRYPT,
        type: TYPE_RSA_PUBLIC,
        encrypted: false,
        // TODO: Probably should do a deep copy
        versions: key.metadata.versions
    };

    if (key.metadata.versions.length != 1) {
        throw new Error('TODO: Support key sets with multiple keys');
    }

    var primaryVersion = _getPrimaryVersion(key.metadata);

    var data = {
        meta: JSON.stringify(metadata)
    };
    data[String(primaryVersion)] = keyczar_util.publicKeyToKeyczar(key.primary);
    return _makeKeyczar(data);
}

function fromJson(serialized) {
    var data = JSON.parse(serialized);
    return _makeKeyczar(data);
}

// find the primary version; ensure we don't have more than one
function _getPrimaryVersion(metadata) {
    var primaryVersion = null;
    for (var i = 0; i < metadata.versions.length; i++) {
        if (metadata.versions[i].status == STATUS_PRIMARY) {
            if (primaryVersion !== null) {
                throw new Error('Invalid key: multiple primary keys');
            }
            primaryVersion = metadata.versions[i].versionNumber;
        }
    }

    if (primaryVersion === null) {
        throw new Error('No primary key');
    }

    return primaryVersion;
}

// Returns a Keyczar object from data.
function _makeKeyczar(data) {
    var keyczar = {};

    function rsa_decrypt(message) {
        message = _unpackOutput(message);
        if (message.keyhash != keyczar.primaryHash) {
            primaryHex = forge.util.bytesToHex(keyczar.primaryHash);
            actualHex = forge.util.bytesToHex(message.keyhash);
            throw new Error('Mismatched keyhash (primary: ' +
                primaryHex + ' actual: ' + actualHex + ')');
        }
        return rsa_oaep.rsa_oaep_decrypt(keyczar.primary, message.message);
    }

    function rsa_encrypt(message) {
        var ciphertext = rsa_oaep.rsa_oaep_encrypt(keyczar.primary, message);
        outbytes = _packOutput(keyczar.primaryHash, ciphertext);
        return keyczar_util.encodeBase64Url(outbytes);
    }

    keyczar.metadata = JSON.parse(data.meta);
    if (keyczar.metadata.encrypted !== false) {
        throw new Error('Encrypted keys not supported');
    }

    var primaryVersion = _getPrimaryVersion(keyczar.metadata);

    var t = keyczar.metadata.type;
    var p = keyczar.metadata.purpose;
    var primaryKeyString = data[String(primaryVersion)];
    if (t == TYPE_RSA_PRIVATE && p == PURPOSE_DECRYPT_ENCRYPT) {
        keyczar.encrypt = rsa_encrypt;
        keyczar.decrypt = rsa_decrypt;
        keyczar.primary = keyczar_util.privateKeyFromKeyczar(primaryKeyString);
        keyczar.primaryHash = _rsaHash(keyczar);
        keyczar.primaryToJson = keyczar_util.privateKeyToKeyczar;
    } else if (t == TYPE_RSA_PUBLIC && p == PURPOSE_ENCRYPT) {
        keyczar.encrypt = rsa_encrypt;
        keyczar.primary = keyczar_util.publicKeyFromKeyczar(primaryKeyString);
        keyczar.primaryHash = _rsaHash(keyczar);
        keyczar.primaryToJson = keyczar_util.publicKeyToKeyczar;
    } else {
        throw new Error('Unsupported key type/purpose: ' + t + '/' + p);
    }

    // Returns the JSON serialization of this keyczar.
    keyczar.toJson = function() {
        var out = {};
        out.meta = JSON.stringify(keyczar.metadata);

        // TODO: Store and serialize ALL keys. For now this works
        if (keyczar.metadata.versions.length != 1) {
            throw new Error('TODO: Support keyczars with multiple keys');
        }
        var primaryVersion = _getPrimaryVersion(keyczar.metadata);
        out[String(primaryVersion)] = keyczar.primaryToJson(keyczar.primary);
        return JSON.stringify(out);
    };

    return keyczar;
}

module.exports.create = create;
module.exports.fromJson = fromJson;
module.exports.exportPublicKey = exportPublicKey;
