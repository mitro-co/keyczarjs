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

// Unpacks Keyczar's output format
function _unpackOutput(encoded) {
    messageBytes = keyczar_util.decodeBase64Url(encoded);
    if (messageBytes.charAt(0) != VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + messageBytes.charCodeAt(0));
    }

    keyhash = messageBytes.substr(1, keyczar_util.KEYHASH_LENGTH);
    message = messageBytes.substr(1 + keyczar_util.KEYHASH_LENGTH);
    return {keyhash: keyhash, message: message};
}

function _packOutput(keyhash, message) {
    if (keyhash.length != keyczar_util.KEYHASH_LENGTH) {
        throw new Error('Invalid keyhash length: ' + keyhash.length);
    }

    return VERSION_BYTE + keyhash + message;
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
        "1": keyczar_util._rsaPrivateKeyToKeyczarJson(generator.keys.privateKey)
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
    data[String(primaryVersion)] = key.primary.exportPublicKeyJson();
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

    keyczar.metadata = JSON.parse(data.meta);
    if (keyczar.metadata.encrypted !== false) {
        throw new Error('Encrypted keys not supported');
    }

    var primaryVersion = _getPrimaryVersion(keyczar.metadata);

    var t = keyczar.metadata.type;
    var p = keyczar.metadata.purpose;
    var primaryKeyString = data[String(primaryVersion)];
    if (t == TYPE_RSA_PRIVATE && p == PURPOSE_DECRYPT_ENCRYPT) {
        keyczar.primary = keyczar_util.privateKeyFromKeyczar(primaryKeyString);
    } else if (t == TYPE_RSA_PUBLIC && p == PURPOSE_ENCRYPT) {
        keyczar.primary = keyczar_util.publicKeyFromKeyczar(primaryKeyString);
    } else {
        throw new Error('Unsupported key type/purpose: ' + t + '/' + p);
    }

    keyczar.encrypt = function(plaintext) {
        var ciphertext = keyczar.primary.encrypt(plaintext);
        outbytes = _packOutput(keyczar.primary.keyhash, ciphertext);
        return keyczar_util.encodeBase64Url(outbytes);
    };

    keyczar.decrypt = function(message) {
        message = _unpackOutput(message);
        if (message.keyhash != keyczar.primary.keyhash) {
            var primaryHex = forge.util.bytesToHex(keyczar.primary.keyhash);
            var actualHex = forge.util.bytesToHex(message.keyhash);
            throw new Error('Mismatched keyhash (primary: ' +
                primaryHex + ' actual: ' + actualHex + ')');
        }
        return keyczar.primary.decrypt(message.message);
    };

    // Returns the JSON serialization of this keyczar.
    keyczar.toJson = function() {
        var out = {};
        out.meta = JSON.stringify(keyczar.metadata);

        // TODO: Store and serialize ALL keys. For now this works
        if (keyczar.metadata.versions.length != 1) {
            throw new Error('TODO: Support keyczars with multiple keys');
        }
        var primaryVersion = _getPrimaryVersion(keyczar.metadata);
        out[String(primaryVersion)] = keyczar.primary.toJson();
        return JSON.stringify(out);
    };

    return keyczar;
}

module.exports.create = create;
module.exports.fromJson = fromJson;
module.exports.exportPublicKey = exportPublicKey;
