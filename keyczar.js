var forge = require('forge');

var keyczar_util = require('./keyczar_util');
var rsa_oaep = require('./rsa_oaep');

var TYPE_AES = 'AES';
var TYPE_RSA_PRIVATE = 'RSA_PRIV';
var TYPE_RSA_PUBLIC = 'RSA_PUB';
var PURPOSE_DECRYPT_ENCRYPT = 'DECRYPT_AND_ENCRYPT';
var PURPOSE_ENCRYPT = 'ENCRYPT';
var STATUS_PRIMARY = 'PRIMARY';

var RSA_DEFAULT_BITS = 4096;
var AES_DEFAULT_BITS = 128;
var HMAC_DEFAULT_BITS = 256;

function _generateAes(size) {
    if (!size) size = AES_DEFAULT_BITS;

    // generate random bytes for both AES and HMAC
    var keyBytes = forge.random.getBytes(size/8);
    var hmacBytes = forge.random.getBytes(HMAC_DEFAULT_BITS/8);
    return keyczar_util._aesFromBytes(keyBytes, hmacBytes);
}

// Returns a new Keyczar key. Note: this is slow for RSA keys.
// TODO: Support different types. Right now it generates asymmetric RSA keys.
// TODO: Possibly generate the key in steps to avoid hanging a browser?
function create(type, options) {
    if (!options) {
        options = {};
    }
    // TODO: Enforce a list of acceptable sizes
    if (!options.size) {
        options.size = null;
    }
    if (!options.name) {
        options.name = '';
    }

    var keyString = null;
    var size = options.size;
    if (type == TYPE_RSA_PRIVATE) {
        if (!size) size = RSA_DEFAULT_BITS;

        var generator = forge.pki.rsa.createKeyPairGenerationState(size);
        // run until done
        forge.pki.rsa.stepKeyPairGenerationState(generator, 0);
        keyString = keyczar_util._rsaPrivateKeyToKeyczarJson(generator.keys.privateKey);
    } else if (type == TYPE_AES) {
        keyString = _generateAes(size).toJson();
    } else {
        throw new Error('Unsupported key type: ' + type);
    }

    // Create the initial metadata
    var metadata = {
        name: options.name,
        purpose: PURPOSE_DECRYPT_ENCRYPT,
        type: type,
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
        "1": keyString
    };

    return _makeKeyczar(data);
}

// Return a new keyczar containing the public part of key, which must be an asymmetric key.
function _exportPublicKey(key) {
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
        keyczar.exportPublicKey = function() { return _exportPublicKey(keyczar); };
    } else if (t == TYPE_RSA_PUBLIC && p == PURPOSE_ENCRYPT) {
        keyczar.primary = keyczar_util.publicKeyFromKeyczar(primaryKeyString);
    } else if (t == TYPE_AES && p == PURPOSE_DECRYPT_ENCRYPT) {
        keyczar.primary = keyczar_util.aesFromKeyczar(primaryKeyString);
    } else {
        throw new Error('Unsupported key type/purpose: ' + t + '/' + p);
    }

    keyczar.encrypt = function(plaintext, encoder) {
        if (!encoder && encoder !== null) {
            encoder = keyczar_util.encodeBase64Url;
        }

        var message = keyczar.primary.encrypt(plaintext);
        if (encoder !== null) message = encoder(message);
        return message;
    };

    keyczar.decrypt = function(message, decoder) {
        if (!decoder && decoder !== null) {
            decoder = keyczar_util.decodeBase64Url;
        }

        if (decoder !== null) message = decoder(message);
        return keyczar.primary.decrypt(message);
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

function createSessionCrypter(key, sessionMaterial) {
    if (key.metadata.type != TYPE_RSA_PRIVATE && key.metadata.type != TYPE_RSA_PUBLIC) {
        throw new Error('Invalid key type for SessionCrypter: ' + key.metadata.type);
    }

    var sessionKey = null;
    var rawSessionMaterial = null;
    if (sessionMaterial) {
        // decrypt session key: not base64 encoded if leading byte is VERSION_BYTE
        if (sessionMaterial.charAt(0) == keyczar_util.VERSION_BYTE) {
            rawSessionMaterial = sessionMaterial;
        } else {
            rawSessionMaterial = keyczar_util.decodeBase64Url(sessionMaterial);
        }
        var decrypted = key.decrypt(rawSessionMaterial, null);
        var keyBytes = keyczar_util._unpackByteStrings(decrypted);

        sessionKey = keyczar_util._aesFromBytes(keyBytes[0], keyBytes[1]);
    } else {
        // generate the session key
        sessionKey = _generateAes();

        // encrypt the key
        var packed = sessionKey.pack();
        rawSessionMaterial = key.encrypt(packed, null);
    }

    var crypter = {
        rawSessionMaterial: rawSessionMaterial,
        sessionMaterial: keyczar_util.encodeBase64Url(rawSessionMaterial)
    };

    crypter.encrypt = function(plaintext, encoder) {
        var ciphertext = sessionKey.encrypt(plaintext);

        // TODO: Call non-null, non-undefined encoder()
        if (encoder !== null) ciphertext = keyczar_util.encodeBase64Url(ciphertext);
        return ciphertext;
    };

    crypter.decrypt = function(message, decoder) {
        // TODO: Call non-null, non-undefined decoder()
        if (decoder !== null) message = keyczar_util.decodeBase64Url(message);
        return sessionKey.decrypt(message);
    };

    sessionKey.sessionMaterial = sessionMaterial;
    return crypter;
}

// Returns a byte string containing (session material, session encryption).
// Convenience wrapper around a SessionCrypter.
function encryptWithSession(key, message) {
    var crypter = createSessionCrypter(key);
    var rawEncrypted = crypter.encrypt(message, null);
    var packed = keyczar_util._packByteStrings([crypter.rawSessionMaterial, rawEncrypted]);
    return keyczar_util.encodeBase64Url(packed);
}

function decryptWithSession(key, message) {
    message = keyczar_util.decodeBase64Url(message);
    var unpacked = keyczar_util._unpackByteStrings(message);
    var crypter = createSessionCrypter(key, unpacked[0]);
    return crypter.decrypt(unpacked[1], null);
}

module.exports.TYPE_RSA_PRIVATE = TYPE_RSA_PRIVATE;
module.exports.TYPE_RSA_PUBLIC = TYPE_RSA_PUBLIC;
module.exports.TYPE_AES = TYPE_AES;
module.exports.create = create;
module.exports.fromJson = fromJson;
module.exports.createSessionCrypter = createSessionCrypter;
module.exports.encryptWithSession = encryptWithSession;
module.exports.decryptWithSession = decryptWithSession;
