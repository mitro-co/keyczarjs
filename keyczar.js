var forge = require('forge');

var keyczar_util = require('./keyczar_util');
var rsa_oaep = require('./rsa_oaep');

var TYPE_RSA_PRIVATE = 'RSA_PRIV';
var PURPOSE_DECRYPT_ENCRYPT = 'DECRYPT_AND_ENCRYPT';
var STATUS_PRIMARY = 'PRIMARY';

var VERSION_BYTE = '\x00';
var KEYHASH_LENGTH = 4;

// Unpacks Keyczar's output format
function _unpack_encoded(encoded) {
    messageBytes = keyczar_util.decodeBase64Url(encoded);
    if (messageBytes.charAt(0) != VERSION_BYTE) {
        throw new Error('Unsupported version byte: ' + messageBytes.charCodeAt(0));
    }

    keyhash = messageBytes.substr(1, 1+KEYHASH_LENGTH);
    message = messageBytes.substr(1+KEYHASH_LENGTH);
    return {keyhash: keyhash, message: message};
}

function fromJson(serialized) {
    var keyczar = {};
    var data = JSON.parse(serialized);

    function rsa_decrypt(message) {
        var message = _unpack_encoded(message);
        // TODO: verify keyhash?
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
    } else {
        throw new Error('Unsupported key type/purpose: ' + t + '/' + m);
    }

    return keyczar;
}

module.exports.fromJson = fromJson;
