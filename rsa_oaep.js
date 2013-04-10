// RSA OAEP implementation based on the following, MIT and BSD code
// https://github.com/davedoesdev/jsjws/commit/4a2d8958c82100bf0fecfda9933bb399a83b8b14
// http://webrsa.cvs.sourceforge.net/viewvc/webrsa/Client/RSAES-OAEP.js?content-type=text%2Fplai

// See official documentation:
// http://www.rsa.com/rsalabs/node.asp?id=2125

var forge = require('forge');

// RSAES-OAEP-ENCRYPT message (M), with optional label (L)
function rsa_oaep_encrypt(key, message, label, seed) {
    // hash function hard-coded to SHA-1
    var md = forge.md.sha1.create();

    // compute length in bytes and check output
    var keyLength = Math.ceil(key.n.bitLength() / 8);
    var maxLength = keyLength - 2 * md.digestLength - 2;
    if (message.length > maxLength) {
        throw new Error("input message too long (max: " + maxLength +
                " message: " + message.length + ")");
    }

    if (!label) label = '';
    md.update(label);
    var lHash = md.digest();

    var PS = '';
    var PS_length = maxLength - message.length;
    for (var i = 0; i < PS_length; i++) {
        PS += '\x00';
    }

    var DB = lHash.getBytes() + PS + '\x01' + message;

    if (!seed) {
        seed = forge.random.getBytes(md.digestLength);
    } else if (seed.length != md.digestLength) {
        throw new Error("Invalid seed");
    }

    var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, md);
    var maskedDB = xorString(DB, dbMask);

    var seedMask = rsa_mgf1(maskedDB, md.digestLength, md);
    var maskedSeed = xorString(seed, seedMask);

    var EM = '\x00' + maskedSeed + maskedDB;

    // true = public key; do not pad
    var C = forge.pki.rsa.encrypt(EM, key, true);
    return C;
}

// RSAES-OAEP-DECRYPT ciphertext (C), with optional label (L)
function rsa_oaep_decrypt(key, ciphertext, label) {
    // compute length in bytes and check output
    var keyLength = Math.ceil(key.n.bitLength() / 8);

    if (ciphertext.length != keyLength) {
        throw new Error('Decryption error: invalid ciphertext length');
    }

    // hash function hard-coded to SHA-1
    var md = forge.md.sha1.create();

    if (keyLength < 2 * md.digestLength + 2) {
        throw new Error('Decryption error: key too short for the hash function');
    }

    // false = private key operation; false = no padding
    var EM = forge.pki.rsa.decrypt(ciphertext, key, false, false);

    if (!label) label = '';
    md.update(label);
    var lHash = md.digest();

    // Split the message into its parts
    var y = EM.charCodeAt(0);
    var maskedSeed = EM.substring(1, md.digestLength + 1);
    var maskedDB = EM.substring(1 + md.digestLength);

    var seedMask = rsa_mgf1(maskedDB, md.digestLength, md);
    var seed = xorString(maskedSeed, seedMask);

    var dbMask = rsa_mgf1(seed, keyLength - md.digestLength - 1, md);
    var db = xorString(maskedDB, dbMask);

    var lHashPrime = db.substring(0, md.digestLength);

    // Constant time find the 0x1 byte separating the padding (zeros) from the message
    // TODO: It must be possible to do this in a better/smarter way?
    var in_ps = 1;
    var index = md.digestLength;
    var error = 0;
    for (var i = md.digestLength; i < db.length; i++) {
        var code = db.charCodeAt(i);

        var is_1 = (code & 0x1) ^ 0x1;

        // non-zero if not 0 or 1 in the ps section
        var error_mask = in_ps ? 0xfffe : 0x0000;
        error |= (code & error_mask);

        // latch in_ps to zero after we find is_1
        in_ps = in_ps & is_1;
        index += in_ps;
    }

    if (error || db.charCodeAt(index) != 0x1) {
        throw new Error("Decryption error: invalid padding");
    }
    return db.substring(index + 1);
}

function xorString(string1, string2) {
    if (string1.length != string2.length) {
        throw new Error("mismatched string lengths: "+  string1.length + ", " + string2.length);
    }

    var out = '';
    for (i = 0; i < string1.length; i++) {
        out += String.fromCharCode(string1.charCodeAt(i) ^ string2.charCodeAt(i));
    }
    return out;
}

function rsa_mgf1(seed, maskLength, hash) {
   var t = '';
   var count = Math.ceil(maskLength / hash.digestLength);
   for (var i = 0; i < count; i++) {
      c = String.fromCharCode((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
      hash.start();
      hash.update(seed + c);
      t += hash.digest().getBytes();
   }

   return t.substring(0, maskLength);
}

module.exports.rsa_oaep_encrypt = rsa_oaep_encrypt;
module.exports.rsa_oaep_decrypt = rsa_oaep_decrypt;
