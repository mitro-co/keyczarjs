// Program to re-encrypt data written from Java to verify that round-tripping works.

var fs = require('fs');

var keyczar = require('./keyczar');

function readFile(path) {
    return fs.readFileSync(path, {encoding: 'utf-8'});
}

function writeFile(path, contents) {
    return fs.writeFileSync(path, contents, {encoding: 'utf-8'});
}

function encrypt(keyPath, message, outputPath) {
    var key = keyczar.fromJson(readFile(keyPath));
    var encrypted = key.encrypt(message);
    writeFile(outputPath, encrypted);
}

function decrypt(keyPath, encryptedPath, expectedMessage, expectedType, keyPassword) {
    var key = keyczar.fromJson(readFile(keyPath), keyPassword);
    if (key.metadata.type != expectedType) {
        throw new Error('Unexpected key type: ' + key.metadata.type);
    }
    var encrypted = readFile(encryptedPath);
    var decrypted = key.decrypt(encrypted);
    if (expectedMessage !== null) {
        if (decrypted != expectedMessage) {
            process.stderr.write(encryptedPath + ' did not decrypt correctly\n');
            process.exit(1);
        } else {
            console.log(encryptedPath + ' decrypts successfully');
        }
    }
    return decrypted;
}

function makeLonger(input) {
    if (input.length === 0) {
        input = '\x00';
    }

    while (input.length < 1000) {
        input += input;
    }
    return input;
}

function encryptSession(keyPath, message, outputPath) {
    var key = keyczar.fromJson(readFile(keyPath));
    var encrypted = keyczar.encryptWithSession(key, message);
    writeFile(outputPath, encrypted);
}

function decryptSession(keyPath, encryptedPath, expectedMessage) {
    var key = keyczar.fromJson(readFile(keyPath));
    var encrypted = readFile(encryptedPath);
    var decrypted = keyczar.decryptWithSession(key, encrypted);
    if (expectedMessage !== null && decrypted != expectedMessage) {
        process.stderr.write(encryptedPath + ' did not decrypt correctly\n');
        process.exit(1);
    }
    return decrypted;
}

function sign(keyPath, message, signaturePath) {
    var key = keyczar.fromJson(readFile(keyPath));
    writeFile(signaturePath, key.sign(message));
}

function verify(keyPath, message, signaturePath) {
    var signature = readFile(signaturePath);
    var publicSignKey = keyczar.fromJson(readFile(keyPath));
    if (signature != signature) {
        process.stderr.write('signature did not match\n');
        process.exit(1);
    }
}

if (process.argv.length != 4 && process.argv.length != 5) {
    process.stderr.write('node roundtripper.js (mode) (in/out directory) [message to en/decrypt]\n');
    process.exit(1);
}

var mode = process.argv[2];
var dirpath = process.argv[3];
var message = 'Hello this is a longish message from Javascript';
var password = 'foopassword';
if (process.argv.length == 5) {
    message = process.argv[4];
}

if (mode == 'encrypt') {
    console.log('generating private key ...');
    var privateKey = keyczar.create(keyczar.TYPE_RSA_PRIVATE, undefined, {size:1024});
    writeFile(dirpath + '/privatekey.json', privateKey.toJson());

    var publicKey = privateKey.exportPublicKey();
    writeFile(dirpath + '/publickey.json', publicKey.toJson());

    console.log('encrypting message length', message.length);
    encrypt(dirpath + '/publickey.json', message, dirpath + '/publickey_encrypted');

    console.log('encrypting key with password');
    writeFile(dirpath + '/privatekey_encrypted.json', privateKey.toJsonEncrypted(password));

    console.log('generating AES key ...');
    var symmetric = keyczar.create(keyczar.TYPE_AES);
    writeFile(dirpath + '/symmetric.json', symmetric.toJson());
    encrypt(dirpath + '/symmetric.json', message, dirpath + '/symmetric_encrypted');

    encryptSession(dirpath + '/publickey.json', makeLonger(message), dirpath + '/publickey_session');

    console.log('generating signing key ...');
    var privateSignKey = keyczar.create(keyczar.TYPE_RSA_PRIVATE, keyczar.PURPOSE_SIGN_VERIFY, {size:1024});
    writeFile(dirpath + '/privatekey_sign.json', privateSignKey.toJson());

    // Export the public key; sign with the private key
    var publicSignKey = privateSignKey.exportPublicKey();
    writeFile(dirpath + '/publickey_sign.json', publicSignKey.toJson());
    sign(dirpath + '/privatekey_sign.json', message, dirpath + '/privatekey_sign');
} else if (mode == 'decrypt') {
    console.log('asymmetric:');
    decrypt(dirpath + '/privatekey.json', dirpath + '/publickey_reencrypted', message, keyczar.TYPE_RSA_PRIVATE);
    console.log('symmetric:');
    decrypt(dirpath + '/symmetric.json', dirpath + '/symmetric_reencrypted', message, keyczar.TYPE_AES);

    var output = decryptSession(dirpath + '/privatekey.json', dirpath + '/publickey_session_reencrypted', makeLonger(message));

    // verify the session signature
    verify(dirpath + '/publickey_sign.json', output, dirpath + '/publickey_session_sign');
} else if (mode == 'roundtrip') {
    var decrypted = decrypt(dirpath + '/privatekey.json', dirpath + '/publickey_encrypted', null, keyczar.TYPE_RSA_PRIVATE);
    encrypt(dirpath + '/publickey.json', decrypted, dirpath + '/publickey_reencrypted');

    var decrypted2 = decrypt(dirpath + '/privatekey_encrypted.json', dirpath + '/publickey_encrypted', null, keyczar.TYPE_RSA_PRIVATE, password);
    if (decrypted2 != decrypted) {
        process.stderr.write('encrypted private key did not work?\n');
        process.exit(1);
    }

    // verify the signature
    verify(dirpath + '/publickey_sign.json', decrypted2, dirpath + '/privatekey_sign');

    decrypted = decrypt(dirpath + '/symmetric.json', dirpath + '/symmetric_encrypted', null, keyczar.TYPE_AES);
    encrypt(dirpath + '/symmetric.json', decrypted, dirpath + '/symmetric_reencrypted');

    decrypted = decryptSession(dirpath + '/privatekey.json', dirpath + '/publickey_session', null);
    encryptSession(dirpath + '/publickey.json', decrypted, dirpath + '/publickey_session_reencrypted');

    // sign the session output
    sign(dirpath + '/privatekey_sign.json', decrypted, dirpath + '/publickey_session_sign');

    console.log('JS re-encrypted to', dirpath);
} else {
    process.stderr.write('mode must be encrypt, decrypt, or roundtrip\n');
    process.exit(1);
}
