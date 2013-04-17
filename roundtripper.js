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

function decrypt(keyPath, encryptedPath, expectedMessage, expectedType) {
    var key = keyczar.fromJson(readFile(keyPath));
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

if (process.argv.length != 4 && process.argv.length != 5) {
    process.stderr.write('node roundtripper.js (mode) (in/out directory) [message to en/decrypt]\n');
    process.exit(1);
}

var mode = process.argv[2];
var dirpath = process.argv[3];
var message = 'Hello this is a longish message from Javascript';
if (process.argv.length == 5) {
    message = process.argv[4];
}

if (mode == 'encrypt') {
    console.log('generating private key ...');
    var privateKey = keyczar.create(keyczar.TYPE_RSA_PRIVATE);
    writeFile(dirpath + '/privatekey.json', privateKey.toJson());

    var publicKey = privateKey.exportPublicKey();
    writeFile(dirpath + '/publickey.json', publicKey.toJson());

    console.log('encrypting message length', message.length);
    encrypt(dirpath + '/publickey.json', message, dirpath + '/publickey_encrypted');

    console.log('generating AES key ...');
    var symmetric = keyczar.create(keyczar.TYPE_AES);
    writeFile(dirpath + '/symmetric.json', symmetric.toJson());
    encrypt(dirpath + '/symmetric.json', message, dirpath + '/symmetric_encrypted');

    encryptSession(dirpath + '/publickey.json', makeLonger(message), dirpath + '/publickey_session');
} else if (mode == 'decrypt') {
    console.log('asymmetric:');
    decrypt(dirpath + '/privatekey.json', dirpath + '/publickey_reencrypted', message, keyczar.TYPE_RSA_PRIVATE);
    console.log('symmetric:');
    decrypt(dirpath + '/symmetric.json', dirpath + '/symmetric_reencrypted', message, keyczar.TYPE_AES);

    decryptSession(dirpath + '/privatekey.json', dirpath + '/publickey_session_reencrypted', makeLonger(message));
} else if (mode == 'roundtrip') {
    var decrypted = decrypt(dirpath + '/privatekey.json', dirpath + '/publickey_encrypted', null, keyczar.TYPE_RSA_PRIVATE);
    encrypt(dirpath + '/publickey.json', decrypted, dirpath + '/publickey_reencrypted');

    decrypted = decrypt(dirpath + '/symmetric.json', dirpath + '/symmetric_encrypted', null, keyczar.TYPE_AES);
    encrypt(dirpath + '/symmetric.json', decrypted, dirpath + '/symmetric_reencrypted');

    decrypted = decryptSession(dirpath + '/privatekey.json', dirpath + '/publickey_session', null);
    encryptSession(dirpath + '/publickey.json', decrypted, dirpath + '/publickey_session_reencrypted');

    console.log('JS re-encrypted to', dirpath);
} else {
    process.stderr.write('mode must be encrypt, decrypt, or roundtrip\n');
    process.exit(1);
}
