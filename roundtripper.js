// Program to re-encrypt data written from Java to verify that round-tripping works.

var fs = require('fs');

var keyczar = require('./keyczar');

function readFile(path) {
    return fs.readFileSync(path, {encoding: 'utf-8'});
}

function writeFile(path, contents) {
    return fs.writeFileSync(path, contents, {encoding: 'utf-8'});
}

function decrypt(dirpath, encryptedPath) {
    var privateKey = keyczar.fromJson(readFile(dirpath + '/privatekey.json'));
    var encrypted = readFile(dirpath + '/publickey_encrypted');
    return privateKey.decrypt(encrypted);
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
    var privateKey = keyczar.create();
    writeFile(dirpath + '/privatekey.json', privateKey.toJson());

    var publicKey = keyczar.exportPublicKey(privateKey);
    writeFile(dirpath + '/publickey.json', publicKey.toJson());

    console.log('encrypting message length', message.length);
    var encrypted = publicKey.encrypt(message);
    writeFile(dirpath + '/publickey_encrypted', encrypted);
} else if (mode == 'decrypt') {
    var reencryptedPath = dirpath + '/publickey_reencrypted';
    var decrypted = decrypt(dirpath, reencryptedPath);
    if (decrypted != message) {
        process.stderr.write(reencryptedPath + ' did not decrypt correctly\n');
        process.exit(1);
    } else {
        console.log(reencryptedPath + ' decrypts successfully');
    }
} else if (mode == 'roundtrip') {
    var decrypted = decrypt(dirpath, dirpath + '/publickey_encrypted');
    var publicKey = keyczar.fromJson(readFile(dirpath + '/publickey.json'));
    var reencrypted = publicKey.encrypt(decrypted);
    var reencrypted_path = dirpath + '/publickey_reencrypted';
    fs.writeFileSync(reencrypted_path, reencrypted, {encoding: 'utf-8'});
    console.log('JS re-encrypted to', reencrypted_path);
} else {
    process.stderr.write('mode must be encrypt, decrypt, or roundtrip\n');
    process.exit(1);
}
