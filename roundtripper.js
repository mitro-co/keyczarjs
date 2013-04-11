// Program to re-encrypt data written from Java to verify that round-tripping works.

var fs = require('fs');

var keyczar = require('./keyczar');

function readFile(path) {
    return fs.readFileSync(path, {encoding: 'utf-8'});
}

dirpath = process.argv[2];
privateKey = keyczar.fromJson(readFile(dirpath + '/privatekey.json'));
encrypted = readFile(dirpath + '/publickey_encrypted');
decrypted = privateKey.decrypt(encrypted);

publicKey = keyczar.fromJson(readFile(dirpath + '/publickey.json'));
reencrypted = publicKey.encrypt(decrypted);
reencrypted_path = dirpath + '/publickey_reencrypted';
fs.writeFileSync(reencrypted_path, reencrypted, {encoding: 'utf-8'});
console.log('JS re-encrypted to', reencrypted_path);
