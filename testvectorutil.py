#!/usr/bin/env python

import base64
import sys


def collect_hex(f):
    out = ''
    for line in f:
        line = line.strip()
        if line == '':
            break
        out += line + ' '

    bytes = testVectorToBytes(out)
    return ''.join(base64.encodestring(bytes).split())


def read_vectors(path):
    f = open(path)

    variables = {
        '# Message': 'message',
        '# Seed': 'seed',
        '# Encryption': 'encrypted',
        '# RSA modulus': 'modulus',
        '# RSA public exponent': 'exponent',
        '# RSA private exponent d': 'd',
        '# Prime p': 'p',
        '# Prime q': 'q',
        '# p\'s CRT exponent dP': 'dP',
        '# q\'s CRT exponent dQ': 'dQ',
        '# CRT coefficient qInv': 'qInv',
    }

    for line in f:
        if line[0] == '#':
            found = False
            for prefix, variable in variables.iteritems():
                if line.startswith(prefix):
                    b64 = collect_hex(f)
                    print "    %s = '%s';" % (variable, b64)
                    found = True
                    break
            if not found and '-----' not in line and '=====' not in line:
                print '    //', line[1:],

            if line.startswith('# Encryption'):
                print '    checkOAEPEncrypt(pubkey, privateKey, message, seed, encrypted);\n'
            elif line.startswith('# CRT coefficient qInv'):
                print '    pubkey = forge.pki.setRsaPublicKey(_base64ToBn(modulus), _base64ToBn(exponent));'
                print '    privateKey = forge.pki.setRsaPrivateKey(_base64ToBn(modulus), _base64ToBn(exponent),'
                print '        _base64ToBn(d), _base64ToBn(p), _base64ToBn(q), _base64ToBn(dP),'
                print '        _base64ToBn(dQ), _base64ToBn(qInv));\n'


def testVectorToBytes(vectorstring):
    out = ''
    for hexbyte in vectorstring.split():
        assert len(hexbyte) == 2
        out += chr(int(hexbyte, 16))
    return out


def hex_to_base64():
    message = sys.stdin.read()
    bytes = testVectorToBytes(message)

    print base64.encodestring(bytes)


def base64_to_hex():
    encoded = sys.stdin.read()
    bytes = base64.decodestring(encoded)

    for i, c in enumerate(bytes):
        print '%02x' % ord(c),
        if (i+1) % 16 == 0:
            print


def exit_error():
    sys.stderr.write('testvectorutil.py (hex|b64|read path)\n')
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        exit_error()

    mode = sys.argv[1]
    if mode == 'hex':
        hex_to_base64()
    elif mode == 'b64':
        base64_to_hex()
    else:
        if mode != 'read' or len(sys.argv) != 3:
            exit_error()
        path = sys.argv[2]
        read_vectors(path)
