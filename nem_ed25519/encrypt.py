from binascii import unhexlify
from os import urandom
from Cryptodome.Cipher import AES
from nem_ed25519.utils import *


def encrypt(sk, pk, msg):
    assert isinstance(sk, str), 'SK is hex str'
    assert len(sk) == 64, 'SK is 32bytes, not "{}"'.format(sk)
    assert isinstance(pk, str), 'PK is hex str'
    assert len(pk) == 64, 'PK is 32bytes, not "{}"'.format(pk)
    assert isinstance(msg, bytes), 'Msg is bytes'
    sk = unhexlify(sk.encode())[::-1]
    pk = unhexlify(pk.encode())

    h = to_hash(sk)
    a = 2**(B - 2) + sum(2**i * bit(h, i) for i in range(3, B - 2))
    A = decodepoint(pk)
    g = encodepoint(scalarmult(A, a))
    salt = urandom(32)
    iv = urandom(16)
    key_int = int.from_bytes(g, 'big') ^ int.from_bytes(salt, 'big')
    shared_key = to_hash_sha3_256(key_int.to_bytes(32, 'big'))
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    encrypted_msg = cipher.encrypt(pad(msg))
    return salt + iv + encrypted_msg


def decrypt(sk, pk, enc):
    assert isinstance(sk, str), 'SK is hex str'
    assert len(sk) == 64, 'SK is 32bytes, not "{}"'.format(sk)
    assert isinstance(pk, str), 'PK is hex str'
    assert len(pk) == 64, 'PK is 32bytes, not "{}"'.format(pk)
    assert isinstance(enc, bytes), 'Enc is bytes'
    sk = unhexlify(sk.encode())[::-1]
    pk = unhexlify(pk.encode())

    salt, iv, encrypted_msg = enc[:32], enc[32:32 + 16], enc[32 + 16:]
    h = to_hash(sk)
    a = 2**(B - 2) + sum(2**i * bit(h, i) for i in range(3, B - 2))
    A = decodepoint(pk)
    g = encodepoint(scalarmult(A, a))
    key_int = int.from_bytes(g, 'big') ^ int.from_bytes(salt, 'big')
    shared_key = to_hash_sha3_256(key_int.to_bytes(32, 'big'))
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    decrypt = cipher.decrypt(encrypted_msg)
    return unpad(decrypt)
