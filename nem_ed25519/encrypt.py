from binascii import a2b_hex
from os import urandom
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from nem_ed25519.utils import *


def encrypt(sk, pk, msg):
    if isinstance(sk, str):
        sk = a2b_hex(sk)
    if isinstance(pk, str):
        pk = a2b_hex(pk)
    assert len(sk) == 32, 'SK is 32bytes, not "{}"'.format(sk.hex())
    assert len(pk) == 32, 'PK is 32bytes, not "{}"'.format(pk.hex())
    assert isinstance(msg, bytes), 'Msg is bytes'
    sk = sk[::-1]

    h = to_hash(sk)
    a = 2**(B - 2) + sum(2**i * bit(h, i) for i in range(3, B - 2))
    A = decodepoint(pk)
    g = encodepoint(scalarmult(A, a))
    salt = urandom(32)
    iv = urandom(16)
    key_int = int.from_bytes(g, 'big') ^ int.from_bytes(salt, 'big')
    shared_key = to_hash_sha3_256(key_int.to_bytes(32, 'big'))
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    encrypted_msg = cipher.encrypt(pad(msg, AES.block_size))
    return salt + iv + encrypted_msg


def decrypt(sk, pk, enc):
    if isinstance(sk, str):
        sk = a2b_hex(sk)
    if isinstance(pk, str):
        pk = a2b_hex(pk)
    assert len(sk) == 32, 'SK is 32bytes, not "{}"'.format(sk)
    assert len(pk) == 32, 'PK is 32bytes, not "{}"'.format(pk)
    assert isinstance(enc, bytes), 'Enc is bytes'
    sk = sk[::-1]

    salt, iv, encrypted_msg = enc[:32], enc[32:32 + 16], enc[32 + 16:]
    h = to_hash(sk)
    a = 2**(B - 2) + sum(2**i * bit(h, i) for i in range(3, B - 2))
    A = decodepoint(pk)
    g = encodepoint(scalarmult(A, a))
    key_int = int.from_bytes(g, 'big') ^ int.from_bytes(salt, 'big')
    shared_key = to_hash_sha3_256(key_int.to_bytes(32, 'big'))
    cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(encrypted_msg)
    return unpad(dec, AES.block_size)
