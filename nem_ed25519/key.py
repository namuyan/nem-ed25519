from os import urandom
from nem_ed25519.utils import *
from binascii import hexlify, unhexlify
from Cryptodome.Hash import RIPEMD160
from base64 import b32decode, b32encode


def encoder(data, encode):
    if encode is str:
        return hexlify(data).decode()
    else:
        return data


def secret_key(seed=None, encode=str):
    if seed is None:
        seed = urandom(32)
    assert isinstance(seed, bytes), 'seed is byte or None.'
    h = to_hash(seed)
    i = as_key(h)
    k = to_bytes(i)
    return encoder(data=k, encode=encode)


def public_key(sk, encode=str):
    if isinstance(sk, str):
        sk = unhexlify(sk.encode())
    assert len(sk) == 32, 'SK is 32bytes. {}'.format(len(sk))
    h = to_hash(sk[::-1])
    k = as_key(h)
    c = outer(B_POINT, k)
    p = point_to_bytes(c)
    return encoder(data=p, encode=encode)


def get_address(pk, main_net=True, prefix=None):
    """ compute the nem-py address from the public one """
    if isinstance(pk, str):
        pk = unhexlify(pk.encode())
    assert len(pk) == 32, 'PK is 32bytes {}'.format(len(pk))
    k = sha3_256(pk).digest()
    ripe = RIPEMD160.new(k).digest()
    if prefix is None:
        body = (b"\x68" if main_net else b"\x98") + ripe
    else:
        assert isinstance(prefix, bytes), 'Set prefix 1 bytes'
        body = prefix + ripe
    checksum = sha3_256(body).digest()[0:4]
    return b32encode(body + checksum).decode()


def dummy_address(startwith, padding=b'\x00'):
    dummy_body = b32decode(startwith + '=' * (8 - len(startwith) % 8))
    body = dummy_body + padding * (21 - len(dummy_body))
    checksum = sha3_256(body).digest()[0:4]
    return b32encode(body + checksum).decode()


def is_address(ck, prefix=None):
    raw = b32decode(ck.encode())
    header, ripe, checksum = raw[:1], raw[1:1 + 20], raw[1 + 20:]
    f_body = (checksum == sha3_256(header + ripe).digest()[0:4])
    f_header = (prefix is None or header == prefix)
    return f_body and f_header


def convert_address(ck, prefix):
    raw = b32decode(ck.encode())
    header, ripe, checksum = raw[:1], raw[1:1 + 20], raw[1 + 20:]
    body = prefix + ripe
    checksum_new = sha3_256(body).digest()[0:4]
    return b32encode(body + checksum_new).decode()
