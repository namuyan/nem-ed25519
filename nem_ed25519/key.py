#!/user/env python3
# -*- coding: utf-8 -*-

from os import urandom
from .utils import *
from binascii import hexlify, unhexlify
from Cryptodome.Hash import RIPEMD160
from base64 import b32decode, b32encode


def secret_key(seed=None):
    if seed is None:
        seed = urandom(32)
    assert isinstance(seed, bytes), 'seed is byte or None.'
    h = to_hash(seed)
    i = as_key(h)
    k = to_bytes(i)
    return hexlify(k).decode()


def public_key(sk):
    assert isinstance(sk, str), 'SK is hex str.'
    h = to_hash(unhexlify(sk.encode())[::-1])
    k = as_key(h)
    c = outer(B_POINT, k)
    return hexlify(point_to_bytes(c)).decode()


def get_address(pk, main_net=True, prefix=None):
    """ compute the nem-py address from the public one """
    k = keccak_256(unhexlify(pk.encode())).digest()
    ripe = RIPEMD160.new(k).digest()
    if prefix is None:
        body = (b"\x68" if main_net else b"\x98") + ripe
    else:
        assert isinstance(prefix, bytes), 'Set prefix 1 bytes'
        body = prefix + ripe
    checksum = keccak_256(body).digest()[0:4]
    return b32encode(body + checksum).decode()


def is_address(ck, prefix=None):
    raw = b32decode(ck.encode())
    header, ripe, checksum = raw[:1], raw[1:1 + 20], raw[1 + 20:]
    f_body = (checksum == keccak_256(header + ripe).digest()[0:4])
    f_header = (prefix is None or header == prefix)
    return f_body and f_header


def convert_address(ck, prefix):
    raw = b32decode(ck.encode())
    header, ripe, checksum = raw[:1], raw[1:1 + 20], raw[1 + 20:]
    body = prefix + ripe
    checksum_new = keccak_256(body).digest()[0:4]
    return b32encode(body + checksum_new).decode()
