#!/user/env python3
# -*- coding: utf-8 -*-

"""
this code is a cleaned version of http://ed25519.cr.yp.to/python/ed25519.py for python3

code released under the terms of the GNU Public License v3, copyleft 2015 yoochan

http://code.activestate.com/recipes/579102-ed25519/
"""

from Cryptodome.Cipher import AES
from Cryptodome.Hash import RIPEMD160
from base64 import b32encode, b32decode
from binascii import hexlify, unhexlify
from os import urandom
from .utils import *


class Ed25519:
    @staticmethod
    def secret_key(seed=None):
        if seed is None:
            seed = urandom(32)
        assert len(seed) == 32 and isinstance(seed, bytes), 'seed is byte or None, and bytes'
        h = to_hash(seed)
        i = as_key(h)
        k = to_bytes(i)
        return hexlify(k).decode()

    @staticmethod
    def public_key(sk):
        assert isinstance(sk, str), 'SK is hex str.'
        h = to_hash(unhexlify(sk.encode())[::-1])
        k = as_key(h)
        c = outer(B_POINT, k)
        return hexlify(point_to_bytes(c)).decode()

    @staticmethod
    def get_address(pk, main_net=True):
        """ compute the nem-py address from the public one """
        k = sha3_256(unhexlify(pk.encode())).digest()
        ripe = RIPEMD160.new(k).digest()
        body = (b"\x68" if main_net else b"\x98") + ripe
        checksum = sha3_256(body).digest()[0:4]
        return b32encode(body + checksum).decode()

    @staticmethod
    def is_address(ck):
        raw = b32decode(ck.encode())
        header, ripe, checksum = raw[:1], raw[1:1+20], raw[1+20:]
        return checksum == sha3_256(header + ripe).digest()[0:4]

    @staticmethod
    def sign(msg, sk, pk):
        assert isinstance(msg, bytes), 'Msg is bytes'
        assert isinstance(sk, str), 'SK is hex str'
        assert isinstance(pk, str), 'PK is hex str'
        sk = unhexlify(sk.encode())[::-1]
        pk = unhexlify(pk.encode())

        h = to_hash(sk)
        a = 2 ** (B - 2) + sum(2 ** i * bit(h, i) for i in range(3, B - 2))

        m_raw = bytes([getitem(h, j) for j in range(B // 8, B // 4)]) + msg
        r = Hint_hash(m_raw)

        R = scalarmult_B(r)
        S = (r + Hint_hash(encodepoint(R) + pk + msg) * a) % L
        return encodepoint(R) + encodeint(S)

    @staticmethod
    def verify(msg, sign, pk):
        assert isinstance(msg, bytes), 'Msg is bytes'
        assert isinstance(sign, bytes), 'Sign is bytes'
        assert isinstance(pk, str), 'PK is hex str'
        pk = unhexlify(pk.encode())
        if len(sign) != B // 4:
            raise ValueError("signature length is wrong")

        if len(pk) != B // 8:
            raise ValueError("public-key length is wrong")

        try:
            R = decodepoint(sign[:B // 8])
            A = decodepoint(pk)
            S = decodeint(sign[B // 8:B // 4])
            h = Hint_hash(encodepoint(R) + pk + msg)

            (x1, y1, z1, t1) = P = scalarmult_B(S)
            (x2, y2, z2, t2) = Q = edwards_add(R, scalarmult(A, h))

            f_P_on = not isoncurve(P)
            f_Q_on = not isoncurve(Q)
            f_X_on = (x1 * z2 - x2 * z1) % PRIME != 0
            f_Y_on = (y1 * z2 - y2 * z1) % PRIME != 0
        except Exception as e:
            raise ValueError(e)

        if f_P_on or f_Q_on or f_X_on or f_Y_on:
            raise ValueError('Not correct signature.')

    @staticmethod
    def encrypt(sk, pk, msg):
        assert isinstance(sk, str), 'SK is hex str'
        assert isinstance(pk, str), 'PK is hex str'
        assert isinstance(msg, bytes), 'Msg is bytes'
        sk = unhexlify(sk.encode())[::-1]
        pk = unhexlify(pk.encode())

        h = to_hash(sk)
        a = 2 ** (B - 2) + sum(2 ** i * bit(h, i) for i in range(3, B - 2))
        A = decodepoint(pk)
        g = encodepoint(scalarmult(A, a))
        salt = urandom(32)
        iv = urandom(16)
        key_int = int.from_bytes(g, 'big') ^ int.from_bytes(salt, 'big')
        shared_key = to_hash_sha3_256(key_int.to_bytes(32, 'big'))
        cipher = AES.new(shared_key, AES.MODE_CBC, iv)
        encrypted_msg = cipher.encrypt(pad(msg))
        return salt + iv + encrypted_msg

    @staticmethod
    def decrypt(sk, pk, enc):
        assert isinstance(sk, str), 'SK is hex str'
        assert isinstance(pk, str), 'PK is hex str'
        assert isinstance(enc, bytes), 'Enc is bytes'
        sk = unhexlify(sk.encode())[::-1]
        pk = unhexlify(pk.encode())

        salt, iv, encrypted_msg = enc[:32], enc[32:32+16], enc[32+16:]
        h = to_hash(sk)
        a = 2 ** (B - 2) + sum(2 ** i * bit(h, i) for i in range(3, B - 2))
        A = decodepoint(pk)
        g = encodepoint(scalarmult(A, a))
        key_int = int.from_bytes(g, 'big') ^ int.from_bytes(salt, 'big')
        shared_key = to_hash_sha3_256(key_int.to_bytes(32, 'big'))
        cipher = AES.new(shared_key, AES.MODE_CBC, iv)
        decrypt = cipher.decrypt(encrypted_msg)
        return unpad(decrypt)
