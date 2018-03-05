#!/user/env python3
# -*- coding: utf-8 -*-

"""
this code is a cleaned version of http://ed25519.cr.yp.to/python/ed25519.py for python3

code released under the terms of the GNU Public License v3, copyleft 2015 yoochan

http://code.activestate.com/recipes/579102-ed25519/
"""

from .key import secret_key, public_key, get_address, is_address
from .encrypt import encrypt, decrypt
from .signature import sign, verify
import base64
import binascii


def encoding(data, encode):
    if encode == 'raw':
        return data
    elif encode == 'base64':
        return base64.b64encode(data).decode()
    elif encode == 'hex':
        return binascii.hexlify(data).decode()
    else:
        raise TypeError('encode is \"raw\" or \"base64\" or \"hex\"')


def decoding(data):
    if isinstance(data, bytes):
        return data
    try:
        return base64.b64decode(data.encode(), validate=True)
    except (binascii.Error, UnicodeDecodeError):
        return binascii.unhexlify(data.encode())


class Encryption:
    def __init__(self, main_net=True, prefix=None):
        self.main_net = main_net
        self.prefix = prefix
        self.sk = None
        self.pk = None
        self.ck = None

    def secret_key(self, seed=None):
        self.sk = secret_key(seed)
        return self.sk

    def public_key(self, sk=None):
        self.pk = public_key(sk if sk else self.sk)
        return self.pk

    def get_address(self, pk=None):
        self.ck = get_address(pk if pk else self.pk, self.main_net, self.prefix)
        return self.ck

    def is_address(self, ck=None):
        return is_address(ck if ck else self.ck)

    def sign(self, msg, encode='hex'):
        return encoding(sign(msg, self.sk, self.pk), encode)

    def verify(self, msg, signature):
        verify(msg, decoding(signature), pk=self.pk)

    def encrypt(self, recipient_pk, msg, encode='hex'):
        return encoding(encrypt(self.sk, recipient_pk, msg), encode)

    def decrypt(self, sender_pk, enc):
        return decrypt(self.sk, sender_pk, decoding(enc))
