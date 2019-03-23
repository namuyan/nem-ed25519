from .key import encoder, get_address, dummy_address, is_address, convert_address
from binascii import a2b_hex
import nem_ed25519_rust


def secret_key(encode=str):
    sk, pk = nem_ed25519_rust.generate_keypair()
    return encoder(data=sk, encode=encode)


def public_key(sk, encode=str):
    if isinstance(sk, str):
        sk = a2b_hex(sk)
    pk = nem_ed25519_rust.secret2public(sk)
    return encoder(data=pk, encode=encode)


def sign(msg, sk, encode=bytes):
    assert isinstance(msg, bytes)
    if isinstance(sk, str):
        sk = a2b_hex(sk)
    sig = nem_ed25519_rust.sign(msg, sk)
    return encoder(data=sig, encode=encode)


def verify(msg, sign, pk):
    assert isinstance(msg, bytes)
    if isinstance(sign, str):
        sign = a2b_hex(sign)
    if isinstance(pk, str):
        pk = a2b_hex(pk)
    nem_ed25519_rust.verify(msg, sign, pk)


def encrypt(sk, pk, msg, encode=bytes):
    if isinstance(sk, str):
        sk = a2b_hex(sk)
    if isinstance(pk, str):
        pk = a2b_hex(pk)
    assert isinstance(msg, bytes)
    enc = nem_ed25519_rust.encrypt(sk, pk, msg)
    return encoder(data=enc, encode=encode)


def decrypt(sk, pk, enc):
    if isinstance(sk, str):
        sk = a2b_hex(sk)
    if isinstance(pk, str):
        pk = a2b_hex(pk)
    if isinstance(enc, str):
        enc = a2b_hex(enc)
    return nem_ed25519_rust.decrypt(sk, pk, enc)


class Encrypt(object):
    def __init__(self, your_sk, other_pk):
        self.your_sk = your_sk
        self.other_pk = other_pk

    @classmethod
    def new(cls, other_pk):
        sk, pk = nem_ed25519_rust.generate_keypair()
        return cls(your_sk=sk, other_pk=other_pk)

    @property
    def sk(self):
        return self.your_sk.hex()

    @property
    def pk(self):
        return public_key(sk=self.your_sk)

    def sign(self, msg, encode=bytes):
        return sign(msg=msg, sk=self.your_sk, encode=encode)

    def verify(self, msg, sig):
        return verify(msg=msg, sign=sig, pk=self.other_pk)

    def encrypt(self, msg, encode=bytes):
        return encrypt(sk=self.your_sk, pk=self.other_pk, msg=msg, encode=encode)

    def decrypt(self, enc):
        decrypt(sk=self.your_sk, pk=self.other_pk, enc=enc)


__all__ = [
    "secret_key",
    "public_key",
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "Encrypt",
    "get_address",
    "dummy_address",
    "is_address",
    "convert_address",
]
