from sha3 import keccak_256
from binascii import hexlify, unhexlify
from Cryptodome.Hash import RIPEMD160
from base64 import b32decode, b32encode


def encoder(data, encode):
    if encode is str:
        return hexlify(data).decode()
    else:
        return data


def get_address(pk, main_net=True, prefix=None):
    """ compute the nem-py address from the public one """
    if isinstance(pk, str):
        pk = unhexlify(pk.encode())
    assert len(pk) == 32, 'PK is 32bytes {}'.format(len(pk))
    k = keccak_256(pk).digest()
    ripe = RIPEMD160.new(k).digest()
    if prefix is None:
        body = (b"\x68" if main_net else b"\x98") + ripe
    else:
        assert isinstance(prefix, bytes), 'Set prefix 1 bytes'
        body = prefix + ripe
    checksum = keccak_256(body).digest()[0:4]
    return b32encode(body + checksum).decode()


def dummy_address(startwith, padding=b'\x00'):
    dummy_body = b32decode(startwith + '=' * (8 - len(startwith) % 8))
    body = dummy_body + padding * (21 - len(dummy_body))
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
