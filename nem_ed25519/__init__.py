try:
    import sha3
except ImportError:
    raise Exception('You need install manually by\n'
                    '# pyp3 install --user git+https://github.com/jameshilliard/pysha3@pypy3\n'
                    'check the version, **pypy3** is important.')

from .key import secret_key, public_key, get_address, dummy_address, is_address, convert_address
from .signature import sign, verify
from .encrypt import encrypt, decrypt
__all__ = [
    "secret_key", "public_key", "get_address", "dummy_address", "is_address", "convert_address",
    "sign", "verify", "encrypt", "decrypt"
]
