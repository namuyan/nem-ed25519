from .key import secret_key, public_key, get_address, dummy_address, is_address, convert_address
from .signature import sign, verify
from .encrypt import encrypt, decrypt

"""
NB: This code is not safe for use with secret keys or secret data.
The only safe use of this code is for verifying signatures on public messages.
Functions for computing the public key of a secret key and for signing
a message are included, namely publickey_unsafe and signature_unsafe,
for testing purposes only.
The root of the problem is that Python's long-integer arithmetic is
not designed for use in cryptography.  Specifically, it may take more
or less time to execute an operation depending on the values of the
inputs, and its memory access patterns may also depend on the inputs.
This opens it to timing and cache side-channel attacks which can
disclose data to an attacker.  We rely on Python's long-integer
arithmetic, so we cannot handle secrets without risking their disclosure.
"""

__all__ = [
    "secret_key",
    "public_key",
    "get_address",
    "dummy_address",
    "is_address",
    "convert_address",
    "sign",
    "verify",
    "encrypt",
    "decrypt",
]
