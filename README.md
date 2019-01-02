nem-ed25519 (pypy3 version)
===========
NEM implementation ed26619 encryption modules for Python.  
NEM use Keccak hash function, not same SHA3.

Require
-------
Python3 (>=3.5)

how to use
-----
Please look [test codes folder.](test)

Install
------
```commandline
pip install nem-ed25519
 or
pip install git+https://github.com/namuyan/nem-ed25519.git
```

setup
----
**Only work on Linux!**
* `pyp3 install --user pycryptodomex`
* `pyp3 install --user git+https://github.com/jameshilliard/pysha3@pypy3`
* `pyp3 install --user gmpy_cffi`

Samples1
------
```python
from nem_ed25519.key import secret_key, public_key, get_address
# secret key
sk = secret_key()
# public key
pk = public_key(sk)
# compressed key
ck = get_address(pk, main_net=True)
 
from nem_ed25519.signature import sign, verify
# sign message
sign = sign(msg=b'hello world', sk=sk, pk=pk)
# verify message
verify(msg=b'hello world', sign=sign, pk=pk)
 
from nem_ed25519.encrypt import encrypt, decrypt
# encrypt/decrypt message
sk1 = secret_key()
pk1 = public_key(sk1)
enc = encrypt(sk=sk, pk=pk1, msg=b'Hot potato.')
dec = decrypt(sk=sk1, pk=pk, enc=enc)
```

Samples2
--------
Import setting at first, and you can select encode mode.  
Please look at [allinone.py](test/allinone.py)
```python
from nem_ed25519.base import Encryption
ecc = Encryption()
```

Author
------
[@namuyan_mine](http://twitter.com/namuyan_mine/)

Licence
-------
MIT
