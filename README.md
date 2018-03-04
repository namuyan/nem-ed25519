nem-ed25519
===========
NEM implementation ed26619 encryption modules for Python.  
NEM use Keccak hash function, not same SHA3.

Require
-------
Python3 (>=3.5)

how to use
-----
Please look [test codes folder.](test)

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
```python
from nem_ed25519.base import Ed25519 as ecc
sk = ecc.secret_key()
pk = ecc.public_key(sk)
ck = ecc.get_address(pk)
ecc.is_address(ck)
ecc.sign()
ecc.verify()
ecc.encrypt()
ecc.decrypt()
```

Author
------
[@namuyan_mine](http://twitter.com/namuyan_mine/)

Licence
-------
MIT
