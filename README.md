nem-ed25519(Rust impl ver)
===========
NEM implementation ed26619 crypto modules for Python.  
NEM use Keccak hash function, not same SHA3.

Require
-------
* Python3 (>=3.5)
* Rust **nightly**

how to use
-----
Please look [test codes folder.](test)

Install
------
install from specific branch **rust-ver**
```bash
pip3 install --user git+https://github.com/namuyan/nem-ed25519@rust-ver
```

Samples1
------
```python
from nem_ed25519 import *
# secret key
sk = secret_key()
# public key
pk = public_key(sk)
# compressed key
ck = get_address(pk, main_net=True)
# encoded key
ek = get_ek(pk, prefix=b'\x00')
pk_copy = decode_ek(ek)
 
from nem_ed25519 import sign, verify
# sign message
sign = sign(msg=b'hello world', sk=sk)
# verify message
verify(msg=b'hello world', sign=sign, pk=pk)
 
from nem_ed25519 import encrypt, decrypt
# encrypt/decrypt message
sk1 = secret_key()
pk1 = public_key(sk1)
enc = encrypt(sk=sk, pk=pk1, msg=b'Hot potato.')
dec = decrypt(sk=sk1, pk=pk, enc=enc)
```

warning: delete **Encryption** class

bench
----
| action  | master | rust-ver | times | 
| ----    | ----   | ----     | ----   |
|address generate | 5.8mS | 0.045mS | 128 |
|sign/verify | 3.211mS | 0.13mS | 24 |
|encrypt/decrypt | 2.92mS | 0.246uS | 12 |

Author
------
[@namuyan_mine](http://twitter.com/namuyan_mine/)

Licence
-------
MIT
