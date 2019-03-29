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

Install
------
```commandline
pip install nem-ed25519
 or
pip install git+https://github.com/namuyan/nem-ed25519.git
```

This version need GMP.  
*For Linux*  
```
apt-get install python3-gmpy2 libgmp3-dev libmpc-dev
apt install libmpfr-dev
pip install gmpy2
```  
  
*For windows*  
Download [pythonlibs](https://www.lfd.uci.edu/~gohlke/pythonlibs/#gmpy)  
`pip install gmpy2‑2.0.8‑cp36‑cp36m‑win_amd64.whl` If you use Python3.6 64bit

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

warning: delete **Encryption** class

Author
------
[@namuyan_mine](http://twitter.com/namuyan_mine/)

Licence
-------
MIT
