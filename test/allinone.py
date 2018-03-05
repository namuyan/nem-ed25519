from nem_ed25519.base import Encryption

ecc = Encryption()

print("sk", ecc.secret_key())
print("pk", ecc.public_key())
print("ck", ecc.get_address())

msg = b'hello world nice day.'
signature = ecc.sign(msg, encode='base64')
print("sign", signature)
ecc.verify(msg, signature)

enc = ecc.encrypt(ecc.pk, msg, encode='base64')
print(enc)
print(ecc.decrypt(ecc.pk, enc))
