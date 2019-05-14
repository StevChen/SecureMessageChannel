from os import chmod
from Crypto.PublicKey import RSA

key = RSA.generate(2048)
with open("./client_1/private.key", 'wb+') as content_file:
    content_file.write(key.exportKey('PEM'))
pubkey = key.publickey()
with open("./client_1/public.key", 'wb+') as content_file:
    content_file.write(pubkey.exportKey('PEM'))