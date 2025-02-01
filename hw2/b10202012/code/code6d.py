import socks
import socket
import requests
import base64
import hashlib 

def onion_address_from_public_key(public_key: bytes) -> str:
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    onion_address = "{}.onion".format(
        base64.b32encode(public_key + checksum + version).decode().lower()
    )
    return onion_address

s = socks.socksocket()
with open('tor.pub', 'rb') as f:
    text = f.read()

print(text)
domain = onion_address_from_public_key(bytes(text[32:]))
print(domain)

for i in range(65536):
    try:
        s.connect((domain, i))
        print(i)
    except:
        pass