from pwn import *
from secretpy import Zigzag

r = remote('cns.csie.org', 44398)
r.sendlineafter(b'6. Exit\n', b'1')
_ = r.recvuntil(b'(Hex-encoded) : ')
_ = r.recvuntil(b'(Hex-encoded) : ')
bob = r.recvline().decode().strip('\n')
ciphertext = bytes.fromhex(bob).decode()
r.close()
print(ciphertext)

chipher = Zigzag()
for i in range(2, len(ciphertext), 1):
    dec = chipher.decrypt(ciphertext, i)
    print(dec)

