from pwn import *

r = remote('cns.csie.org', 44398)
r.sendlineafter(b'6. Exit\n', b'1')
_ = r.recvuntil(b'(Hex-encoded) : ')
affine = r.recvline().decode().strip('\n')
_ = r.recvuntil(b'my passphrase is "')
hint = r.recvline().decode().strip('\n').strip('"').encode()
ciphertext = bytes.fromhex(affine)
r.close()
print(ciphertext, hint)
for N in range(1000):
    try:
        a = (hint[1] - hint[0]) * pow(ciphertext[1] - ciphertext[0], -1, N) % N
        b = (hint[0] - a * ciphertext[0]) % N
        if bytes([(a*c+b) % N for c in ciphertext]).decode()[:2] == hint.decode():
            print(N, a, b, bytes([(a*c+b) % N for c in ciphertext]).decode())
    except:
        pass

