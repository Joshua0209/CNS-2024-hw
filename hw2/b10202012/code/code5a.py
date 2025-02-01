from pwn import *
alice = remote('cns.csie.org', 23461)
bob = remote('cns.csie.org', 23462)


bob.sendlineafter(b' to me?', b'Alice')
alice.recvuntil(b'a = ')
a = alice.recvuntil(b'\n')
bob.sendafter(b'a = ', a)
bob.recvuntil(b'c = ')
c = bob.recvuntil(b'\n')
alice.sendafter(b'c = ', c)
alice.recvuntil(b'w = ')
w = alice.recvuntil(b'\n')
bob.sendafter(b'w = ', w)
flag = bob.recvuntil(b'\n')
alice.close()
bob.close()
print(flag)
