from pwn import *
import base64
from itertools import product, cycle
from tqdm import tqdm

r=remote('cns.csie.org', 44398)
r.sendlineafter(b"6. Exit\n", b'1')
out = r.recvuntil(b'I \'encrypt\'').decode()
ctext = out.split('\n')[-2].split(' ')[-1]

r.sendlineafter(b"6. Exit\n", b'5')
r.sendlineafter(b"passphrase:", base64.b64decode(bytes.fromhex(ctext)))
ctext = r.recvuntil(b'Please').decode().split('\n')[-2][:-1]
print(ctext)
ctext = bytes.fromhex(ctext)
r.close()

potential_key = [[],[],[],[],[],[]]

# Find possible key individually
for i in range(6):
    for key in range(256):
        plaintext = bytearray([key ^ ctext[j] for j in range(i, len(ctext), 6)])
        try:
            plaintext_str = plaintext.decode('utf-8')
            if plaintext_str.isprintable():
                # print(bytes(plaintext))
                potential_key[i].append(key)
        except UnicodeDecodeError:
            pass

# print([len(potential_key[i]) for i in range(6)])

'''
# Brute force with the key find before
for a in tqdm(range(len(potential_key[0]))):
    for b in tqdm(range(len(potential_key[1])), leave=False):
        for c in tqdm(range(len(potential_key[2])), leave=False):
            for d in range(len(potential_key[3])):
                for e in range(len(potential_key[4])):
                    for f in range(len(potential_key[5])):
                        key = bytearray([potential_key[i][j] for i,j in enumerate([a,b,c,d,e,f])])
                        plaintext = bytearray([x ^ y for x, y in zip(ctext, cycle(key))]).decode()
                        if 'CNS{' in plaintext:
                            print(a,b,c,d,e,f, end=' ')
                            print(bytes(plaintext))
'''

# I found the first four characters are FLAG (Using 'CNS{' in plaintext) 
ans = b'FLAG'
for i in range(4):
    potential_key[i] = [ctext[i]^ans[i]]
# print(potential_key)

for a in range(len(potential_key[4])):
    for b in range(len(potential_key[5])):
        key = bytearray()
        for i in range(6):
            if i<4:
                key.append(potential_key[i][0])
            elif i == 4:
                key.append(potential_key[i][a])
            elif i == 5:
                key.append(potential_key[i][b])
        plaintext = bytearray([x ^ y for x, y in zip(ctext, cycle(key))]).decode()
        
        
        # constraint put after looking partial secret. 
        # Can be removed and using human labored to check the answer
        if 'Don\'t'in plaintext:
            print(plaintext)