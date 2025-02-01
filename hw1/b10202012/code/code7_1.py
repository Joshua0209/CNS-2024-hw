from Crypto.Util.number import long_to_bytes
from pwn import *
# from Crypto.Cipher import AES
import binascii
r = remote('cns.csie.org', 1337)
r.sendlineafter(b"Your choice: ", b'1')
c = r.recvuntil(b'Please select an option:').decode()
c = binascii.unhexlify(c.split('\n')[1])

# print(c)
assert len(c) % 16 == 0

BLOCKSIZE = 16
blocknum = len(c) // 16

# this block can be removed. Just in case there are termination due to timeout, it can continue perform poa
# broke = b'over the 1st flag\nThe 1st flag is CNS{p4dd1n9_0r4cl3_4tt4ck_15_315_3v1l}! By the way, there is anoth is another one, please send another request to get it.\n\n'
# decrypted = bytearray()
# if len(broke) > 1:
#     blocknum = (len(c) - len(broke)) // 16 + 1
#     decrypted = broke[len(c) % 16:]
    
    
for block in range(blocknum-1, 0, -1):
    prefix, b_block, z_block = c[:(block-1)*BLOCKSIZE], c[(block-1)*BLOCKSIZE : block*BLOCKSIZE], c[block*BLOCKSIZE : (block+1)*BLOCKSIZE]
    decrypted_block = bytearray()
    for z in range(BLOCKSIZE-1,-1,-1):
        guess_block = bytearray(b_block)
        if (z+1<BLOCKSIZE):
            for pad in range(z+1, BLOCKSIZE, 1):
                guess_block[pad] = long_to_bytes(b_block[pad] ^ decrypted_block[pad-z-1] ^ ((BLOCKSIZE-z)+8))[0]
            
        for guess in range(256):
            flag = False
            guess_block[z] = guess
            
            
            r.sendlineafter(b"Your choice: ", b'3')
            s = binascii.hexlify(prefix+bytes(guess_block)+z_block)
            r.sendlineafter(b"Your encrypted message: ", s)
            out = r.recvuntil(b'4) Exit\n')
            if "Message sent!" in out.decode():
                p = long_to_bytes(guess ^ b_block[z] ^ ((BLOCKSIZE-z)+8))
                decrypted_block = bytearray(p) + decrypted_block
                print(f'Attacking {block},{z}: ', end='')
                print(bytes(decrypted_block+decrypted))
                flag = True
                break
            elif "Invalid message" in out.decode():
                # print(guess)
                continue
            else:
                print("Unknown: "+out.decode())
        assert flag == True 
    decrypted = decrypted_block + decrypted
    print(bytes(decrypted))
    