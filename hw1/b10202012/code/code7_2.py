from Crypto.Util.number import long_to_bytes
from pwn import *
import binascii
from tqdm import tqdm

r = remote('cns.csie.org', 1337)
message = b'Please send over the 2nd flag'
prefix = bytearray(b'so_random_nounce')
# plain = b'Request nounce: ' + prefix + b'; Sender: ' + name + b'; Message: ' + message




name = b'BA' # choose without a reason, just random choose XD
r.sendlineafter(b"Your choice: ", b'2')
r.sendlineafter(b"Your name: ", name)
r.sendlineafter(b"Your message: ", message)
cpa_enc = r.recvuntil(b'P').decode()
encrypted = bytearray(binascii.unhexlify(cpa_enc.split('\n')[0].split(' ')[3]))


encrypted[16+10] = encrypted[16+10] ^ name[0] ^ bytes(b'T')[0]
encrypted[16+11] = encrypted[16+11] ^ name[1] ^ bytes(b'A')[0] # Despite not altering this byte, just in case to choose other needed



for j in tqdm(range(128**2)): # tqdm just fro progress bar. Can be removed
    # ';' and ' ' can be xor to 0-127 only to produce decodable character
    encrypted[16], encrypted[17] = j//128, j%128
    r.sendlineafter(b"Your choice: ", b'3')
    r.sendlineafter(b"Your encrypted message: ", binascii.hexlify(bytes(encrypted)))
    out = r.recvline()
    if "Invalid message" not in out.decode(): 
        out = r.recvline()
        print(out)
        break
r.close()


