'''
The public key of server 0 is (124081970591444116372561135022243731601, 65537)
The public key of server 1 is (295854498024367540663725278816226551969, 65537)
The public key of server 2 is (134138914117932567917324603136497608507, 65537)
The public key of server 3 is (156257727339545029265617037608973270617, 65537)
The public key of server 4 is (202159711191653800813097286403901334349, 65537)
The public key of server 5 is (146130045400700997501888780958133695771, 65537)
The public key of server 6 is (221526572318918879743842744498349535839, 65537)
The public key of server 7 is (263336819223061053405931711084248579899, 65537)
The public key of server 8 is (235231596104415333060701164159845413519, 65537)
The public key of server 9 is (150724314047080947940066983527006076457, 65537)
The public key of Bob is (119290148645885832214960703014816216573, 65537)

Send the message "Give me flag, now!" to Bob
The route of the packet should be [4, 9, 8, 6, 5, 10], where 10 stands for Bob
Now, send packet to server 4 (hex encoded):
>
'''
from pwn import *
from code6b_lib import Packet

def revkey():
    raw = r.recvline().decode()
    n = int(raw[raw.find('(')+1: raw.find(',')])
    e = int(raw[raw.find(',')+2: raw.find(')')])    
    return (n, e)

r = remote('cns.csie.org', 3002)
pk, sk = {}, {}
for i in range(11):
    pk[str(i)] = revkey()

r.recvuntil(b'[')
route = r.recvuntil(b']').decode().strip(']').split(', ')

packet = Packet.create(b'Give me flag, now!', 'Bob', pk['10'])

for i in range(len(route)-2,-1,-1):
    packet.add_next_hop(str(route[i+1]).encode(), pk[route[i]])

r.sendlineafter(b'> ', str(packet.data.hex()).encode())
m = r.recvline()
while b'Bob' not in m:
    m = r.recvline()
print(m)
