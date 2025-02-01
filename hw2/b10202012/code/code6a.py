'''
The public key of server0 is (223239029349511565359559114673362089769, 65537)
The public key of server1 is (243320571577609043317557603198333182621, 65537)
The public key of server2 is (107975221609576674920863384563571288571, 65537)
The public key of Bob is (251729791461667492614120633558716606903, 65537)

Your public key is (119624665184809340661645029835519155909, 65537)
Your private key is (119624665184809340661645029835519155909, 65040903528240707310554544997049741153)

In the following, the packets arrived at your mix will be printed apperiodically.
You can send packets directly at any moment using the format "(next hop, hex encoded message)".
For example, if you want to send a packet to server0, you can send "(0, packet.data.hex())".
Wait for 3 seconds to start ...
'''
from pwn import *
from code6b_lib import Packet

def revkey():
    raw = r.recvline().decode()
    n = int(raw[raw.find('(')+1: raw.find(',')])
    e = int(raw[raw.find(',')+2: raw.find(')')])    
    return (n, e)

r = remote('cns.csie.org', 3001)

r.recvuntil(b'Your')
my_pk = revkey()
my_sk = revkey()

r.recvuntil(b'start')
r.recvline()
packets = []
packet = r.recvline().strip()
while b'CNS' not in packet:
    next_hop, message = Packet(bytes.fromhex(packet.decode())).decrypt_server(my_sk)
    packets.append(f"({next_hop}, {message.data.hex()})".encode())
    if len(packets) >= 10:
        random.shuffle(packets)
        r.sendline(b'\n'.join(packets))
        packets = []

    packet = r.recvuntil((b'}',b'\n')).strip()
    print('buffer: ' + str(len(packets)))


print(packet)

r.close()