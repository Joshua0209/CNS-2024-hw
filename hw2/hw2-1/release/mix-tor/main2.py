#!/usr/bin/env python3
import random
import time
from lib import Packet, PublicKeyCipher

from secret import flag2

def main():
    pk, sk = {}, {}
    num_server = 10
    route_length = 5
    for i in range(num_server):
        pk[i], sk[i] = PublicKeyCipher.gen_key()
        print(f'The public key of server {i} is {pk[i]}')
    pk[num_server], sk[num_server] = PublicKeyCipher.gen_key()
    print(f'The public key of Bob is {pk[num_server]}\n')

    route = [random.choice(range(num_server))]
    while len(route) < route_length:
        route.append(random.choice([i for i in range(num_server) if i != route[-1]]))
    route.append(num_server)
    
    print(f'Send the message "Give me flag, now!" to Bob')
    print(f'The route of the packet should be {route}, where {num_server} stands for Bob')
    print(f'Now, send packet to server {route[0]} (hex encoded):')
    raw = input('> ')
    packet = Packet(bytes.fromhex(raw))

    print(f'processing ...')
    time.sleep(1)
    print(route)
    try:
        for i in range(len(route) - 1):
            next_hop, next_packet = packet.decrypt_server(sk[route[i]])
            print(next_hop)
            assert next_hop == route[i+1]
            packet = next_packet
        message = packet.decrypt_client(sk[num_server])
        assert message == b'Give me flag, now!'
    except Exception as e:
        print(e)
        print(f'Bob: I cannot hear you!')
        exit()

    print(f'Bob: {flag2}')


if __name__ == '__main__':
    main()

