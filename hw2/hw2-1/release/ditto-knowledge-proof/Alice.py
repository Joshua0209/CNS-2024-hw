#!/usr/bin/env python3

import random
from utils import alarm
from public import Alice_Pub_Key
from secret import alice_private_key

def connect_to_bob():
    print('Connecting to bob...')

def send_identity_to_bob():
    print('Alice')

def send_proof_to_bob(p: int, g: int, y: int, x: int):
    
    # send a after received request
    r = random.randint(1, p - 2)
    a = pow(g, r, p)
    print(f'a = {a}')

    # Receive challenge from Bob
    try:
        c = int(input('c = ').strip())
    except:
        print('Invalid input! You are weird! Bye!')
        exit(1)
    
    # Compute w and send it back to bob
    w = c * x + r
    print(f'w = {w}')

if __name__ == '__main__':
    alarm(300)
    
    p, g, y = Alice_Pub_Key['p'], Alice_Pub_Key['g'], Alice_Pub_Key['y']
    x = alice_private_key
    y = pow(g, x, p)
    assert y == Alice_Pub_Key['y']

    while True:
        connect_to_bob()
        send_identity_to_bob()
        send_proof_to_bob(p, g, y, x)
        mode = input('Continue to talk with Bob? (y/n)\n> ').strip()
        if mode == 'y':
            continue
        else:
            break
        