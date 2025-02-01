#!/usr/bin/env python3

import random
from public import Admin_Pub_Key
from secret import admin_private_key
from utils import H

def connect_to_bob():
    print('Connecting to bob...')

def send_identity_to_bob():
    print('Admin')

def send_non_interactive_proof_to_bob(p: int, g: int, y: int, x: int):
    r = random.randint(1, p - 2)
    a = pow(g, r, p)
    print(f'a = {a}')
    c = H(p, g, y, a)
    w = c * x + r
    print(f'w = {w}')

    # Save it at private.py! Hopefully i save it on correct file ><
    f = open('public.py', 'a+')
    f.write(f'admin_a = {a}\nadmin_w = {w}\n')
    f.close()

if __name__ == '__main__':
    p, g, y = Admin_Pub_Key['p'], Admin_Pub_Key['g'], Admin_Pub_Key['y']
    x = admin_private_key
    y = pow(g, x, p)
    assert y == Admin_Pub_Key['y']

    connect_to_bob()
    send_identity_to_bob()
    send_non_interactive_proof_to_bob(p, g, y, x)