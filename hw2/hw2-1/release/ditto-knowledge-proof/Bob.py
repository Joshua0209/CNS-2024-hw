#!/usr/bin/env python3

from public import Alice_Pub_Key, Admin_Pub_Key, Carrol_Pub_Key
from utils import alarm, verifier_interactive_mode, verifier_non_interactive_mode, elgamal_encryption, random_number_generator
from secret import FLAG1, FLAG2, FLAG3, FLAG4
import random
import secrets

class my_super_secure_random_number_generator(random_number_generator):
    def __init__(self, p):
        self.state = int.from_bytes(secrets.token_bytes(64), 'big')
        self.a = 0xc814b5bd7461e52483115b6fff1c020c96f1a90ce173a0877e7579acff457864eb5185531123b965f68286988b1e55d9c7b06915a8637f63294d661d44939aa7
        self.c = 0x6369d6d9eed8bda45c2764a559500a11a1e695a57554b5f5f904bea20377bd77df435169b8d2e0669fd1a3d4bc4776ef3849d4ae1e3b12e7c80ac23155435b8f
        self.modulus = p
        for _ in range(87):
            self.step()
    
    def step(self):
        self.state = (self.a * self.state + self.c) % self.modulus

    def random(self):
        self.step()
        return self.state
    
class normal_random_number_generator(random_number_generator):
    def __init__(self, p):
        self.p = p
        self.generator = random.randint
    
    def step(self):
        self.generator(1, self.p - 2)
    
    def random(self):
        return self.generator(1, self.p - 2)

def talk_to_Alice(p: int, g: int, y: int, rng: random_number_generator):
    print('Hi Alice, I have to verify your identity first. Please prove that you are Alice by proving that you know the secret key of Alice!')
    if verifier_interactive_mode(p, g, y, rng) == True:
        print(f'You are definitely Alice! Here is the flag for you: {FLAG1}')
    else:
        print('No no no... You are not Alice! Bye!')
    return

def talk_to_Carrol(p: int, g: int, y: int, rng: random_number_generator):
    print('Hi Carrol, I have to verify your identity first. Please prove that you are Carrol by proving that you know the secret key of Carrol!')
    if verifier_interactive_mode(p, g, y, rng) == True:
        print(f'You are definitely Carrol! Here is the flag for you: {FLAG2}')
    else:
        print('No no no... You are not Carrol! Bye!')

def talk_to_Admin():
    print('Hi Admin, I have to verify your identity first. Please prove that you are Admin by proving that you know the secret key of Admin!')
    p, g, y = Admin_Pub_Key['p'], Admin_Pub_Key['g'], Admin_Pub_Key['y']
    if verifier_non_interactive_mode(p, g, y) == True:
        print(f'You are definitely Admin! Here is the flag for you: {FLAG3}')
        print('Since you are Admin and you prove that you have the secret key, I will encrypt the FLAG4 for you to prevent eavesdropping!')
        c1, c2 = elgamal_encryption(p, g, y, FLAG4.encode())
        print(f'c1 = {c1}')
        print(f'c2 = {c2}')
    else:
        print('No no no... You are not Admin! Bye!')
    pass


if __name__ == '__main__':
    
    alarm(300)
    Alice_p, Alice_g, Alice_y = Alice_Pub_Key['p'], Alice_Pub_Key['g'], Alice_Pub_Key['y']
    Carrol_p, Carrol_g, Carrol_y = Carrol_Pub_Key['p'], Carrol_Pub_Key['g'], Carrol_Pub_Key['y']
    normal_rng = normal_random_number_generator(Alice_p)
    secure_rng = my_super_secure_random_number_generator(Carrol_p)
    while True:
        identity = input('Hello, here is Bob! Who are talking to me?\n> ').strip()
        if identity == 'Alice':
            talk_to_Alice(Alice_p, Alice_g, Alice_y, normal_rng)
        elif identity == 'Carrol':
            talk_to_Carrol(Carrol_p, Carrol_g, Carrol_y, secure_rng)
        elif identity == 'Admin':
            talk_to_Admin()
        else:
            print('I don\'t know you! My mom say don\'t talk with stranger, so bye~~')
            exit(1)