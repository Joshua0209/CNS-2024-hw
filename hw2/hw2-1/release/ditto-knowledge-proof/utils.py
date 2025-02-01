import signal
import hashlib
import random
from binascii import unhexlify
from Crypto.Util.number import bytes_to_long

class random_number_generator:
    def __init__(self, p):
        pass

    def step(self):
        pass
    
    def random(self):
        pass

# Timeout
def alarm(second):
    def handler(signum, frame):
        print('I think you are disconnect... Bye!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

def H(*args):
    sha512 = hashlib.sha512()
    for arg in args:
        sha512.update(str(arg).encode())
    output = unhexlify(sha512.hexdigest())
    return int.from_bytes(output, 'big')

def verifier_interactive_mode(p: int, g: int, y: int, rng: random_number_generator):
    try:
        a = int(input('a = '))
        assert a > 0 and a < p
    except:
        print('Invalid input! You are weird! Bye!')
        exit(1)
    
    c = rng.random()
    print('c =', c)
    try:
        w = int(input('w = '))
    except:
        print('Invalid input! You are weird! Bye!')
        exit(1)
    
    if pow(g, w, p) == (pow(y, c, p) * a) % p:
        return True
    else:
        return False

def verifier_non_interactive_mode(p: int, g: int, y: int):
    try:
        a = int(input('a = '))
        assert a > 0 and a < p
    except:
        print('Invalid input! You are weird! Bye!')
        exit(1)
    
    c = H(p, g, y, a)

    try:
        w = int(input('w = '))
    except:
        print('Invalid input! You are weird! Bye!')
        exit(1)
    
    if pow(g, w, p) == (pow(y, c, p) * a) % p:
        return True
    else:
        return False


def elgamal_encryption(p: int, g: int, y: int, m: bytes) -> bytes:
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (pow(y, k, p) * bytes_to_long(m)) % p
    return c1, c2