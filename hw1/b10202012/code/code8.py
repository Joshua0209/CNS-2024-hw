# !pip install length-extension-tool
import hashlib
import HashTools
from pwn import *
import binascii


def sha256(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha256()
    h.update(s)
    return h.digest()

def pow(text, randomstring):
    nonce = randint(1000, 100000)
    nonceString = text + str(nonce)
    while sha256(nonceString)[-3:].hex() != "{:0>6}".format(randomstring):
        nonce = nonce + 1
        nonceString = text + str(nonce)
    # print(nonceString)
    return bytes(nonceString.encode())

def find_col(text):
    nonce = randint(1000, 100000)
    shelf = {}
    productName = text + str(nonce)
    while sha256(productName)[-4:] not in shelf:
        shelf[sha256(productName)[-4:]] = productName
        nonce = nonce + 1
        productName = text + str(nonce)
    
    # print(productName, shelf[sha256(productName)[-4:]])
    return (productName, shelf[sha256(productName)[-4:]])


def stage12(col):
    for i in range(2):
        r.sendlineafter(b'Your choice: ', b'1')
        r.sendlineafter(b'Product name: ', col[i])
        r.sendlineafter(b'Amount: ', b'10')
        # print(r.recvuntil(b'left'))
    
    for _ in range(3):
        r.sendlineafter(b'Your choice: ', b'2')
        # print(r.recvuntil(b'left'))

    r.sendlineafter(b'Your choice: ', b'3')

    flag = r.recvuntil(b'=')
    print(flag)


if __name__ == '__main__':
    # preprocess
    col1 = open('shattered-1.pdf', 'rb').read() + b'CNS2024'
    col2 = open('shattered-2.pdf', 'rb').read() + b'CNS2024'

    r = remote('cns.csie.org', 9010)
    # pow
    randomstring = r.recvuntil(b':')[-7:-1].decode()
    UserX = pow('CNS2024', randomstring)
    r.sendlineafter(b'\n', UserX)
    
    # stage 1
    stage12([col1, col2])
    
    # stage 2
    r.recvuntil(b'Your key is ')
    key = r.recvline().decode().strip('\n').strip('.')
    # print(key)
    col1, col2 = find_col('CNS2024' + key)
    stage12([bytes(col1.encode()), bytes(col2.encode())])
    
    # stage 3
    r.recvuntil(b'Your ID is ')
    ID = r.recvuntil(b'!').decode().strip('!')
    # print(ID)
    magic = HashTools.new("sha256")
    
    for l in range(40,51):
        r.sendlineafter(b'Your choice: ', b'1')
        new_data, new_sig = magic.extension(
            secret_length=l+len(b"&identity="+b"key="), original_data=b'staff',
            append_data=b'admin', signature=str(ID)
        )
        r.sendlineafter(b'Show me your ID: ', bytes(new_sig))
        r.sendlineafter(b'Identity: ', new_data)
    
        out = r.recvline()
        if 'You got admin!' in out.decode():
            flag = r.recvline()
            print(flag)
            break