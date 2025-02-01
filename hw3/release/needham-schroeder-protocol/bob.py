#!/usr/bin/env python3

import base64
import random
from user import User
from utils import cns_decrypt, cns_encrypt, alarm
from secret import FLAG1, FLAG3, bob_secret_key


class Bob(User):
    def __init__(self, username, user_id=None, key_server=None):
        self.username = username
        self.user_id = user_id
        self.key_server = key_server

    def listenA(self, ):
        try:
            encrypted_forward_message = input('Please give me the forward message: ').strip()
            forward_message = cns_decrypt(self.key_server, encrypted_forward_message.encode()).decode()
            v = forward_message.split('||')
            keyAB = base64.b64decode(v[0])
            userA = v[1]

            return keyAB, userA
        except:
            print('Something is wrong... Bye!')
            exit()
    
    def respondA(self, keyAB, userA):
        try:
            nonce_B = random.randint(1, 1000000000)
            response = f'{nonce_B}'
            encrypted_response = cns_encrypt(keyAB, response.encode())
            print(f'Response: {encrypted_response}')
            return nonce_B
        except:
            print('Something is wrong... Bye!')
            exit()
    
    def receive_msg_A(self, keyAB, userA, nonce_B):
        # Should receive N_B - 1 from A
        try:
            encrypted_message = input('Please give me the message: ').strip()
            message = cns_decrypt(keyAB, encrypted_message.encode()).decode()
            try:
                nonce_res = int(message)
            except:
                print('Invalid message!')
                return False
            
            if nonce_res == nonce_B - 1:
                return True
            else:
                return False
        except:
            return False
        
    def send_msg_B(self, userA, keyAB):
        if userA == 'cnsStudent':
            # flag1
            message = f'Oh you are CNS student! Here is your flag: {FLAG1}'
            encrypted_message = cns_encrypt(keyAB, message.encode())
            print(f'Message: {encrypted_message}')
        elif userA == 'alice':
            # flag3
            message = f'Oh you are Alice! Here is your flag: {FLAG3}'
            encrypted_message = cns_encrypt(keyAB, message.encode())
            print(f'Message: {encrypted_message}')
        else:
            print('I do not know you!')
            return
        

if __name__ == '__main__':
    alarm(300)

    user = Bob('bob', '1b877f7f20fb853df3e7352fbb8f8f423f27ea9d413e7a13808655859724a82c', base64.b64decode(bob_secret_key))

    while True:
        print('Hello, I am Bob!')
        keyAB, userA = user.listenA()
        nonce_B = user.respondA(keyAB, userA)
        if user.receive_msg_A(keyAB, userA, nonce_B):
            user.send_msg_B(userA, keyAB)
        else:
            print('Something is wrong... I gonna disconnect!')
            break

    print('Bye~~')