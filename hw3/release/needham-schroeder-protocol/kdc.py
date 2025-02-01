#!/usr/bin/env python3

from utils import alarm, cns_encrypt
from secret import bob_secret_key, alice_secret_key, FLAG2, logs
import hashlib
import uuid
import secrets
import base64

# default user
database = [
    {
        'username': 'admin',
        'password': 'efb8a0cd6c2407b099cadde0d4e72bbd7884bf8aef764d44103c624ffaf84d11',
        'id': '6355c19cd0b04fd394796186a77a3944',
        'symmetric_key': base64.b64encode(secrets.token_bytes(32))
    },
    {
        'username': 'bob',
        'password': '1b877f7f20fb853df3e7352fbb8f8f423f27ea9d413e7a13808655859724a82c',
        'id': 'c200fc127adf4843ac58974fefa061d9',
        'symmetric_key': bob_secret_key
    },
    {
        'username': 'alice',
        'password': 'df1fbdff7f294a7a765a0ee03aabef79f5c6c711136de660db5909c87c3b1b49',
        'id': '0393e1a4235c49e494845b0c171493df',
        'symmetric_key': alice_secret_key
    }
]

current_user = None

def print_menu():
    print()
    print('Please select your action: ')
    print('1. Register an account')
    print('2. Login an account')
    print('3. Request Session Key')
    print('4. View Logs')
    print('5. Logout')
    print('6. Exit')


def register():
    username = input('Enter your username: ').strip()
    if not username.isalpha() or len(username) > 32 or len(username) < 4:
        print('Invalid username!')
        return
    if any(user['username'] == username for user in database):
        print('Username already exists!')
        return
    
    password = input('Enter your password: ').strip()
    if len(password) < 8:
        print('Password is too short!')
        return
    password = hashlib.sha256(password.encode()).hexdigest()
    symmetric_key = base64.b64encode(secrets.token_bytes(32))
    user_id = uuid.uuid4().hex
    database.append({
        'username': username,
        'password': password,
        'id': user_id,
        'symmetric_key': symmetric_key
    })
    print('Account created successfully!')
    print(f'username: {username}')
    print(f'password: {password}')
    print(f'id: {user_id}')
    # Note that in the real world, we should sent symmetric_key though secure channel,
    # However, in this case, we just print it out for simplicity
    # As MitM attack is not in the scope of this challenge
    print(f'symmetric_key: {symmetric_key.decode()}')
    return

def login():
    global current_user

    if current_user is not None:
        print('You are already logged in!')
        return

    username = input('Enter your username: ').strip()
    password = input('Enter your password: ').strip()
    password = hashlib.sha256(password.encode()).hexdigest()
    user = next((user for user in database if user['username'] == username and user['password'] == password), None)
    if user is None:
        print('Invalid username or password!')
        return
    
    current_user = user
    if current_user['id'] == '6355c19cd0b04fd394796186a77a3944' and current_user['username'] == 'admin':
        print(f'Welcome admin! Here is the flag: {FLAG2}')
    print('Login successfully!')

def logout():
    global current_user
    current_user = None
    print('Logout successfully!')

def request():
    if current_user is None:
        print('Please login first!')
        return
    
    print('Who do you want to communicate ?')
    target = input('Enter the username: ').strip()
    target_user = next((user for user in database if user['username'] == target), None)
    if target_user is None:
        print('User not found!')
        return
    
    nonce = input('Give me a nonce: ').strip()
    key_AS = base64.b64decode(current_user['symmetric_key'])
    key_BS = base64.b64decode(target_user['symmetric_key'])

    key_AB_encoded = base64.b64encode(secrets.token_bytes(32))
    B = target_user['username']
    forward_message = f'{key_AB_encoded.decode()}||{current_user["username"]}'
    encrypted_forward_message = cns_encrypt(key_BS, forward_message.encode())
    
    response = f'{nonce}||{key_AB_encoded.decode()}||{B}||{encrypted_forward_message}'
    encrypted_response = cns_encrypt(key_AS, response.encode())
    print(f'Response: {encrypted_response}')
    return
    

def view_logs():
    if current_user is None or current_user['username'] != 'admin' or current_user['id'] != '6355c19cd0b04fd394796186a77a3944':
        print('Permission denied!')
        return
    print(logs)
    return


if __name__ == '__main__':
    alarm(300)

    print('Welcome to KDC system!')
    
    while True:
        print_menu()
        choice = int(input('> ').strip())
        if choice == 1:
            register()
        elif choice == 2:
            login()
        elif choice == 3:
            request()
        elif choice == 4:
            view_logs()
        elif choice == 5:
            logout()
        elif choice == 6:
            break
        else:
            print('Invalid choice!')
            continue

    print('See you again! Byebye')
    exit(1)