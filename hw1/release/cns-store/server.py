#!/usr/bin/env python3

import os
import sys
import base64
import random
import hashlib
import select
import signal
import time
import io
from Crypto.Util.number import bytes_to_long

import secret



def input_untruncated(prompt: str) -> bytes:
    """Just for handling network I/O"""

    print(prompt, end="")
    buf = io.BytesIO()
    b = sys.stdin.buffer.read1(4096)
    assert buf.write(b) == len(b)

    def stdin_ready():
        rlist, _, _ = select.select([sys.stdin.fileno()], [], [], 1)
        return rlist

    while stdin_ready():
        b = sys.stdin.buffer.read1(4096)
        assert buf.write(b) == len(b)

    return buf.getvalue()

def alarm(time):
    def handler(signum, frame):
        print("timeout!")
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(time)

def sha1(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha1()
    h.update(s)
    return h.digest()

def sha256(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha256()
    h.update(s)
    return h.digest()

def LoginMenu():
    print("Welcome to CNS Store!")
    print("Show me your passion of CNS to login and start buying some Flags")

def Login():
    LoginMenu()
    
    randomstring = hex(random.randint(0, 16777216))[2:]
    Input = input_untruncated(f"Give me the input that contains CNS2024 and the sha256 ends with {randomstring:0<6}:\n").strip(b"\n")
    UserX = Input.decode("utf-8")
    if len(UserX) > 400:
        print("Input size too big!")
        exit()
    UserHash = sha256(UserX)

    if "CNS2024" not in UserX:
    	print("Why don't you love CNS :(")
    	exit()
    if sha256(UserX)[-3:].hex() != "{:0>6}".format(randomstring):
        print("Not enough passion :(")
        exit()
    print("Successfully login")
    
    return

def stage1_menu():
	print('============================================================================================')
	print('Hello! Lucky you. You are the 2024th customer of our store!')
	print('You receive $100 as your gift')
	print('Everything is $5 in our store')
	print('We sell a flag and all kinds of products that contains "CNS2024" in the name!')
	print('However, don\'t buy too much of them. We only have 10 of each.')
	print('Things are going rough nowadays...')
	print('What do you need?')
	print('1.Buy something')
	print('2.Buy a lottery to win the flag with the total price on the shelf')
	print('3.Buy Flag')
	print('3.Exit')
	print('=============================================================================================')
	print()

def stage2_menu():
	print('============================================================================================')
	print('How did you get here Hacker?')
	print('It wouldn\'t be that easy this time.')
	print('You receive $100 as your gift')
	print('Everything is $5 in our store')
	print('We sell a flag and all kinds of products that contains both "CNS2024" and the KEY in the name!')
	print('However, don\'t buy too much of them. We only have 10 of each.')
	print('Things are going rough nowadays...')
	print('What do you need?')
	print('1.Buy something')
	print('2.Buy a lottery to win the flag with the total price on the shelf')
	print('3.Buy Flag')
	print('4.Exit')
	print('=============================================================================================')
	print()

def stage12(stageNum):
	key = random.randint(0,10000000)
	shelf = {}
	sold = []
	tries = 0
	cash = 100
	while True:
		if(stageNum) == 1:
			stage1_menu()
		elif(stageNum) == 2:
			stage2_menu()
			print(f'Your key is {key}.')
		try:
			cmd = int(input("Your choice: "))
		except ValueError:
			print("\nInvalid input\n")
			continue

		match cmd:
			case 1:
				#buy something
				productName = input_untruncated("Product name: ").strip(b"\n")
				if b"CNS2024" not in productName:
					print('We don\'t sell this kind of stuff.')
					exit()
				if stageNum == 2:
					if str(key).encode('utf-8') not in productName:
						print('We don\'t sell this kind of stuff.')
						exit()
				try:
					amount = int(input("Amount: "))
				except ValueError:
					print("\nInvalid input\n")
					continue
				if productName in sold:
					print("\nPurchase the amount you need the first time.\n")
					continue
				if amount > 10 or amount < 1:
					print("\nAre you messing with me?\n")
					continue

				if stageNum == 1:
					h = sha1(productName)
				elif stageNum == 2:
					h = sha256(productName)[-4:]	
				if h not in shelf: #create 10 product and put it on shelf if it isn't on shelf
					shelf[h] = 10
                
				shelf[h] -= amount
				cash -= amount*5
				print(f"You got ${cash} left\n")
				sold += [productName]
				if(cash < 0):
					print("You are broke HAHAHA")
					exit()
			case 2:
				#lottery
				if shelf == {}:
					print("The shelf is empty")
				cash -= sum(shelf.values()) * 5
				print(f"You got ${cash} left\n")
				#buy everything on the shelf
				if(cash < 0):
					print("You are broke HAHAHA")
					exit()
			case 3:
				#buy flag
				if cash >= 150:
					if stageNum == 1:
						print("Wait what?????")
						print(f"{secret.flag1}\n")
						return
					elif stageNum == 2:
						print("Wait what?????")
						print(f"{secret.flag2}\n")
						return
				elif cash <= 0:
					print("The Flag is ... oh you are broke HAHAHA\n")
				else:
					print("You need $150 to buy the flag\n")
				
			case 4:
				#exit
				exit()
			case _:
				print("\nInvalid input\n")
				exit()
		tries += 1
		if tries >=6:
			print("Time is gold. Stop wasting your time shopping!")
			exit()



def init():


    key = os.urandom(random.randint(40, 50))
    assert len(key) >= 40 and len(key) <= 50

    return key

def staff():
	staffInput = input_untruncated("Give me input: ").strip(b"\n")
	if len(staffInput) > 70:
		print('\nInput too long\n')
		exit()
	else:
		c = bytes_to_long(staffInput) ^ bytes_to_long(os.urandom(len(staffInput)))
		print(c)
def admin():
	print(f'Admins can get their Flag. {secret.flag3}')
	exit()

def stage3():
	key = init()
	identity = b"staff"
	ID = sha256(b"key="+key+b"&identity="+identity)
	print('============================================================================================')
	print('It seems like we have some security issues in our server.')
	print('hmm....  You should be our staff and help us out!')
	print(f'Your ID is {ID.hex()}! You are working for us from now on!')
	print('=============================================================================================')
	print()
	print()

	while True:
		print('1.Login')
		print('2.Quit this weird gig')
		print()
		try:
			cmd = int(input("Your choice: "))
		except ValueError:
			print("\nInvalid input\n")
			exit()

		match cmd:
			case 1:
				userID = input('Show me your ID: ').strip('\n')
				userIdentity = input_untruncated('what\'s your Identity: ').strip(b"\n")
				IDstr = b'key=' + key + b'&identity=' + userIdentity
				if str(sha256(IDstr).hex()) != userID:
					print(f'\nWho are you??????????\n')
				elif userIdentity[-5:] == b"staff":
					print('Hello, are you the new staff?')
					staff()
				elif userIdentity[-5:] == b"admin":
					print('You got admin!')
					admin()
				else:
					print(userIdentity[-5:])
					print('\nweird\n')
			case 2:
				print("\nDon't runnnnnnnnnnnnnnnnnnnn!\n")
				exit()
			case _:
				print("\nInvalid input\n")
				exit()



def main():
	sys.stdout = io.TextIOWrapper( open(sys.stdout.fileno(), "wb", buffering=0), write_through=True)
	alarm(200)
	Login()
	stage12(1)
	stage12(2)
	stage3()







if __name__ == "__main__":
    main()
