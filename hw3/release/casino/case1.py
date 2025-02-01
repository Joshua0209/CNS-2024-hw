#!/usr/bin/python3

import random
import secret
import os

class Player:
    def __init__(self, i):
        self.index = i
    
    def guess(self):
        self.number = random.getrandbits(32)
        print(f"player {self.index}'s number: {self.number}")
        return self.number

    def win(self):
        return False

class UserPlayer(Player):
    def __init__(self, i):
        super().__init__(i)
    
    def guess(self):
        while True:
            v = input('your number: ').strip()
            try:
                v = int(v)
                if v < 0:
                    print('invalid number :(')
                    continue
                break
            except:
                print('invalid number :(')
        self.number = v
        return self.number

    def win(self):
        return True

def menu(current, chance, price):
    print("=====================")
    print(" 1. play (1G)        ")
    print(f" 2. buy flag ({price}G)")
    print(" 3. exit             ")
    print("=====================")
    print(f"Current money: {current}G")
    print(f"{chance} chances left")

def not_enough():
    print("You don't have enough money.")

def buyflag():
    print(f"This is your flag: {secret.flag}")

def play():
    members = []
    random.seed(int.from_bytes(os.urandom(16), byteorder='little'))

    for i in range(799):
        members.append(Player(i+1))
    members.append(UserPlayer(i+1))

    ballot = 0
    for i in range(800):
        ballot += members[i].guess()
    
    ballot %= 800
    return members[ballot].win()

if __name__ == "__main__":
    current = 100
    goal = 20000
    chance = 200
    print(f"Welcome to my casino. Now you have {current}G.")
    print(f"You need {goal}G to buy the flag.")
    print(f"You have {chance} chances to pay 1G and play for 1 round. the rule is simple:")
    print(f"There will be 800 people (including you) sitting in a circle. In each round, everyone")
    print("can randomly choose a number, and the sum of the numbers will be the index of winner!")
    print("The winner cat take away all the people's bet, which is 800G in total.")
    print("Good luck!")

    while True:
        menu(current, chance, goal)
        choice = input('Your choice: ').strip()
        try:
            choice = int(choice)
        except:
            print('Invalid Choice')
            continue
        if choice == 1:
            if chance <= 0:
                print("You don't have any chances!")
                continue
            if current >= 1:
                chance -= 1
                current -= 1
                win = play()
                if win:
                    current += 800
                    print(f"Congratulations! You win in this turn, and now you have {current}G.")
                else:
                    print(f"Oops! You lose in this turn, and now you have {current}G.")
            else:
                not_enough()
            
        elif choice == 2:
            if current >= goal:
                current -= goal
                buyflag()
            else:
                not_enough()
        elif choice == 3:
            exit()
        else:
            print('Invalid Choice')