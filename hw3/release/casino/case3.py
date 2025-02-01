#!/usr/bin/python3

import random
import secret

class Player:
    def __init__(self, i):
        self.index = i
    
    def guess(self):
        self.number = random.getrandbits(32)
        print(f"player {self.index}'s number: {self.number}")
        return self.number

    def win(self):
        print(f"player {self.index} wins!!")

class UserPlayer(Player):
    def __init__(self, i):
        super().__init__(i)
    
    def guess(self):
        self.number = random.getrandbits(32)
        print(f"You've been kicked out of the game.")
        return 0

    def win(self):
        print(f"Play again ._.")

def play(seed):
    
    random.seed(int.from_bytes(seed, byteorder='little'))
    user_index = random.getrandbits(32) % 800
    members = []

    for i in range(800):
        if user_index == i:
            members.append(UserPlayer(i+1))
        else:
            members.append(Player(i+1))
    
    ballot = 0
    for i in range(800):
        ballot += members[i].guess()
    
    ballot %= 800
    return members[ballot].win()

if __name__ == "__main__":
    # current = 100
    # goal = 28000
    # chance = 200
    # print(f"Welcome to my casino. Now you have {current}G.")
    # print(f"However, due to your notorious cheating behaviors, you are kicked out of the game!")
    # print(f"You are still allowed to watch other players play the game, though.")
    # print("maybe you can find something interesting from the players' pattern...")
    # print("Good luck!")
    assert len(secret.flag) == 50
    play(secret.flag)
