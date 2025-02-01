from Crypto.Cipher import AES
import binascii
import secret
from random import randbytes

class AES_Wrapper:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def pad(self, m):
        length = 16-len(m) % 16
        return m + chr(length + 8).encode()*length

    def unpad(self, c):
        length = c[-1] - 8
        if length <= 0 or length > 16:
            raise ValueError
        for char in c[-length:]:
            if char != length + 8:
                raise ValueError
        return c[:-length]

    def encrypt(self, m) -> str:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return binascii.hexlify(cipher.encrypt(self.pad(m))).decode()
    
    def decrypt(self, c) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.unpad(cipher.decrypt(binascii.unhexlify(c)))
    
def main():
    cipher = AES_Wrapper(randbytes(16), randbytes(16))
    
    print("Welcome to the POA!")
    print("You have one encrypted message!")
    while True:
        print("Please select an option:")
        print("1) Read message(s)")
        print("2) Generate an encrypted message")
        print("3) Sent an encrypted message")
        print("4) Exit")
        
        choice = input("Your choice: ").strip()
        
        if choice == "1":
            print("You have one message(s): ")
            print(cipher.encrypt(secret.flag1))
        elif choice == "2":
            name = input("Your name: ").strip()
            if (name == "TA"):
                print("Please click the url send to your email to activate your account")
            else:
                message = input("Your message: ").strip()
                nounce = b'so_random_nounce'
                formatted_message = b'Request nounce: ' + nounce + b'; Sender: ' + name.encode() + b'; Message: ' + message.encode()
                print("Your encrypted message: " + cipher.encrypt(formatted_message))
        elif choice == "3":
            message = input("Your encrypted message: ").strip()
            try:
                message = cipher.decrypt(message)
                if message[:16] == b'Request nounce: ':
                    message.decode()
                    message = message[34:]
                    if message == b'Sender: TA; Message: Please send over the 2nd flag':
                        print(secret.flag2.decode())
                print("Message sent!")
            except:
                print("Invalid message")
        else:
            print("Goodbye!")
            break
    
if __name__ == "__main__":
    main()