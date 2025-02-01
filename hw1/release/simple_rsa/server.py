from Crypto.Util.number import getStrongPrime, bytes_to_long
import signal
from secret import FLAG1, FLAG2, FLAG3, FLAG4
from secret import Affine_key, Bob_key, Admin_key

database = {}

def print_banner():
    print('''

░██████╗██╗░░░██╗██████╗░███████╗██████╗░  ░██████╗███████╗░█████╗░██╗░░░██╗██████╗░███████╗
██╔════╝██║░░░██║██╔══██╗██╔════╝██╔══██╗  ██╔════╝██╔════╝██╔══██╗██║░░░██║██╔══██╗██╔════╝
╚█████╗░██║░░░██║██████╔╝█████╗░░██████╔╝  ╚█████╗░█████╗░░██║░░╚═╝██║░░░██║██████╔╝█████╗░░
░╚═══██╗██║░░░██║██╔═══╝░██╔══╝░░██╔══██╗  ░╚═══██╗██╔══╝░░██║░░██╗██║░░░██║██╔══██╗██╔══╝░░
██████╔╝╚██████╔╝██║░░░░░███████╗██║░░██║  ██████╔╝███████╗╚█████╔╝╚██████╔╝██║░░██║███████╗
╚═════╝░░╚═════╝░╚═╝░░░░░╚══════╝╚═╝░░╚═╝  ╚═════╝░╚══════╝░╚════╝░░╚═════╝░╚═╝░░╚═╝╚══════╝

░██████╗███████╗░█████╗░██████╗░███████╗████████╗  ░██████╗████████╗░█████╗░██████╗░░█████╗░░██████╗░███████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝  ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔════╝░██╔════╝
╚█████╗░█████╗░░██║░░╚═╝██████╔╝█████╗░░░░░██║░░░  ╚█████╗░░░░██║░░░██║░░██║██████╔╝███████║██║░░██╗░█████╗░░
░╚═══██╗██╔══╝░░██║░░██╗██╔══██╗██╔══╝░░░░░██║░░░  ░╚═══██╗░░░██║░░░██║░░██║██╔══██╗██╔══██║██║░░╚██╗██╔══╝░░
██████╔╝███████╗╚█████╔╝██║░░██║███████╗░░░██║░░░  ██████╔╝░░░██║░░░╚█████╔╝██║░░██║██║░░██║╚██████╔╝███████╗
╚═════╝░╚══════╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░  ╚═════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░╚══════╝

░░██╗░██████╗░██████╗░██████╗░██████╗██╗░░
░██╔╝██╔════╝██╔════╝██╔════╝██╔════╝╚██╗░
██╔╝░╚█████╗░╚█████╗░╚█████╗░╚█████╗░░╚██╗
╚██╗░░╚═══██╗░╚═══██╗░╚═══██╗░╚═══██╗░██╔╝
░╚██╗██████╔╝██████╔╝██████╔╝██████╔╝██╔╝░
░░╚═╝╚═════╝░╚═════╝░╚═════╝░╚═════╝░╚═╝░░ VERSION 2.0
''')
    print('Welcome to my SUPER SECURE SECRET STORAGE (SSSS) VERSION 2.0! Here we store all your secrets in a secure way! In the latest version, we dispose of the old and insecure passphrase-protected methods. From now, your secrets will be encrypted by using the modern and secure encryption methods -- RSA! Besides, we still offer access to view our database, as we are confident in the unbreakable and highly secure of RSA, giving trivial information doesn\'t break RSA, right...?')
    print('-' * 100)
    

def print_menu():
    print('Please select your action: ')
    print('1. View Database')
    print('2. View Affine\'s Secret')
    print('3. View Bob\'s Secret')
    print('4. View Eve\'s Secret')
    print('5. View Admin\'s Secret')
    print('6. Exit')

def view_database():
    print('====================================================================================================')
    print(f"Username                           : {database['affine']['name']}")
    print(f'n                                  : {database["affine"]["n"]}')
    print(f'e                                  : {database["affine"]["e"]}')
    print(f'hint                               : Just Simple RSA Challenge :D')
    print('====================================================================================================')
    print(f"Username                           : {database['bob']['name']}")
    print(f'n                                  : {database["bob"]["n"]}')
    print(f'e1                                 : {database["bob"]["e1"]}')
    print(f'e2                                 : {database["bob"]["e2"]}')
    print(f"hint                               : Giving two strong encrypted ciphertexts doesn't effect right?")
    print('====================================================================================================')
    print(f"Username                           : {database['eve']['name']}")
    print(f'n                                  : {database["eve"]["n"]}')
    print(f'e                                  : {database["eve"]["e"]}')
    print(f"hint                               : Small e doesn't mean it's weak, right?")
    print('====================================================================================================')
    print(f"Username                           : {database['admin']['name']}")
    print(f'n                                  : {database["admin"]["n"]}')
    print(f'e                                  : {database["admin"]["e"]}')
    print(f"hint                               : Alright, Alright! You say small e is weak, then i make it BIG!")
    print('====================================================================================================')
    return

def view_affine_secret():
    print(f"Here is the Affine\'s secret c : {database['affine']['c']}")
    return

def view_bob_secret():
    print(f"Here is the Bob\'s secret c1 and c2 : ({database['bob']['c1']}, {database['bob']['c2']})")
    return

def view_eve_secret():
    print(f"Here is the Eve\'s secret c : {database['eve']['c']}")
    return

def view_admin_secret():
    print(f"Here is the admin\'s secret c : {database['admin']['c']}")

def setup_db():
    def generate_affine():
        username = 'affine'
        p, q = Affine_key
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        c = pow(bytes_to_long(FLAG1), e, n)

        return {
            'name': username,
            'n': n,
            'e': e,
            'c': c,
        }
    
    def generate_bob():
        username = 'bob'
        p, q = Bob_key
        n = p * q
        phi = (p - 1) * (q - 1)
        e1 = 65537
        e2 = 100003
        c1 = pow(bytes_to_long(FLAG2), e1, n)
        c2 = pow(bytes_to_long(FLAG2), e2, n)

        return {
            'name': username,
            'n': n,
            'e1': e1,
            'e2': e2,
            'c1': c1,
            'c2': c2,
        }

    def generate_eve():
        username = 'eve'
        p, q = getStrongPrime(2048), getStrongPrime(2048)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 7
        c = pow(bytes_to_long(FLAG3), e, n)

        return {
            'name': username,
            'n': n,
            'e': e,
            'c': c,
        }
    
    def generate_admin():
        username = 'admin'
        e, p, q = Admin_key
        n = p * q
        c = pow(bytes_to_long(FLAG4), e, n)

        return {
            'name': username,
            'n': n,
            'e': e,
            'c': c
        }
    
    database['affine'] = generate_affine()
    database['bob'] = generate_bob()
    database['eve'] = generate_eve()
    database['admin'] = generate_admin()

def alarm(second):
    def handler(signum, frame):
        print('You need to be faster ...')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

def main():
    setup_db()

    print_banner()
    alarm(300)
    while True:
        print_menu()
        recv = input('> ').strip()

        if recv == '1':
            view_database()
        elif recv == '2':
            view_affine_secret()
        elif recv == '3':
            view_bob_secret()
        elif recv == '4':
            view_eve_secret()
        elif recv == '5':
            view_admin_secret()
        elif recv == '6':
            break
        else:
            print('Invalid input! Please try again.')
    print('bye bye~~')

if __name__ == "__main__":
    main()