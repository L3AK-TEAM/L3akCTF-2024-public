import secrets
from circuit import *
from flag import FLAG
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long

def printMenu():
    menu = '''Select an Option:
    1) Insert a stuck-at fault
    2) Remove a stuck-at fault
    3) Evaluate circuit
    4) Print Circuit (Diagram)
    5) Print Circuit (List)
    6) Go To Next Circuit
    '''
    print(menu)

greeting_msg = '\n"Of this one thing make sure against your dying day - that your faults die before you do." - Lucius Annaeus Seneca, Letters from a Stoic\n'
print(greeting_msg)

secret = long_to_bytes(secrets.randbits(len(FLAG)*8))
key = sha256(secret).digest()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(FLAG, AES.block_size))
print(f'Encrypted Flag: {ciphertext.hex()}\n')

secret_chunks = [bytes_to_long(s) for s in [secret[i:i+4] for i in range(0, len(secret), 4)]]
num_secrets = len(secret_chunks)

for i in range(num_secrets):

    s = secret_chunks[i]
    test = [int(i) for i in bin(s)[2:].zfill(32)]
    circuit = Circuit(s)
    max_faults = 6
    max_evaluations = 160
    num_faults = 0
    num_evaluations = 0

    print(f'Circuit {i+1}/{num_secrets}\n')

    while True:

        printMenu()
        option = int(input('Your Choice: '))

        if option == 1:
            if num_faults >= max_faults:
                print('You have reached your fault limit!')
                continue
            net_id = int(input('What net would you like to insert a stuck-at fault on? '))
            fault_val = int(input(f'What fault value should net {net_id} be set to (0 or 1)? '))
            if fault_val != 0 and fault_val != 1:
                print('Nice try, but no.\n')
                continue
            success = circuit.insertFault(net_id, fault_val)
            if success:
                print(f'Inserted stuck-at fault {fault_val} on net {net_id}!\n')
                num_faults += 1
            else:
                print('Something went wrong when trying to insert the desired fault!!\n')
                continue

        elif option == 2:
            if num_faults <= 0:
                print('There are no faults to remove!\n')
                continue
            net_id = int(input('What net would you like to remove a stuck-at fault from? '))
            success = circuit.removeFault(net_id)
            if success:
                print(f'Removed stuck-at fault from net {net_id}!\n')
                num_faults -= 1
            else:
                print('Something went wrong when trying to remove the desired fault!!\n')
                continue

        elif option == 3:
            output = circuit.evaluate()
            print(f'Output: {output}\n')
            num_evaluations += 1
            if num_evaluations >= max_evaluations:
                print('You\'re out of circuit evaluations! Bye!')
                break

        elif option == 4:
            circuit.printDiagram()

        elif option == 5:
            circuit.printList()

        elif option == 6:
            break

        else:
            print('Invalid Option!')
