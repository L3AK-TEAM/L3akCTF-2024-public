import socketserver, socket
import os
from sage.all import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
# P-521 parameters (https://neuromancer.sk/std/nist/P-521)
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
K = GF(p)
a = K(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc)
b = K(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00)
E = EllipticCurve(K, (a, b))
G = E(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
E.set_order(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409 * 0x1)
n = G.order()

FLAG = open('flag.txt', 'r').read().strip()
KEY = randint(1, n - 1)
AES_KEY = hashlib.sha256(long_to_bytes(KEY)).digest()
Q = KEY * G


def get_k() -> int:
    return int.from_bytes(hashlib.sha512(os.urandom(512//8)).digest(), byteorder='big') % n

def digest(msg) -> int:
    if isinstance(msg, str):
        msg = msg.encode()
    return int.from_bytes(hashlib.sha256(msg).digest(), byteorder='big')


def ecdsa_verify(Q, m, r, s) -> bool:
    e = digest(m)
    w = pow(s, -1, n)
    u1 = int((e * w) % n)  
    u2 = int((r * w) % n)  
    P = (u1 * G) + (u2 * Q)
    return r == int(P.xy()[0])


def ecdsa_sign(d, m) -> tuple:
    e = digest(m)
    k = get_k()
    if k == 0:
        raise ValueError("Random k generated as zero, which is invalid.")
    P = k * G
    r_i = int(P.xy()[0])
    s_i = (pow(k, -1, n) * (e + r_i * d)) % n
    return (r_i, s_i)



#██████╗███████╗██████╗░██
def banner() -> bytes:
    banner = """
██████████╗░░█████╗░░█████╗░███████╗█
[=] ------------ Menu------------ [=]
[+] !1: Get Public Key            [+]
[+] !2: Sign a message            [+]
[+] !3: Verify a signature        [+]
[+] !4: Get the encrypted flag    [+]
[+] !5: Exit                      [+]
[=] ------------------------------[=]
██████████╗░░█████╗░░█████╗░███████╗█
\r\n"""
    return bytes(banner, 'utf-8')


class SimpleTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.invalid_attempts = 0
        self.request.settimeout(60)  # Set a timeout for client inactivity
        
        try:
            self.request.sendall(banner() + b"\n>> ")
            while True:
                option = self.request.recv(1024).strip()
                if not option:
                    break
                if not self.process_option(option):
                    break
                self.request.sendall(b"\n>> ")
        except Exception as e:
            pass  
        finally:
            self.request.close()

    def process_option(self, option):
        if option == b'!1':
            self.invalid_attempts = 0
            public_key_info = f"Public Key (X, Y): {Q.xy()}\n".encode()
            self.request.sendall(public_key_info)
        elif option == b'!2':
            self.invalid_attempts = 0
            self.handle_signing()
        elif option == b'!3':
            self.invalid_attempts = 0
            self.handle_verification()
        elif option == b'!4':
            self.invalid_attempts = 0
            encrypted_flag = self.send_flag()
            self.request.sendall(f"Encrypted Flag: {encrypted_flag}\n".encode())
        elif option == b'!5':
            self.request.sendall(b"Goodbye!\n")
            self.request.close()
        else:
            self.invalid_attempts += 1
            self.request.sendall(b"Invalid option. Try again.\n")
            if self.invalid_attempts >= 3:
                self.request.sendall(b"Too many invalid attempts. Exiting.\n")
                return False
        return True

    def handle_error(self, error_message):
        try:
            self.request.sendall(f"An error occurred: {error_message}, please try again later.\n".encode())
        except BrokenPipeError:
            print("client disconnected.")

    def handle_signing(self):
        while True:
            self.request.sendall(b"\nEnter message to sign (`!exit`) to return to main menu.\n\n>> ")
            msg = self.request.recv(1024).strip().decode()
            if msg == '!exit':
                self.request.sendall(banner() + b"\n")
                break
            try:
                r, s = ecdsa_sign(KEY, msg)
                response = f"Signature (r, s): ({r}, {s})\n "
                self.request.sendall(response.encode())
            except Exception as e:
                self.handle_error(str(e))

    def handle_verification(self):
        while True:
            self.request.sendall(b"Enter the message you want to verify in the format `message,r,s` (!exit to return to the main menu)\n\n>> ")
            data = self.request.recv(1024).strip().decode()
            if data == '!exit':
                self.request.sendall(banner() + b"\n\n>> ")
                break
            try:
                message, r, s = data.split(',')
                i_r, i_s = int(r), int(s)
                valid = ecdsa_verify(Q, message, i_r, i_s)
                result = b"Signature is valid" if valid else b"Signature is invalid"
                self.request.sendall(result + b"\n\n>> ")
            except ValueError:
                self.handle_error("Invalid input format for verification.")

    def send_flag(self):
        flag = FLAG.encode()
        iv = get_random_bytes(16)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(flag, AES.block_size))
        return (iv + ct).hex()



class ThreadedTCPServer(socketserver.TCPServer):
    allow_reuse_address = True  # This should fix the 'Address already in use' issue




def run_server(host, port):
    server = socketserver.TCPServer((host, port), SimpleTCPRequestHandler)
    server.allow_reuse_address = True
    server.serve_forever()





def main():
    HOST, PORT = "0.0.0.0", 13338
    run_server(HOST, PORT)

if __name__ == "__main__":
    main()