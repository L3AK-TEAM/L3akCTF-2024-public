from flask import Flask, request
from flask_restful import Resource, Api
import jwt, os, base64, pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from functools import wraps
app = Flask(__name__)
api = Api(app)

JWT_SECRET = os.urandom(32)  
users = {}

class db_cipher:
    def __init__(self, key):
        self.key = key
        self.bs = AES.block_size
        self.pad = lambda data: pad(data, self.bs)
        self.unpad = lambda data: unpad(data, self.bs)
    
    def encrypt(self, raw):
        iv = get_random_bytes(self.bs)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        data = self.pad(raw)
        return base64.urlsafe_b64encode(iv + cipher.encrypt(data)).decode()
    
    def decrypt(self, enc):
        data = base64.urlsafe_b64decode(enc.encode())
        iv = data[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.unpad(cipher.decrypt(data[self.bs:]))
    

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Token is missing'}, 400

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
            if username not in users:
                return {'message': 'Invalid token'}, 400
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        return func(*args, **kwargs)
    return wrapper


class Register(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    def post(self):
        data = request.json
        if not data:
            return {'message': 'JSON data is missing'}, 400
        username = data.get('username')
        password = data.get('password')
        if username in users:
            return {'message': 'Username already exists'}, 400
        if not username or not password:
            return {'message': 'Username and password are required'}, 400
        try:
            token = jwt.encode({'username': username}, JWT_SECRET, algorithm='HS256')
        except:
            return {'message': 'Error generating token'}, 500
        hashed_password = SHA256.new(password.encode()).digest()
        users[username] = {
            'password': hashed_password,
            'token': token, 
            'keys': {'public': [], 'private': []}
            }
        return {'token': token}, 200

class Login(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    def post(self):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Token is missing'}, 400
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        data = request.json
        if not data:
            return {'message': 'JSON data is missing'}, 400

        password = data.get('password')
        hashed_password = SHA256.new(password.encode()).digest()
        if not username or not password:
            return {'message': 'Username and password are required'}, 400
        
        if username not in users or hashed_password != users[username]['password']:
            return {'message': 'Invalid username or password'}, 400
        
        if token != users[username]['token']:
            return {'message': 'Invalid token'}, 400
        return {'message': 'Login successful!', 'token': token}, 200

class UploadKey(Resource):
    def get(self):
        return {'message': 'Please use POST request'}, 400
    
    @login_required
    def post(self):
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Authentication token required.'}, 400
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        
        data = request.json
        if not data:
            return {'message': 'JSON data is missing'}, 400
        
        pubkey_data = data.get('public_key')
        privkey_data = data.get('private_key')

        password = data.get('password')
        password_hash = SHA256.new(password.encode()).digest()
        if password_hash != users[username]['password']:
            return {'message': 'Invalid password'}, 400

        if not all([pubkey_data, privkey_data, password]):
            return {'message': 'Key data and/or password is missing.'}, 400
        
        try:
            pubkey_bytes = base64.urlsafe_b64decode(pubkey_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the keys are base64 encoded."}
        
        cipher = db_cipher(password_hash)
        try:
            privkey_bytes = base64.urlsafe_b64decode(privkey_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the keys are base64 encoded."}
        try:
            encrypted_privkey = cipher.encrypt(privkey_bytes)
        except Exception as e:
            return {'message': f'Error: {e} while encrypting key. Make sure the key is base64 encoded.'}, 400
        users[username]['keys']['public'].append(pubkey_bytes)
        users[username]['keys']['private'].append(encrypted_privkey)
        return {'message': f'[#{username}#]$ - Key uploaded successfully", "public": "(b64){base64.urlsafe_b64encode(pubkey_bytes).decode()}', 'fingerprint': SHA256.new(pubkey_bytes).hexdigest()}, 200

class Encrypt(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    def post(self):
        token = request.headers.get('Authorization')
        data = request.json

        if not token:
            return {'message': 'Token is missing'}, 400
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        password = data.get('password')
        if not password:
            return {'message': 'Password is missing'}, 400
        password_hash = SHA256.new(password.encode()).digest()
        if password_hash != users[username]['password']:
            return {'message': 'Invalid password'}, 400
        
        public_key64 = data.get('public_key')
        if not public_key64:
            return {'message': '(Base64)Public key used for encryption is missing.'}, 400
        
        try:
            key_data = base64.urlsafe_b64decode(public_key64)
            rsakey = RSA.import_key(key_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the key is base64 encoded."}
        
        
        encoded_plaintext = data.get('data')
        if not data:
            return {'message': 'data is missing'}, 400
        
        try:
            decoded_plaintext = base64.urlsafe_b64decode(encoded_plaintext)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the data is base64 encoded."}
        
        try:
            cipher = PKCS1_OAEP.new(rsakey)
            encrypted_data = cipher.encrypt(decoded_plaintext)
        except Exception as e:
            return {'message': f'Encryption failed: {e}'}, 500
        return {'encrypted_data': base64.urlsafe_b64encode(encrypted_data).decode()}, 200

class Decrypt(Resource):

    def get(self):
        return {'message': 'Please use POST request'}, 400

    @login_required
    def post(self):
        data = request.json
        token = request.headers.get('Authorization')
        if not token:
            return {'message': 'Authorization Token Header is missing'}, 400
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['username']
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 400
        
        encrypted_data = data.get('encrypted_data')
        print(encrypted_data)
        if not encrypted_data:
            return {'message': 'Encrypted data is missing'}, 400
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_data)
        except Exception as e:
            return {"message":f"Error: {e}. Make sure the data is base64 encoded."}, 400
        
        password = data.get('password')
        print(password)
        if not password:
            return {'message': 'Password is missing'}, 400
        password_hash = SHA256.new(password.encode()).digest()
        print(password_hash)
        if password_hash != users[username]['password']:
            return {'message': 'Invalid password'}, 400
        try:
            cipher = db_cipher(password_hash)
            encrypted_private_key = users[username]['keys']['private'][0]
            decrypted_key_data = cipher.decrypt(encrypted_private_key)
        except Exception as e:
            return {'message': f'Error: {e} while decrypting key. Make sure you have uploaded a key pair.'}, 400
        
        try:
            private_key = RSA.import_key(decrypted_key_data)
        except Exception as e:
            return {"message":f"Error: {e} while importing key. Make sure you have uploaded a key pair."}
        try:
            rsacipher = PKCS1_OAEP.new(private_key)
            decrypted_data = rsacipher.decrypt(decoded_data)
            try:
                jsonsafe_plaintext = pickle.loads(decrypted_data)
                resp = jsonsafe_plaintext
            except Exception as e:

                return {'decrypted_data': f'{decrypted_data}'}, 200
        except Exception as e:
            return {'decrypted_data': f'{e}'}, 400
        return {'decrypted_data': jsonsafe_plaintext}, 200
    

api.add_resource(Register, '/apiv1/register')
api.add_resource(Login, '/apiv1/login')
api.add_resource(UploadKey, '/apiv1/uploadkey')
api.add_resource(Encrypt, '/apiv1/encrypt')
api.add_resource(Decrypt, '/apiv1/decrypt')

if __name__ == '__main__':
    app.run(debug=True)
