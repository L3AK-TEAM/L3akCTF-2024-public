import random
import string
import hashlib

def generate(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    
    random_string = ''.join(random.choices(characters, k=length))
    
    return random_string

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()