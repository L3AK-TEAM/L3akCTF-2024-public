import discord
from discord.ext import commands
import jwt
import os

intents = discord.Intents.all()
bot = commands.Bot(command_prefix="!", intents=intents)

BOT_TOKEN = os.getenv('TOKEN')
SECRET_KEY_FILE_PATH = 'secret.txt'
FLAG_FILE_PATH = 'flag.txt'

with open(FLAG_FILE_PATH, 'r') as file:
    flag = file.read().strip()

bot.remove_command('help')

def verify_jwt(token):
    try:
        header = jwt.get_unverified_header(token)
        kid = header['kid']
        assert ("/" not in kid)
        with open(kid, 'r') as file:
            secret_key = file.read().strip()
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])
        return decoded_token
    except Exception as e:
        return str(e)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')

@bot.command(name='help')
async def custom_help(ctx):
    help_message = """
    *Help Command*:```
 !help (Shows this message)
 !verify token  (Authenticate with a JWT token)
 !generate (Generate a JWT Token for you)```
    """
    await ctx.send(help_message)

@bot.command(name='verify')
async def authenticate(ctx, *, token=None):
    try:
        if isinstance(ctx.channel, discord.DMChannel) == False:
            await ctx.send("I can't see here 👀 , DM me")
        else:
            result = verify_jwt(token)
            print(ctx.author)
            print(result)
            if isinstance(result, dict):
                username = result.get('username')
                role = result.get('role')
                if username and role=='VIP':
                    await ctx.send(f'Welcome Sir! Here is our secret {flag}')
                elif username:
                    await ctx.send(f'Welcome {username}!')
                else:
                    await ctx.send('Authentication failed. Please try again.')
            else:
                await ctx.send('Authentication failed.')
    except:
        await ctx.send('Authentication failed.')

@bot.command(name='generate')
async def generate_token(ctx, *, username=None):
    try:
        if isinstance(ctx.channel, discord.DMChannel) == False:
            await ctx.send("I can't see here 👀 , DM me")
        elif not username:
            await ctx.send("Please provide a username.")
        else:
            with open(SECRET_KEY_FILE_PATH, 'r') as file:
                secret_key = file.read().strip()
            headers = {
                'kid': SECRET_KEY_FILE_PATH
            }
            token = jwt.encode({'username': username,'role' : 'user'}, secret_key, algorithm='HS256',headers=headers)
            await ctx.send(f'The generated JWT token for {username} is: {token}')
    except:
        await ctx.send('Failed to generate token.')



bot.run(BOT_TOKEN)