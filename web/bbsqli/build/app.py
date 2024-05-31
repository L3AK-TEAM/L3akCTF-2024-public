from flask import Flask, render_template, request, redirect, url_for, session, Response
import sqlite3
import hashlib
import os
from utils import generate,hash_password

app = Flask(__name__)
app.secret_key = generate(60)


FLAG = os.getenv('FLAG', 'TEST{flag}')

def init_db():
    conn = sqlite3.connect('l3ak.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY,
            flag TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_flag(flag):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO flags (flag) VALUES (?)', (flag,))
    conn.commit()
    conn.close()


def add_user(username,email, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute('INSERT INTO users (username,email, password) VALUES (?,?, ?)', (username,email, hashed_password))
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect('l3ak.db')
    conn.row_factory = sqlite3.Row
    return conn



add_user("admin","l3aker@l3ak.com",hash_password(generate(30)))
add_flag(FLAG)


@app.route('/')
def index():
    return redirect(url_for('login'))

def check_blocked():
    # IP blacklisting...
    with open('blocked_ips.txt', 'r') as f:
        blocked_ips = [x.strip() for x in f.read().split()]
    if request.remote_addr in blocked_ips:
        return Response("Stop, what ever you're doing and please open a ticket in the Discord server! https://discord.com/channels/1233420048069296250/1234530911601688657/1234547560618918029", status=418, mimetype='application/text')
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ip blocklist
    blocked_resp = check_blocked()
    if blocked_resp is not None:
        return blocked_resp
    # challenge:
    if request.method == 'POST':
       try: 
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f'SELECT username,email,password FROM users WHERE username ="{username}"')
        user = cursor.fetchone()
        conn.close()
        if user and user['username'] == username and user['password'] == hash_password(password):
            session['username'] = user['username']
            session['email'] = user['email']
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
       except:
           return render_template('login.html', error='Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # ip blocklist
    blocked_resp = check_blocked()
    if blocked_resp is not None:
        return blocked_resp
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return render_template('register.html', error='Username already exists')
        add_user(username, email, password)
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        email = session['email']
        return render_template('dashboard.html', user=username,email=email)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()
