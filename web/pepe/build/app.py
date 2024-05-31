#!/usr/bin/env python3 
from flask import Flask, render_template, request, make_response, redirect
import sqlite3, jwt, datetime, os

app = Flask(__name__, template_folder='./static')

secret = os.environ.get('SECRET', 'secret')

flag = os.environ.get('FLAG', 'L3AK{5q1_1nj3ct10n_CLF}')

conn = sqlite3.connect("challenge.db")
cursor = conn.cursor()

cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT NOT NULL, password TEXT NOT NULL, fortune TEXT NOT NULL);")

cursor.execute("CREATE TABLE IF NOT EXISTS flag (flag TEXT);")

if not cursor.execute("SELECT * FROM flag;").fetchone():
    cursor.execute(f"INSERT INTO flag (flag) VALUES ('{flag}');")

conn.commit()
conn.close()



def create_jwt(username, password, alg):
    payload ={
        'username': username,
        'password': password,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=6000)
    }
    token = jwt.encode(payload, secret, algorithm=alg)
    return token

def verify_jwt(token, alg):
    try:
        payload = jwt.decode(token, secret, algorithms=alg)
        return payload.get('username')
    except jwt.ExpiredSignatureError:
        return 'Token expired'
    except jwt.InvalidTokenError:
        return 'Invalid token'


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.form.get('username') and request.form.get('password'):
        username = request.form.get('username')
        password = request.form.get('password')

        if not username.isalnum():
            return render_template('signup.html', error='Username can only contain alphanumeric characters')

        if len(username) < 3:
            return render_template('login.html', error='Username must be at least 3 characters long')
        if len(username) > 20:
            return render_template('login.html', error='Username must be at most 20 characters long')
        if len(password) < 8:
            return render_template('login.html', error='Password must be at least 8 characters long')
        if not username.isalnum():
            return render_template('login.html', error='Username can only contain alphanumeric characters')

        fortune = os.popen('fortune').read()
        conn = sqlite3.connect("challenge.db")
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?;"
        cursor.execute(query, (username,))
        if cursor.fetchone():
            return render_template('signup.html', error='User already exists')

        query = "INSERT INTO users (username, password, fortune) VALUES (?, ?, ?);"
        
        cursor.execute(query, (username, password, fortune))
        conn.commit()
        conn.close()
        return render_template('login.html', error='User created successfully')
    else:
        return render_template('signup.html', error='Please provide username and password')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.form.get('username') and request.form.get('password') and request.method == 'POST':    
        
        username = request.form.get('username')
        password = request.form.get('password')
        if len(username) < 3:
            return render_template('login.html', error='Username must be at least 3 characters long')
        if len(username) > 20:
            return render_template('login.html', error='Username must be at most 20 characters long')
        if len(password) < 8:
            return render_template('login.html', error='Password must be at least 8 characters long')
        if not username.isalnum():
            return render_template('login.html', error='Username can only contain alphanumeric characters')


        conn = sqlite3.connect("challenge.db")
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ? AND password = ?;"
        cursor.execute(query, (username, password))
        if not cursor.fetchone():
            return render_template('login.html', error='Invalid username or password')  
        conn.close()
        
        token = create_jwt(username, password, 'HS256')
        r = make_response(redirect('/dashboard'))
        r.set_cookie('token', token)
        return r
    
    else:
        return render_template('login.html', error='Please provide username and password')

@app.route('/dashboard')
def dashboard():
    
    token = request.cookies.get('token')
    if not token:
        return render_template('login.html', error='Please login to access this page')
    # my code
    decoded_token = jwt.decode(token, secret, algorithms=['HS256'])
    
    username = decoded_token.get('username')
    username=username.lower()
    filters=[">", "+","=", "<","//", "|","'1", " 1", " true", "'true", " or", "'or", "/or",";", " ", " " ," and", "'and", "/and", "'like", " like", "%00", "null", "admin'","/like", "'where", " where", "/where"]
    passed = next(
            (
                i
                for i in filters
                if i in username
            ),
            None,
        )

    if passed:
        return render_template('login.html', error='Invalid username or password')

    if not token:
        return redirect('/login')
    username = verify_jwt(token, 'HS256')
    if username:
        conn = sqlite3.connect("challenge.db")
        cursor = conn.cursor()
        query = f"SELECT fortune FROM users WHERE username='{username}';"
        result = cursor.execute(query)
        row = result.fetchone()
        if row:
            query = row[0].replace("\\n", "\n").replace("('", "").replace("',)", "")
            conn.close()
            return render_template('dashboard.html', fortunes=query)
        else:
            conn.close()
            return render_template('login.html', error='Invalid username or password')
    else:
        return redirect('/login')

@app.route('/logout')
def logout():
    r = make_response(redirect('/login'))
    r.set_cookie('token', '', expires=0)
    return r

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

