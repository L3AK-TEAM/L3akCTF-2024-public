from flask import Flask, request, render_template, make_response, session, redirect
from flask_session import Session
import uuid
import os
import sqlite3
import jwt
import datetime
from utils.nonce_generator import get_nonce, BITS

app = Flask(__name__, template_folder='templates', static_folder='static')

app.config['SECRET_KEY'] = os.urandom(64)
app.jinja_env.autoescape = False

conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute(
    '''CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE NOT NULL,password TEXT NOT NULL, nonce TEXT NOT NULL)''')
conn.commit()
conn.close()

conn = sqlite3.connect('notes.db')
cursor = conn.cursor()
cursor.execute(
    '''CREATE TABLE IF NOT EXISTS notes (username TEXT NOT NULL,note TEXT NOT NULL,noteid TEXT NOT NULL)''')
conn.commit()
conn.close()

# JWT functions


def encode_jwt(payload):
    try:
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    except Exception as e:
        print(f"Error encoding JWT: {e}")
        return None


def verify_jwt(token):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except Exception as e:
        print(f"Error verifying JWT: {e}")
        return None


def validate_user(username, password):
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?", (username, password))
        if cursor.fetchone():
            conn.commit()
            conn.close()
            return True
        conn.commit()
        conn.close()
        return False
    except Exception as e:
        print(f"Error validating user: {e}")
        return False


def add_to_note(username, note):
    try:
        noteid = str(uuid.uuid4())
        conn = sqlite3.connect('notes.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO notes (username, note, noteid) VALUES (?, ?, ?)", (username, note, noteid))
        conn.commit()
        conn.close()
        return noteid
    except Exception as e:
        print(f"Error adding note: {e}")
        return None


@app.route('/login', methods=['POST', 'GET'])
def login():
    try:
        token = request.cookies.get('token')
        if token:
            user = verify_jwt(token)
            if user:
                return redirect('/')
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            if validate_user(username, password):
                token = encode_jwt({'username': username, 'exp': datetime.datetime.utcnow(
                ) + datetime.timedelta(minutes=30)})
                if token:
                    resp = make_response(redirect('/'))
                    resp.set_cookie('token', token)
                    return resp
                else:
                    return render_template("login.html", error="Failed to generate token")
            else:
                return render_template("login.html", error="Invalid credentials")
        elif request.method == "GET":
            return render_template("login.html")
    except Exception as e:
        print(f"Error in login route: {e}")
        return render_template("login.html", error="An error occurred")


@app.route('/register', methods=['POST', 'GET'])
def register():
    try:
        token = request.cookies.get('token')
        if token:
            user = verify_jwt(token)
            if user:
                return redirect('/')
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            nonce = hex(get_nonce())[2:]
            cursor.execute("INSERT INTO users VALUES (?, ?, ?)",
                           (username, password, nonce))
            conn.commit()
            conn.close()
            return render_template("login.html", success="User registered successfully")
        elif request.method == "GET":
            return render_template("login.html")
    except Exception as e:
        print(f"Error in register route: {e}")
        return render_template("login.html", error="An error occurred")


@app.route("/post_note", methods=['POST', 'GET'])
def post_note():
    try:
        if request.method == "GET":
            return render_template("dash.html", err='hello')
        token = request.cookies.get('token')
        if not token:
            return redirect('/login')
        user = verify_jwt(token)
        if not user:
            return redirect('/login')

        note = request.form.get('note')
        if not note:
            return render_template("dash.html", err="Note cannot be empty")

        if len(note) > 69:
            return render_template("dash.html", err="your note is too long")

        noteid = add_to_note(user['username'], note)
        if noteid:
            resp = make_response(
                redirect(f'/note/{user["username"]}/{noteid}'))
            return resp
        else:
            return render_template("dash.html", error="Failed to add note")
    except Exception as e:
        print(f"Error in post_note route: {e}")
        return render_template("dash.html", error="An error occurred")


@app.route("/")
def home():
    try:
        token = request.cookies.get('token')
        if not token:
            return redirect('/login')
        user = verify_jwt(token)
        if not user:
            return redirect('/login')
        return render_template("dash.html")
    except Exception as e:
        print(f"Error in home route: {e}")
        return render_template("login.html", error="An error occurred")


@app.route("/get_notes")
def get_notes():
    try:
        token = request.cookies.get('token')
        if not token:
            return redirect('/login')
        user = verify_jwt(token)
        if not user:
            return redirect('/login')

        username = user['username']
        conn = sqlite3.connect('notes.db')
        cursor = conn.cursor()
        cursor.execute("SELECT note, noteid FROM notes WHERE username=?",
                       (username,))
        notes = cursor.fetchall()
        conn.commit()
        conn.close()

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT nonce FROM users WHERE username=?",
                       (username,))

        nonce = int(cursor.fetchone()[0], 16)
        resp = make_response(render_template(
            "dash.html", notes=notes, username=username))
        resp.headers['Content-Security-Policy'] = f"script-src 'nonce-{hex(nonce >> (BITS - 64))[2:]}' 'unsafe-eval';"

        new_nonce = get_nonce(nonce)
        cursor.execute("UPDATE users SET nonce = ? WHERE username = ?",
                       (hex(new_nonce)[2:], username))
        conn.commit()
        conn.close()

        return resp
    except Exception as e:
        print(f"Error in get_notes route: {e}")
        return render_template("login.html", error="An error occurred")


@app.route("/note/<string:username>/<string:noteid>")
def get_note(username, noteid):
    try:
        conn = sqlite3.connect('notes.db')
        cursor = conn.cursor()
        cursor.execute("SELECT note FROM notes WHERE username=? AND noteid=?",
                       (username, noteid))
        note = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT nonce FROM users WHERE username=?",
                       (username,))

        nonce = int(cursor.fetchone()[0], 16)
        resp = make_response(render_template("note.html", note=note))
        resp.headers['Content-Security-Policy'] = f"script-src 'nonce-{hex(nonce >> (BITS - 64))[2:]}' 'unsafe-eval';"
        new_nonce = get_nonce(nonce)
        cursor.execute("UPDATE users SET nonce = ? WHERE username = ?",
                       (hex(new_nonce)[2:], username))
        conn.commit()
        conn.close()

        return resp
    except Exception as e:
        print(f"Error in get_note route: {e}")
        return render_template("login.html", error="An error occurred")


@app.route("/logout")
def logout():
    try:
        resp = make_response(redirect('/'))
        resp.set_cookie('token', '', expires=0)
        return resp
    except Exception as e:
        print(f"Error in logout route: {e}")
        return render_template("login.html", error="An error occurred")


if __name__ == '__main__':
    try:
        app.run(host="0.0.0.0", port="8080", debug=False)
    except Exception as e:
        print(f"Error running the application: {e}")
