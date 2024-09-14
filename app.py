import os
import pathlib
import requests
import sqlite3
from flask import Flask, session, abort, redirect, request, render_template, flash
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import re

load_dotenv()

# SQLite Config
conn = sqlite3.connect('users.sqlite3', check_same_thread=False)
cursor = conn.cursor()

app = Flask("flask-login-app")
app.secret_key = os.environ.get("APP_SECRET")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.environ.get("CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:3000/callback"
)

flow2 = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:3000/login/callback"
)

def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()
    return wrapper

@app.route('/googlelogin')
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if session["state"] != request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    # Check if the email exists, regardless of OAuth ID
    cursor.execute("SELECT * FROM users WHERE user_email = ?", (id_info.get("email"),))
    row = cursor.fetchone()

    if row:
        # If the user already exists, update the Google ID if necessary
        if not row[3]:  # Assuming `user_oauth_id` is the 4th column
            cursor.execute("UPDATE users SET user_oauth_id = ? WHERE user_email = ?", (id_info.get("sub"), id_info.get("email")))
            conn.commit()
        session['logged_in'] = True
        session["google_id"] = id_info.get("sub")
        session["username"] = id_info.get("name")
        session["email"] = id_info.get("email")
        flash("Logged in successfully.", "success")
    else:
        # Insert new user with OAuth ID
        cursor.execute("INSERT INTO users (username, user_email, user_oauth_id) VALUES (?, ?, ?)",
                       (id_info.get("name"), id_info.get("email"), id_info.get("sub")))
        conn.commit()
        session['logged_in'] = True
        session["google_id"] = id_info.get("sub")
        session["username"] = id_info.get("name")
        session["email"] = id_info.get("email")
        flash("Registration successful. Logged in with Google.", "success")

    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect("/")

@app.route('/')
def index():
    if 'logged_in' in session and session['logged_in']:
        username = session.get('name', 'Guest')  # Use 'name' if that's what you have in the session
        return render_template('index.html', logged_in=True, username=username, show_registration=False)
    else:
        return render_template('index.html', logged_in=False, show_registration=True)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if the password is provided
        if not password:
            flash("Password is required", "error")
            return render_template('index.html', show_registration=True)

        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return render_template('index.html', show_registration=True)
        
        if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
            flash("Password must contain both letters and numbers", "error")
            return render_template('index.html', show_registration=True)

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template('index.html', show_registration=True)

        hashed_password = generate_password_hash(password, method='sha256')

        # Check if the email is already registered
        cursor.execute("SELECT * FROM users WHERE user_email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Email already registered. Please log in.", "error")
            return redirect('/signin')

        # Register the new user
        cursor.execute("INSERT INTO users (username, user_email, user_password) VALUES (?, ?, ?)",
                       (username, email, hashed_password))
        conn.commit()

        session['username'] = username
        session['email'] = email

        flash("Registration successful! You can now log in.", "success")
        return redirect("/signin")
    
    return render_template('index.html', show_registration=True)

@app.route('/signin', methods=["GET", "POST"])
def sign_in():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE user_email = ?", (email,))
        user = cursor.fetchone()

        if user:
            print(f"User found: {user}")  # Debugging line

        if user and user[5] and check_password_hash(user[5], password):  # Assuming password is in the 6th column
            session['logged_in'] = True
            session['username'] = user[1]
            session['email'] = user[2]
            flash('Login successful!', 'success')
            print(f"Session set: {session}")  # Debugging line
            return redirect('/')
        else:
            flash('Incorrect email or password', 'error')
            print(f"Failed login attempt for: {email}")  # Debugging line
            return redirect('/signin')
    else:
        return render_template('index.html')


@app.route('/googlelogin_callback')
def google_login_callback():
    authorization_url, state = flow2.authorization_url()
    session["state2"] = state
    return redirect(authorization_url)

@app.route("/login/callback")
def login_callback():
    if "google_id" in session:
        return abort(404)

    flow2.fetch_token(authorization_response=request.url)

    if session["state2"] != request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow2.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    cursor.execute("SELECT * FROM users WHERE user_oauth_id = ? OR user_email = ?", 
                   (id_info.get("sub"), id_info.get("email")))
    row = cursor.fetchone()

    if row:
        session['logged_in'] = True
        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        session["email"] = id_info.get("email")
        flash("Logged in successfully.", "success")
        return redirect('/')
    else:
        flash("No account found with this Google login. Please register.", "error")
        return redirect('/register')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
