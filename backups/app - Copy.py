# app.py (Backend)
from flask import Flask, request, jsonify, render_template
import pyodbc
import bcrypt
import os
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import re

# Load environment variables first!!!!!! ALV!!!!!!!!
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['DATABASE'] = os.getenv('CONNECTION_STR')

# Rate limiter setup
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def get_db_connection():
    try:
        app.logger.debug("Attempting to establish database connection...")
        conn = pyodbc.connect(app.config['DATABASE'])
        app.logger.debug("Database connection established successfully.")
        return conn
    except pyodbc.Error as e:
        app.logger.error(f"Database connection failed: {str(e)}")
        return None


def validate_input(username, password):
    """Sanitize and validate user input with feedback"""
    
    # Validate username length
    if not (3 <= len(username) <= 30):
        return "Username must be between 3 and 30 characters long."
    
    # Validate username characters
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9@._-]*[a-zA-Z0-9]$", username):
        return "Username can only contain letters, numbers, and '@', '.', '-', '_', but cannot start or end with them."

    # Validate password length
    if not (8 <= len(password) <= 128):
        return "Password must be between 8 and 128 characters long."
    
    # Validate password strength (at least one uppercase, one digit, one special char)
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[@$!%*?&]", password):
        return "Password must contain at least one special character (@, $, !, %, *, ?, &)."

    return "Valid input"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
@limiter.limit("5/minute")  # Brute-force protection
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').encode('utf-8')

        # Log the received inputs
        app.logger.debug(f"Received username: {username}, password length: {len(password)}")


        if not validate_input(username, password):
            return jsonify(success=False, message=validate_input), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Get user with lock status
        cursor.execute("""
            SELECT UserId, PasswordHash, failed_attempts, last_attempt 
            FROM users 
            WHERE username = ?
        """, (username,))
        user = cursor.fetchone()
        

        if not user:
            app.logger.debug("User not found")
            # Simulate similar response time for non-existent users
            bcrypt.checkpw(password, bcrypt.gensalt())
            return jsonify(success=False, message="Invalid credentials"), 401
        
        # Extract values correctly (by index)
        user_id, password_hash, failed_attempts, last_attempt = user


        # Check account lock
        if user.failed_attempts >= 5 and (datetime.now() - user.last_attempt < timedelta(minutes=5)):
            app.logger.debug("Account is locked")
            return jsonify(success=False, message="Account locked"), 403

        # Verify password
        if bcrypt.checkpw(password, password_hash.encode('utf-8')):
            # Reset failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = 0 
                WHERE UserId  = ?
            """, (user.id,))
            conn.commit()
            app.logger.debug("Login successful")
            return jsonify(success=True), 200
        else:
            # Update failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = failed_attempts + 1, 
                    last_attempt = ? 
                WHERE UserId  = ?
            """, (datetime.now(), user.UserId))
            conn.commit()
            app.logger.debug("Incorrect password")
            return jsonify(success=False, message="Invalid credentials"), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify(success=False, message="Server error"), 500
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=1)