# app.py (Backend)
from flask import Flask, redirect, request, jsonify, render_template, send_from_directory
import requests
import pyodbc
import bcrypt
import os
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import re
import logging
from logging.handlers import RotatingFileHandler
import sys

# Configure logging
def setup_logging():
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    current_date = datetime.now().strftime("%Y-%m-%d")  # Only use the date for naming the log file
    
    # Create log directory if it doesn't exist
    log_dir = os.path.join("C:\\", "Dev", "Web Apps", "VM_WEB_GUI", "Logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"server_{current_date}.log")
    
    # Create a rotating log handler that will append logs to the file
    handler = RotatingFileHandler(
        log_file,
        maxBytes=5*1024*1024,  # 5 MB
        backupCount=3,
        encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(log_format))

    # Configure root logger to append to the log file for the day
    logging.basicConfig(
        level=logging.INFO,
        handlers=[handler]
    )

    # Optionally, redirect stdout/stderr to the logger
    sys.stdout = StreamToLogger(logging.INFO)
    sys.stderr = StreamToLogger(logging.ERROR)

class StreamToLogger:
    """Redirect stdout/stderr to the logger."""
    def __init__(self, log_level):
        self.log_level = log_level
        self.line_buffer = ""

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            logging.log(self.log_level, line.rstrip())

    def flush(self):
        pass


# Initialize logging immediately (or you can also move this into main())
setup_logging()
# Load environment variables first!!!!!! ALV!!!!!!!!
load_dotenv()

app = Flask(__name__, static_folder="static")
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['DATABASE'] = os.getenv('CONNECTION_STR')

#Retrieve the current public IP address.
def get_current_public_ip():
    try:
        response = requests.get("http://myexternalip.com/raw")
        response.raise_for_status()  # Raises an HTTPError for bad responses
        app.logger.info(f"SUCCESS retrieving public IP: {response.text.strip()}")
        return response.text.strip()
    except requests.RequestException as e:
        app.logger.info(f"Error retrieving public IP: {e} will swtich to .env")
        return None
    
# Retrieve the server's public IP address at startup   
server_ip = get_current_public_ip()

# If unable to retrieve the public IP, fall back to the environment variable
if server_ip is None:
    server_ip = os.getenv('ZAMATALLICA_SERVER_IP')
    app.logger.info("Unable to determine the server's public IP. Please set the ZAMATALLICA_SERVER_IP environment variable.")
    raise RuntimeError("Server IP configuration is missing.")

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
        app.logger.info("Attempting to establish database connection...")
        conn = pyodbc.connect(app.config['DATABASE'])
        app.logger.info("Database connection established successfully.")
        return conn
    except pyodbc.Error as e:
        app.logger.error(f"Database connection failed: {str(e)}")
        return None

''' --- Ill save this for later no need to validate a password unlless you are creating a password
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
        return "Password must contain at least one special character"

    return None
'''


@app.before_request
def redirect_to_domain():
    if request.host == server_ip and not request.is_secure:
        return redirect("https://zamatallica.ddns.net" + request.full_path, code=301)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/proxmox/vnc-ticket')
def vnc_ticket():
    vm_id = request.args.get('vmId')
    
    # Proxmox API call
    headers = {
        'Authorization': f'PVEAPIToken={os.getenv("PROXMOX_API_TOKEN")}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f"{os.getenv('PROXMOX_API_BASE')}/nodes/prxmxhomesrvr/qemu/{vm_id}/vncproxy",
            headers=headers  # Include the JSON payload
        )
        response.raise_for_status()
        return jsonify(response.json()['data'])
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
@limiter.limit("5/minute")  # Brute-force protection
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        # Log the received inputs
        app.logger.info(f"Received username: {username}, password length: {len(password)}")
        '''  -- SAVE this chunk for password validation form later
        # Validate input first
        validation_msg = validate_input(username, password)
        if validation_msg:
            return jsonify(success=False, message=validation_msg), 400
        '''
        
        # Convert to bytes after validation
        password_bytes = password.encode('utf-8')

        conn = get_db_connection()
        if not conn:
            return jsonify(success=False, message="Database connection failed"), 500
        
        with conn.cursor() as cursor:
            # Get user with lock status
            cursor.execute("""
                SELECT UserId, PasswordHash, failed_attempts, last_attempt 
                FROM users 
                WHERE username = ?
            """, (username,))
            user = cursor.fetchone()
        

        if not user:
            app.logger.info("User not found")
            # Simulate hash check for timing consistency
            bcrypt.checkpw(b"dummy", bcrypt.gensalt())
            return jsonify(success=False, message="Invalid credentials"), 401
        
        # Extract values correctly (by index)
        user_id, password_hash, failed_attempts, last_attempt = user


        # Check account lock
        if failed_attempts >= 5 and last_attempt:
            lock_time = datetime.now() - last_attempt
            if lock_time < timedelta(minutes=5):
                app.logger.info("Account is locked")
                return jsonify(success=False, message="Account locked"), 403

        # Verify password
        if bcrypt.checkpw(password_bytes, password_hash.encode('utf-8')):
            # Reset failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = 0, last_attempt = NULL 
                WHERE UserId  = ?
            """, (user_id,))
            conn.commit()
            app.logger.info("Login successful")
            return jsonify(success=True), 200
        else:
            # Update failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_attempts = failed_attempts + 1, 
                    last_attempt = ? 
                WHERE UserId  = ?
            """, (datetime.now(), user_id))
            conn.commit()
            app.logger.info("Incorrect password")
            return jsonify(success=False, message="Invalid credentials"), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify(success=False, message="Server error"), 500
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"SERVER START ********************************** Starting Flask Web server at {start_time} *********************************************** SERVER START")
    environment = os.getenv('FLASK_ENV', 'development')  # Default to 'production' if not set
    logging.info(f"Environment: {environment}")
    logging.info(f"Server IP: {server_ip}")
    app.run(host="0.0.0.0", 
            ssl_context=("C:/certs/Certbot/cert.pem", 
                        "C:/certs/Certbot/key.pem"), 
            port=443, debug=True)
