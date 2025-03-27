# app.py (Backend)
from flask import Flask, redirect, url_for,request, jsonify, render_template, send_from_directory
from flask_socketio import SocketIO
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
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user


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


# Initialize logging immediately (or can also move this into main())
setup_logging()
# Load environment variables first!!!!!! ALV!!!!!!!!
load_dotenv()

app = Flask(__name__, static_folder="static")
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['DATABASE'] = os.getenv('CONNECTION_STR')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Route to redirect unauthorized users

# UserMixin interface:
class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    with conn.cursor() as cursor:
        cursor.execute("SELECT UserId, username FROM users WHERE UserId = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(user_data[0], user_data[1])
    return None

#Configure Websockets
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def handle_connect():
    app.logger.info("Client connected to WebSocket")

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info("Client disconnected from WebSocket")

#Retrieve the current public IP address.
def get_current_public_ip():
    """Function to retrieve public IP (implement your method here)"""
    try:
        import requests
        response = requests.get('https://api64.ipify.org?format=json', timeout=5)
        return response.json().get("ip")
    except Exception as e:
        logging.error(f"Failed to retrieve public IP: {e}")
        return None

# Retrieve the server's public IP address at startup   
server_ip = get_current_public_ip()

# If unable to retrieve the public IP, fall back to the environment variable
if not server_ip:
    server_ip = os.getenv('ZAMATALLICA_SERVER_IP')
    logging.warning("Unable to determine the server's public IP. Falling back to environment variable.")

if not server_ip:
    raise RuntimeError("Server IP configuration is missing. Please set the ZAMATALLICA_SERVER_IP environment variable.")

def is_trusted_ip():
    """ Allow unlimited requests from internal services (adjust as needed). """
    trusted_ips = {"127.0.0.1", "localhost", "192.168.1.17"}  # Use a set for faster lookup
    
    if server_ip:  # Only add if server_ip is valid
        trusted_ips.add(server_ip)

    return get_remote_address() in trusted_ips

# Rate limiter setup
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100000 per day", "5000 per hour"]
)

def get_db_connection():
    try:
        app.logger.info(f"Attempting to establish database connection:  {app.config['DATABASE']}")
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

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify(success=True), 200

@app.route('/api/validate-session', methods=['GET'])
def validate_session():
    if current_user.is_authenticated:
        return jsonify(success=True, user_id=current_user.id), 200
    return jsonify(success=False), 401

@app.route('/api/check-session', methods=['GET'])
def check_session():
    if current_user.is_authenticated:
        return jsonify(success=True, user = current_user.username), 200
    return jsonify(success=False), 401

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
            # Get user with lock status using stored procedure
            cursor.execute("{CALL sp_GetUserForLogin(?)}", (username,))
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
            # Reset failed attempts (logon successful)
            cursor.execute("{CALL sp_ResetFailedAttempts(?, ?)}", (user_id, 0))
            conn.commit()

            # Log the user in
            user_obj = User(user_id, username)
            login_user(user_obj, remember=True, duration=timedelta(hours=12))  # 12-hour session
            app.logger.info("Login successful")
            return jsonify(success=True), 200
        else:
            # Update failed attempts
            cursor.execute("{CALL sp_ResetFailedAttempts(?, ?)}", (user_id, 1))
            conn.commit()
            app.logger.info("Incorrect password")
            return jsonify(success=False, message="Invalid credentials"), 401

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify(success=False, message="Server error"), 500
    finally:
        if 'conn' in locals():
            conn.close()
        

@app.route('/api/user-info', methods=['GET'])
def get_user_info():
        if not current_user.is_authenticated:
            return redirect(url_for('unauthorized'))
    
        try:
            user_id = current_user.id
            if not user_id:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 401

            conn = get_db_connection()
            if not conn:
                return jsonify(success=False, message="Database connection failed"), 500
                    
            with conn.cursor() as cursor:
                cursor.execute("{CALL sp_Get_User_Info(?)}", (user_id,))
                user_info = cursor.fetchone()

            if not user_info:
                return jsonify({'success': False, 'message': 'User not found'}), 404

            first_name, last_name, email, profile_pic, alias, role_name = user_info
            return jsonify({
                    'success':        True,
                 'first_name':  first_name,
                  'last_name':   last_name,
                      'email':       email,
                'profile_pic': profile_pic,
                      'alias':       alias,
                      'role':    role_name,
            })
        
        except Exception as e:
            return jsonify({'success': False, 'message': str(e), 'user_id': user_id}), 500

        finally:
            if conn:
                conn.close()
                
@app.route('/api/get-vms', methods=['GET'])
def get_vms():
    user_id = None

    if not current_user.is_authenticated:
        return redirect(url_for('unauthorized'))

    try:
            user_id = current_user.id
            if not user_id:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 401

            conn = get_db_connection()
            if not conn:
                return jsonify(success=False, message="Database connection failed"), 500
                    
            with conn.cursor() as cursor:
                cursor.execute("{CALL usp_GetUserVMs_backend(?)}", (user_id,))
                user_vms = cursor.fetchall()

            if not user_vms:
                return jsonify({'success': False, 'message': 'User not found', 'user_id': user_id}), 404

            vm_list = []
            for vm in user_vms:
                proxmox_vm_id, proxmox_vm_name = vm
                vm_list.append({
                    'proxmox_vm_id': proxmox_vm_id,
                    'proxmox_vm_name': proxmox_vm_name
                })
            
            return jsonify({'success': True, 'vms': vm_list})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'user_id': user_id}), 500

    finally:
        if conn:
            conn.close()

@app.route('/api/get-vm-user-credentials', methods=['GET'])
def get_vm_user_credentials():
        user_id = None
        conn = None

        if not current_user.is_authenticated:
            return redirect(url_for('unauthorized'))

        try:
            user_id = current_user.id
            if not user_id:
                return jsonify({'success': False, 'message': 'Unauthorized'}), 401

            vm_id = request.args.get('vm_id', '').strip()
            if not vm_id:
                return jsonify({'success': False, 'message': 'No vm_id was given'}), 401
            
            try:
                vm_id = int(vm_id)
            except ValueError:
                return jsonify({'success': False, 'message': 'Invalid vm_id format'}), 400
        
            conn = get_db_connection()
            if not conn:
                return jsonify(success=False, message="Database connection failed"), 500
                    
            with conn.cursor() as cursor:
                cursor.execute("{CALL usp_get_user_vm_credentials_backend(?, ?, 3, 0)}", (user_id,vm_id))
                vm_user_credentials = cursor.fetchall()

            if not vm_user_credentials:
                return jsonify({'success': False, 'message': 'User credentials not found'}), 404

            credentials_list = []
            for credentials in vm_user_credentials:
                account_username, credential_username, vm_pw_hash, domain_name, auth_method, last_logon = credentials
                credentials_list.append({
                    'account_username': account_username,
                    'credential_username': credential_username,
                    'vm_user_password_hash': vm_pw_hash,
                    'domain_name': domain_name,
                    'auth_method_name': auth_method,
                    'vm_last_logon': last_logon,
                })
            return jsonify({'success': True, 'reslt set': credentials_list})
        
        except Exception as e:
            return jsonify({'success': False, 'message': str(e), 'user_id': user_id}), 500

        finally:
            if conn:
                conn.close()

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

if __name__ == '__main__':
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"SERVER START ********************************** Starting Flask Web server at {start_time} *********************************************** SERVER START")
    environment = os.getenv('FLASK_ENV', 'development')  # Default to 'production' if not set
    logging.info(f"Environment: {environment}")
    logging.info(f"Server IP: {server_ip}")
    socketio.run(app, host="0.0.0.0", port=5001,  debug=True)
    
    #Enable HTTPS 
'''   app.run(host="0.0.0.0",  
            ssl_context=("C:/certs/Certbot/cert.pem", 
                        "C:/certs/Certbot/privkey.pem"), 
            port=443, debug=True)'''
