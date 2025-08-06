import os
import mysql.connector
import uuid
import cv2
import base64
import numpy as np
import re  # For input validation
from math import ceil
from datetime import datetime, timedelta, time, date
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps  # For decorators
from opencage.geocoder import OpenCageGeocode
from flask_wtf import CSRFProtect
from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.google import make_google_blueprint, google
from connexmail import send_otp_email, generate_otp
from location import get_community_centers, find_closest_community_center, geocode_address
from flask import redirect
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from security_questions import security_questions_route, reset_password_route, forgot_password_route
from facial_recog import register_user_face, capture_face_from_webcam, process_webcam_image_data, verify_user_face, check_face_recognition_enabled

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow insecure transport for OAuth (not recommended for production)


load_dotenv()  # Load environment variables from .env file

# --- Database config (replace with your actual config or import from config file) ---
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = int(os.environ.get('DB_PORT', 3306))

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key')  # Use a secure secret key in production

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
if not OPENAI_API_KEY:
    print("WARNING: OPENAI_API_KEY environment variable is not set. Chatbot may not function.")
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key')  # Use a secure secret key in production

api_key = os.getenv('OPEN_CAGE_API_KEY')
geocoder = OpenCageGeocode(api_key)

# --- Input Validation Functions ---
def validate_password(password):
    """
    Validate password complexity:
    - At least 8 characters
    - Contains at least one number
    - Contains at least one lowercase letter
    - Contains at least one uppercase letter
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;':\",./<>?)."
    
    return True, "Password is valid."

def validate_date_of_birth(dob_str):
    """
    Validate date of birth:
    - Must be a valid date
    - Cannot be in the future
    - Must be at least 13 years old (reasonable minimum age)
    """
    try:
        dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        today = date.today()
        
        # Check if date is in the future
        if dob > today:
            return False, "Date of birth cannot be in the future."
        
        # Calculate age (optional: minimum age check)
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        if age < 13:
            return False, "You must be at least 13 years old to register."
        
        # Check if date is too far in the past (reasonable check)
        if age > 120:
            return False, "Please enter a valid date of birth."
        
        return True, "Date of birth is valid."
        
    except ValueError:
        return False, "Please enter a valid date in YYYY-MM-DD format."

# Initialize OpenCage Geocoder if API key is available


app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(413)
def too_large(e):
    flash("File is too large. Maximum allowed size is 2MB.", "danger")
    return redirect(request.referrer or url_for('admin_events'))

def get_lat_lng_from_address(address):
    if not geocoder:
        print("Geocoding not available - API key not configured")
        return None, None
    try:
        result = geocoder.geocode(address)
        if result and len(result):
            latitude = result[0]['geometry']['lat']
            longitude = result[0]['geometry']['lng']
            return latitude, longitude
        return None, None
    except Exception as e:
        print("Geocoding error:", e)
        return None, None
    
def get_address_from_lat_lng(lat, lng):
    if not geocoder:
        print("Reverse geocoding not available - API key not configured")
        return None
    try:
        result = geocoder.reverse_geocode(lat, lng)
        if result and len(result):
            return result[0]['formatted']  # A readable address string
        return None
    except Exception as e:
        print("Reverse geocoding error:", e)
        return None

# --- Helper functions for /events route ---


google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ],
    redirect_to="google_signup_callback"
)
app.register_blueprint(google_bp, url_prefix="/auth")

# Session configuration for better security
app.config['SESSION_COOKIE_SECURE'] = True  # A05:2021-Security Misconfiguration: Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # A05:2021-Security Misconfiguration: Prevent client-side JS access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # A05:2021-Security Misconfiguration: CSRF protection

# --- Database Connection Management ---
# A03:2021-Injection: Always use parameterized queries.
# A05:2021-Security Misconfiguration: Ensure connection details are from secure sources (.env).

def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
    )

def log_audit_action(action, details, user_id=None, status='Success', email=None, role=None, target_table=None, target_id=None):
    """Log audit actions to the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get the current user_id if not provided
        if user_id is None:
            user_id = session.get('user_id')
        
        # Get email and role from session if not provided
        if email is None:
            email = session.get('user_name', '')
        if role is None:
            role = session.get('user_role', '')
        
        # Insert audit log entry with all the fields
        query = """
        INSERT INTO Audit_Log (user_id, email, role, action, status, details, target_table, target_id, timestamp) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """
        cursor.execute(query, (user_id, email, role, action, status, details, target_table, target_id))
        conn.commit()
        
    except Exception as e:
        # Log the error but don't interrupt the main flow
        print(f"Audit logging error: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

def get_db_cursor(conn):
    return conn.cursor(dictionary=True)

# --- Session Management Functions ---
def create_signup_session(signup_data, otp_code=None, otp_email=None):
    """Create a secure signup session with all necessary data"""
    session_id = f"signup_{datetime.now().timestamp()}"
    session['signup_session_id'] = session_id
    session['signup_session_active'] = True
    session['pending_signup'] = signup_data
    
    if otp_code and otp_email:
        session['otp_code'] = otp_code
        session['otp_email'] = otp_email
        session['otp_verified'] = False
    
    # Set session expiry (30 minutes from now)
    session['signup_session_expires'] = (datetime.now() + timedelta(minutes=30)).timestamp()
    print(f"DEBUG: Created signup session {session_id}")

def create_login_session(user_data, step='password_verified'):
    """Create a secure login session for multi-step authentication"""
    session_id = f"login_{datetime.now().timestamp()}"
    session['login_session_id'] = session_id
    session['login_session_active'] = True
    session['login_step'] = step
    
    # Store temporary user data
    session['temp_user_id'] = user_data.get('user_id')
    session['temp_user_role'] = user_data.get('role')
    session['temp_user_name'] = user_data.get('username')
    session['temp_user_email'] = user_data.get('email', '')
    
    # Set session expiry (15 minutes from now for login security)
    session['login_session_expires'] = (datetime.now() + timedelta(minutes=15)).timestamp()
    print(f"DEBUG: Created login session {session_id} at step {step}")

def is_signup_session_valid():
    """Check if there's a valid active signup session"""
    if not session.get('signup_session_active'):
        return False
    
    # Check if session has expired
    expires = session.get('signup_session_expires')
    if expires and datetime.now().timestamp() > expires:
        clear_signup_session()
        return False
    
    # Check if required data exists
    if not session.get('pending_signup'):
        return False
    
    return True

def is_login_session_valid():
    """Check if there's a valid active login session"""
    if not session.get('login_session_active'):
        return False
    
    # Check if session has expired
    expires = session.get('login_session_expires')
    if expires and datetime.now().timestamp() > expires:
        clear_login_session()
        return False
    
    # Check if required data exists
    if not session.get('temp_user_id'):
        return False
    
    return True

def clear_signup_session():
    """Clear all signup session data"""
    signup_keys = [
        'signup_session_id', 'signup_session_active', 'signup_session_expires',
        'pending_signup', 'otp_code', 'otp_email', 'otp_verified', 'signup_method',
        'captured_face_image', 'security_questions_completed', 'security_question_answers'  # Add new session flags
    ]
    for key in signup_keys:
        session.pop(key, None)
    print("DEBUG: Cleared signup session")

def clear_face_image_from_session():
    """Clear large face image data from session to prevent cookie overflow"""
    session.pop('captured_face_image', None)
    print("DEBUG: Cleared face image from session")

def create_account_with_face(opencv_image):
    """Helper function to create account with facial recognition"""
    signup_data = session.get('pending_signup')
    if not signup_data:
        flash("Signup session expired. Please sign up again.", "error")
        return redirect(url_for('signup'))

    name = signup_data['username']
    password = signup_data['password']
    email = signup_data.get('email', '')
    dob = signup_data['dob']
    location_id = signup_data['location_id']
    is_volunteer = signup_data['is_volunteer']
    hashed_password = generate_password_hash(password)
    role = 'volunteer' if is_volunteer else 'elderly'

    conn = None
    cursor = None
    try:
        print(f"DEBUG: Creating account with facial recognition...")
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generate UUID for the user
        import uuid
        user_uuid = str(uuid.uuid4())
        
        # Try inserting with location_id but handle foreign key constraint gracefully
        try:
            cursor.execute("""
                INSERT INTO Users (uuid, username, email, password, dob, location_id, role, sec_qn_1, sec_qn_2, sec_qn_3)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_uuid, name, email if email else None, hashed_password, dob, location_id, role, None, None, None))
            user_id = cursor.lastrowid
            conn.commit()
            print(f"DEBUG: User inserted successfully with UUID: {user_uuid}")
        except mysql.connector.IntegrityError as ie:
            if ie.errno == 1452:  # Foreign key constraint fails
                print(f"DEBUG: Foreign key constraint detected, inserting without location_id")
                conn.rollback()
                cursor.execute("""
                    INSERT INTO Users (uuid, username, email, password, dob, role, sec_qn_1, sec_qn_2, sec_qn_3)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_uuid, name, email if email else None, hashed_password, dob, role, None, None, None))
                user_id = cursor.lastrowid
                conn.commit()
                print(f"DEBUG: User inserted successfully without location_id but with UUID: {user_uuid}")
            else:
                raise
        
        # Register the face
        success, message = register_user_face(user_id, opencv_image)
        if success:
            print(f"DEBUG: Face registered successfully for user {user_id}")
            if email:
                flash("Account created successfully! Email verified and facial recognition set up.", "success")
            else:
                flash("Account created successfully! Security questions completed and facial recognition set up.", "success")
        else:
            print(f"DEBUG: Face registration failed: {message}")
            flash(f"Account created but facial recognition setup failed: {message}", "warning")
        
        # Clean up session after successful insertion
        clear_signup_session()
        
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"DEBUG: Error during account creation with face: {e}")
        flash("Error creating account. Please try again.", "error")
        return redirect(url_for('signup'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def clear_login_session():
    """Clear all login session data"""
    login_keys = [
        'login_session_id', 'login_session_active', 'login_session_expires',
        'login_step', 'temp_user_id', 'temp_user_role', 'temp_user_name', 'temp_user_email',
        'login_otp_code', 'login_otp_email'
    ]
    for key in login_keys:
        session.pop(key, None)
    print("DEBUG: Cleared login session")

def require_signup_session(f):
    """Decorator to require an active signup session - logs out user if invalid"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_signup_session_valid():
            # Force logout by clearing all session data
            session.clear()
            flash("Invalid session", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_login_session(f):
    """Decorator to require an active login session - logs out user if invalid"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_login_session_valid():
            # Force logout by clearing all session data
            session.clear()
            flash("Invalid session", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Role-Based Access Control (RBAC) Decorators ---
# A01:2021-Broken Access Control: Implement robust access control with decorators.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            # Check if user is in middle of login process
            if session.get('login_step') == 'password_verified' and session.get('temp_user_id'):
                flash("Please complete your security questions to access this page.", 'info')
                return redirect(url_for('security_questions'))
            elif session.get('login_step') == 'otp_required' and session.get('temp_user_id'):
                flash("Please verify your email code to access this page.", 'info')
                return redirect(url_for('login_verify_otp'))
            else:
                flash("You need to be logged in to access this page.", 'info')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required # Ensure user is logged in before checking role
        def decorated_function(*args, **kwargs):
            if g.role not in allowed_roles:
                flash("You do not have permission to access this page.", 'danger')
                app.logger.warning(f"Unauthorized access attempt by user {g.user} (role: {g.role}) to a {allowed_roles} page.")
                return redirect(url_for('home')) # Redirect to a safe page, e.g., home or login
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- User Context Loading ---
@app.before_request
def load_logged_in_user():
    # Clean up expired sessions
    if session.get('signup_session_expires'):
        if datetime.now().timestamp() > session.get('signup_session_expires'):
            clear_signup_session()
    
    if session.get('login_session_expires'):
        if datetime.now().timestamp() > session.get('login_session_expires'):
            clear_login_session()
    
    # Load user context
    g.user = session.get('user_id') # This is the user ID
    g.role = session.get('user_role')
    g.username = session.get('user_name') # This is the username

@app.route('/')
def home():
    if g.role != 'elderly':
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/volunteer_dashboard')
def volunteer_dashboard():
    if g.role != 'volunteer':
        return redirect(url_for('login'))
    return render_template('volunteer.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form.get('email', '').strip() # A03:2021-Injection: Sanitize input by stripping whitespace
        password = request.form.get('password', '').strip()

        # A07:2021-Identification and Authentication Failures: Basic input validation
        if not email_or_username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('login.html')

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = get_db_cursor(conn)
            # A03:2021-Injection: Parameterized query prevents SQL injection
            # Check both email and username fields and get security questions info
            cursor.execute("""
                SELECT user_id, username, password, role, email, sec_qn_1, sec_qn_2, sec_qn_3
                FROM Users 
                WHERE email = %s OR username = %s
            """, (email_or_username, email_or_username))
            user = cursor.fetchone()

            # A07:2021-Identification and Authentication Failures: Generic error message for login
            # This prevents user enumeration.
            if user and check_password_hash(user['password'], password):
                # Clear any existing sessions first
                clear_signup_session()
                clear_login_session()
                
                # Create login session
                create_login_session(user)

                app.logger.info(f"Password verification successful for user {user['username']} ({user['role']}).")

                 # Log successful login
                log_audit_action(
                    action='Login',
                    details=f"Password verified for user {user['email']} with role {user['role']}",
                    user_id=user['user_id'],
                    status='Success'
                )

                # NEW FLOW: Check facial recognition first (highest priority)
                if check_face_recognition_enabled(user['user_id']):
                    # User has facial recognition enabled - redirect to face verification
                    flash("Please verify your identity using facial recognition.", "info")
                    session['login_step'] = 'face_verification_required'
                    return redirect(url_for('login_verify_face'))
                
                # Fallback to existing flow: Check if user has an email (not null or empty)
                user_email = user.get('email', '')
                has_email = user_email and user_email != 'null' and user_email.strip()
                
                if has_email:
                    # User has email - send OTP for login verification
                    otp = generate_otp()
                    print(f"DEBUG: Generated OTP: '{otp}' (type: {type(otp)})")
                    session['login_otp_code'] = otp
                    session['login_otp_email'] = user_email
                    session['login_step'] = 'otp_required'
                    print(f"DEBUG: Stored in session: '{session.get('login_otp_code')}' (type: {type(session.get('login_otp_code'))})")
                    
                    try:
                        send_otp_email(user_email, otp)
                        return redirect(url_for('login_verify_otp'))
                    except Exception as e:
                        app.logger.error(f"Failed to send login OTP to {user_email}: {e}")
                        flash("Failed to send verification code. Please try again.", "error")
                        clear_login_session()
                        return redirect(url_for('login'))
                else:
                    # User doesn't have email - use security questions
                    sec_qn_1 = user.get('sec_qn_1', '')
                    sec_qn_2 = user.get('sec_qn_2', '')
                    sec_qn_3 = user.get('sec_qn_3', '')
                    
                    # Check if security questions are missing or set to "null"
                    needs_security_questions_setup = (
                        not sec_qn_1 or not sec_qn_2 or not sec_qn_3 or
                        sec_qn_1 == 'null' or sec_qn_2 == 'null' or sec_qn_3 == 'null'
                    )
                    
                    if needs_security_questions_setup:
                        # User needs to set up security questions first
                        flash("Please set up your security questions to complete login.", "info")
                        return redirect(url_for('security_questions'))
                    else:
                        # User has security questions - must verify them to complete login
                        flash("Please verify your security questions to complete login.", "info")
                        return redirect(url_for('security_questions'))
            else:
                flash('Invalid credentials.', 'error')

                # Log failed login attempt
                log_audit_action(
                    action='Login',
                    details=f"Invalid credentials for email/username: {email_or_username}",
                    user_id=None,
                    status='Failed'
                )

                app.logger.warning(f"Failed login attempt for email/username: {email_or_username}") # A09:2021-Security Logging
        except Exception as e:
            app.logger.error(f"Login error for email/username {email_or_username}: {e}")
            flash("An unexpected error occurred during login. Please try again.", "error")
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Get community centers from location.py instead of database
    locations = get_community_centers()
    
    if request.method == 'POST':
        # Clear OAuth prefill data once form is submitted
        session.pop('oauth_signup_email', None)
        session.pop('oauth_signup_username', None)
        
        # Get and validate form data
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        dob = request.form.get('dob', '').strip()
        location_id = request.form.get('location_id', '').strip()
        
        # Input validation
        validation_errors = []
        
        # Check required fields
        if not username:
            validation_errors.append("Username is required.")
        elif len(username) < 3:
            validation_errors.append("Username must be at least 3 characters long.")
        
        if not password:
            validation_errors.append("Password is required.")
        else:
            # Validate password complexity
            is_valid, password_msg = validate_password(password)
            if not is_valid:
                validation_errors.append(password_msg)
        
        # Check password confirmation
        if password != confirm_password:
            validation_errors.append("Passwords do not match.")
        
        # Validate date of birth
        if not dob:
            validation_errors.append("Date of birth is required.")
        else:
            is_valid, dob_msg = validate_date_of_birth(dob)
            if not is_valid:
                validation_errors.append(dob_msg)
        
        # Check location selection
        if not location_id:
            validation_errors.append("Please select a community centre.")
        
        # Email validation (if provided)
        if email:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                validation_errors.append("Please enter a valid email address.")
        
        # If there are validation errors, show them and return to form
        if validation_errors:
            for error in validation_errors:
                flash(error, "error")
            return render_template('signup.html', 
                                 locations=locations,
                                 prefill_email=email,
                                 prefill_username=username,
                                 prefill_dob=dob,
                                 max_date=date.today().isoformat())
        
        # Store validated form data in session
        session['pending_signup'] = {
            'username': username,
            'password': password,
            'confirm_password': confirm_password,
            'email': email,
            'dob': dob,
            'location_id': location_id,
            'is_volunteer': 'is_volunteer' in request.form,
            'activate_facial_recognition': 'activate_facial_recognition' in request.form
        }

        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        try:
            # Check if username already exists
            cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
            existing_username = cursor.fetchone()
            cursor.fetchall()  # Consume any remaining results

            if existing_username:
                flash("Username is already taken. Please choose a different username.", "error")
                return render_template('signup.html', 
                                     locations=locations,
                                     prefill_email=email,
                                     prefill_username='',  # Clear username so user can try again
                                     prefill_dob=dob,
                                     max_date=date.today().isoformat())

            # If user provided an email, check if it's already registered and use OTP verification
            if email:
                cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
                existing_email = cursor.fetchone()
                cursor.fetchall()  # Consume any remaining results

                if existing_email:
                    flash("Email is already registered. Please use a different email or try logging in.", "error")
                    return render_template('signup.html', 
                                         locations=locations,
                                         prefill_email='',  # Clear email so user can try again
                                         prefill_username=username,
                                         prefill_dob=dob,
                                         max_date=date.today().isoformat())

                otp = generate_otp()
                print(f"DEBUG: Generated signup OTP: '{otp}' (type: {type(otp)})")
                
                # Clear any leftover login session data to avoid confusion
                clear_login_session()
                
                # Create secure signup session
                signup_data = session['pending_signup']
                create_signup_session(signup_data, otp, email)
                
                print(f"DEBUG: Signup session created successfully")

                # CONDITIONAL LOGIC: Always do email verification first to avoid large session cookies
                # Email + Face Capture → OTP Verification + face capture
                # Email + no Face Capture → OTP Verification
                send_otp_email(email, otp)
                flash("OTP sent to your email for verification.", "success")
                return redirect(url_for('verify_otp'))
            else:
                # No email provided - check if facial recognition is requested
                signup_data = session['pending_signup']
                create_signup_session(signup_data)
                session['signup_method'] = 'security_questions'
                
                # CONDITIONAL LOGIC: Always do security questions first to avoid large session cookies
                # No Email + Face Capture → Security Questions + face capture
                # No Email + no Face Capture → Security Questions
                flash("Please set up security questions to complete your registration.", "info")
                return redirect(url_for('security_questions'))

        except Exception as e:
            flash("An error occurred during signup. Please try again.", "error")
            print(f"Signup Error: {e}")
            return render_template('signup.html', 
                                 locations=locations,
                                 prefill_email=email,
                                 prefill_username=username,
                                 prefill_dob=dob,
                                 max_date=date.today().isoformat())
        finally:
            cursor.close()
            conn.close()

    # Get prefill data from Google OAuth if available
    prefill_email = session.get('oauth_signup_email', '')
    prefill_username = session.get('oauth_signup_username', '')
    
    # Get today's date for date validation
    max_date = date.today().isoformat()
    
    return render_template('signup.html', 
                         locations=locations,
                         prefill_email=prefill_email,
                         prefill_username=prefill_username,
                         max_date=max_date)

@app.route('/api/test_route', methods=['POST'])
def api_test_route():
    """Test API route to check registration"""
    return jsonify({'message': 'test route works'})

@app.route('/api/find_closest_center', methods=['POST'])
def api_find_closest_center():
    """API endpoint to find closest community center based on user location"""
    try:
        data = request.get_json()
        print(f"DEBUG: Received data: {data}")
        
        user_lat = data.get('latitude')
        user_lng = data.get('longitude')
        
        print(f"DEBUG: user_lat: {user_lat}, user_lng: {user_lng}")
        
        if not user_lat or not user_lng:
            print("DEBUG: Missing latitude or longitude")
            return jsonify({'error': 'Latitude and longitude are required'}), 400
        
        print("DEBUG: Calling find_closest_community_center...")
        closest_center = find_closest_community_center(user_lat, user_lng)
        print(f"DEBUG: closest_center result: {closest_center}")
        
        if closest_center:
            print("DEBUG: Returning success response")
            return jsonify({
                'success': True,
                'center': closest_center
            })
        else:
            print("DEBUG: No closest center found")
            return jsonify({'error': 'Could not find closest community center'}), 500
            
    except Exception as e:
        print(f"DEBUG: Exception in api_find_closest_center: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/geocode', methods=['POST'])
def api_geocode():
    """API endpoint to geocode an address"""
    try:
        data = request.get_json()
        address = data.get('address')
        
        if not address:
            return jsonify({'error': 'Address is required'}), 400
        
        result = geocode_address(address)
        
        if result:
            return jsonify({
                'success': True,
                'location': result
            })
        else:
            return jsonify({'error': 'Could not geocode address'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_otp', methods=['GET', 'POST'])
@require_signup_session
def verify_otp():
    # Debug session state
    print(f"DEBUG: Session state at verify_otp: {dict(session)}")
    print(f"DEBUG: Signup session valid: {is_signup_session_valid()}")
    
    if request.method == 'POST':
        # Handle the OTP form submission with individual digit inputs
        otp_digits = []
        for i in range(6):
            digit = request.form.get(f'otp_{i}', '').strip()
            otp_digits.append(digit)
        
        # Also check for a single OTP field (hidden field from JavaScript)
        single_otp = request.form.get('otp', '').strip()
        
        if single_otp:
            entered_otp = single_otp
        else:
            entered_otp = ''.join(otp_digits)
        
        if not entered_otp:
            flash("OTP cannot be empty.", "error")
            return render_template('verify_otp.html')

        # Debug logging
        session_otp = str(session.get('otp_code', ''))
        entered_otp = str(entered_otp)
        print(f"DEBUG: Entered OTP: '{entered_otp}' (type: {type(entered_otp)})")
        print(f"DEBUG: Session OTP: '{session_otp}' (type: {type(session_otp)})")
        print(f"DEBUG: OTP comparison result: {entered_otp == session_otp}")

        if entered_otp == session_otp:
            # OTP verified - now check if facial recognition is needed
            signup_data = session.get('pending_signup')
            if not signup_data:
                flash("Signup session expired. Please sign up again.", "error")
                return redirect(url_for('signup'))
            
            # Mark OTP as verified in session
            session['otp_verified'] = True
            
            # Check if facial recognition is requested
            facial_recognition_requested = signup_data.get('activate_facial_recognition', False)
            if facial_recognition_requested:
                # Check if face was already captured (user did face capture first, then OTP)
                if session.get('captured_face_image'):
                    # Both OTP verified and face captured - create account now
                    try:
                        # Decode the captured face image
                        face_image_data = base64.b64decode(session['captured_face_image'])
                        nparr = np.frombuffer(face_image_data, np.uint8)
                        face_image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                        
                        # Clear face from session immediately to prevent cookie overflow
                        clear_face_image_from_session()
                        
                        # Create account with face
                        return create_account_with_face(face_image)
                        
                    except Exception as face_error:
                        print(f"DEBUG: Error processing stored face image: {face_error}")
                        clear_face_image_from_session()
                        flash("Email verified! Please capture your face again to complete registration.", "info")
                        return redirect(url_for('capture_face'))
                else:
                    # OTP verified, now need face capture before account creation
                    flash("Email verified! Please capture your face to complete registration.", "info")
                    return redirect(url_for('capture_face'))
            else:
                # No facial recognition needed - create account now
                return redirect(url_for('create_account'))
        else:
            flash("Invalid OTP. Please try again.", "error")
            print(f"DEBUG: OTP mismatch - keeping session data intact")
            print(f"DEBUG: Session after failed OTP: {dict(session)}")
            return render_template('verify_otp.html')

    return render_template('verify_otp.html')

@app.route('/create_account')
@require_signup_session
def create_account():
    """Create account without facial recognition after email/security questions verification"""
    signup_data = session.get('pending_signup')
    if not signup_data:
        flash("Signup session expired. Please sign up again.", "error")
        return redirect(url_for('signup'))
    
    # Verify that either OTP or security questions were completed
    email = signup_data.get('email', '').strip()
    if email and not session.get('otp_verified'):
        flash("Please verify your email first.", "error")
        return redirect(url_for('verify_otp'))
    elif not email and not session.get('security_questions_completed'):
        flash("Please complete security questions first.", "error")
        return redirect(url_for('security_questions'))

    name = signup_data['username']
    password = signup_data['password']
    dob = signup_data['dob']
    location_id = signup_data['location_id']
    is_volunteer = signup_data['is_volunteer']
    hashed_password = generate_password_hash(password)
    role = 'volunteer' if is_volunteer else 'elderly'

    conn = None
    cursor = None
    try:
        print(f"DEBUG: Creating account without facial recognition...")
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Generate UUID for the user
        import uuid
        user_uuid = str(uuid.uuid4())
        
        # Try inserting with location_id but handle foreign key constraint gracefully
        try:
            cursor.execute("""
                INSERT INTO Users (uuid, username, email, password, dob, location_id, role, sec_qn_1, sec_qn_2, sec_qn_3)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_uuid, name, email if email else None, hashed_password, dob, location_id, role, None, None, None))
            user_id = cursor.lastrowid
            conn.commit()
            print(f"DEBUG: User inserted successfully with UUID: {user_uuid}")
        except mysql.connector.IntegrityError as ie:
            if ie.errno == 1452:  # Foreign key constraint fails
                print(f"DEBUG: Foreign key constraint detected, inserting without location_id")
                conn.rollback()
                cursor.execute("""
                    INSERT INTO Users (uuid, username, email, password, dob, role, sec_qn_1, sec_qn_2, sec_qn_3)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_uuid, name, email if email else None, hashed_password, dob, role, None, None, None))
                user_id = cursor.lastrowid
                conn.commit()
                print(f"DEBUG: User inserted successfully without location_id but with UUID: {user_uuid}")
            else:
                raise
        
        if email:
            flash("Account created and email verified successfully!", "success")
        else:
            flash("Account created and security questions completed successfully!", "success")
        
        # Clean up session after successful insertion
        clear_signup_session()
        
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"DEBUG: Error during account creation: {e}")
        flash("Error creating account. Please try again.", "error")
        return redirect(url_for('signup'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/capture_face', methods=['GET', 'POST'])
@require_signup_session
def capture_face():
    """Capture face for facial recognition during signup"""
    if request.method == 'POST':
        try:
            # Get image data from the form (base64 from webcam)
            image_data = request.form.get('image_data')
            
            if not image_data:
                flash("No image data received. Please try again.", "error")
                return render_template('capture_face.html')
            
            # Process the webcam image data
            opencv_image = process_webcam_image_data(image_data)
            
            if opencv_image is None:
                flash("Could not process the captured image. Please try again.", "error")
                return render_template('capture_face.html')
            
            # Process the face image immediately without storing in session
            flash("Face captured successfully!", "success")
            
            # Get signup data to determine next step
            signup_data = session.get('pending_signup')
            user_email = signup_data.get('email', '').strip() if signup_data else ''
            
            if user_email:
                # Email user: Check if OTP is already verified
                if session.get('otp_verified'):
                    # Both email and face verification complete - create account now
                    return create_account_with_face(opencv_image)
                else:
                    # Face captured but still need OTP verification
                    # Store face temporarily for final account creation
                    _, buffer = cv2.imencode('.jpg', opencv_image)
                    face_image_b64 = base64.b64encode(buffer).decode('utf-8')
                    session['captured_face_image'] = face_image_b64
                    
                    # Generate and send OTP if not already sent
                    if not session.get('otp_code'):
                        otp = generate_otp()
                        session['otp_code'] = otp
                        session['otp_email'] = user_email
                        send_otp_email(user_email, otp)
                        flash("Face captured! OTP sent to your email for verification.", "success")
                    else:
                        flash("Face captured! Please verify your email to complete registration.", "info")
                    
                    return redirect(url_for('verify_otp'))
            else:
                # No email user: Check if security questions are completed
                if session.get('security_questions_completed'):
                    # Both security questions and face verification complete - create account now
                    from security_questions import _create_account_with_security_questions_and_face
                    return _create_account_with_security_questions_and_face(opencv_image)
                else:
                    # Face captured but still need security questions
                    # Store face temporarily for final account creation
                    _, buffer = cv2.imencode('.jpg', opencv_image)
                    face_image_b64 = base64.b64encode(buffer).decode('utf-8')
                    session['captured_face_image'] = face_image_b64
                    
                    flash("Face captured! Please set up security questions to complete registration.", "info")
                    session['signup_method'] = 'security_questions'
                    return redirect(url_for('security_questions'))
                
        except Exception as e:
            app.logger.error(f"Error capturing face: {e}")
            flash("Error processing face capture. Please try again.", "error")
            return render_template('capture_face.html')
    
    return render_template('capture_face.html')

@app.route('/login_verify_face', methods=['GET', 'POST'])
@require_login_session
def login_verify_face():
    """Verify face for login completion"""
    if request.method == 'POST':
        try:
            # Get image data from the form (base64 from webcam)
            image_data = request.form.get('image_data')
            
            if not image_data:
                flash("No image data received. Please try again.", "error")
                return render_template('login_verify_face.html')
            
            # Process the webcam image data
            opencv_image = process_webcam_image_data(image_data)
            
            if opencv_image is None:
                flash("Could not process the captured image. Please try again.", "error")
                return render_template('login_verify_face.html')
            
            # Get user ID from login session
            user_id = session.get('temp_user_id')
            if not user_id:
                flash("Login session expired. Please login again.", "error")
                clear_login_session()
                return redirect(url_for('login'))
            
            # Verify the face against stored image
            success, message = verify_user_face(user_id, opencv_image)
            
            if success:
                # Face verification successful - complete login
                user_role = session.get('temp_user_role')
                user_name = session.get('temp_user_name')
                
                # Set user session
                session['user_id'] = user_id
                session['user_role'] = user_role
                session['user_name'] = user_name
                
                # Log successful facial recognition login
                log_audit_action(
                    action='Login',
                    details=f'Facial recognition verified for user {session.get("temp_user_email", "")} with role {user_role}',
                    user_id=user_id,
                    status='Success'
                )
                
                # Clean up login session
                clear_login_session()
                
                flash("Login successful! Face verification completed.", "success")
                return redirect(url_for('home'))
            else:
                # Face verification failed - log and provide fallback options
                log_audit_action(
                    action='Login',
                    details=f'Facial recognition failed for user {session.get("temp_user_email", "")} with role {session.get("temp_user_role")}: {message}',
                    user_id=user_id,
                    status='Failed'
                )
                
                flash(f"Face verification failed: {message}. Please try again.", "error")
                
                # Stay in facial recognition flow - do NOT redirect to other methods
                # User must use facial recognition if they have it enabled
                return render_template('login_verify_face.html')
                
        except Exception as e:
            app.logger.error(f"Error during face verification: {e}")
            flash("Error processing face verification. Please try again.", "error")
            return render_template('login_verify_face.html')
    
    # Only render template if GET request (not POST)
    return render_template('login_verify_face.html')

@app.route('/resend_otp', methods=['POST'])
@require_signup_session
def resend_otp():
    try:
        # Generate a new OTP
        new_otp = generate_otp()
        session['otp_code'] = new_otp
        
        # Send the new OTP to the same email
        send_otp_email(session['otp_email'], new_otp)
        
        flash("A new OTP has been sent to your email.", "info")
    except Exception as e:
        flash("Failed to resend OTP. Please try again.", "error")
        print(f"Error resending OTP: {e}")
    
    return redirect(url_for('verify_otp'))

@app.route('/login_verify_otp', methods=['GET', 'POST'])
@require_login_session
def login_verify_otp():
    """Verify OTP for login completion"""
    
    if request.method == 'POST':
        # Handle the OTP form submission with individual digit inputs
        otp_digits = []
        for i in range(6):
            digit = request.form.get(f'otp_{i}', '').strip()
            otp_digits.append(digit)
        
        # Also check for a single OTP field (hidden field from JavaScript)
        single_otp = request.form.get('otp', '').strip()
        
        if single_otp:
            entered_otp = single_otp
        else:
            entered_otp = ''.join(otp_digits)
        
        if not entered_otp:
            flash("OTP cannot be empty.", "error")
            return render_template('verify_otp.html')

        if entered_otp == session.get('login_otp_code'):
            # OTP verified - complete login
            temp_user_id = session.get('temp_user_id')
            temp_user_role = session.get('temp_user_role')
            temp_user_name = session.get('temp_user_name')
            
            # Clear login session and set permanent user session
            clear_login_session()
            session['user_id'] = temp_user_id
            session['user_role'] = temp_user_role
            session['user_name'] = temp_user_name
            
            app.logger.info(f"User {temp_user_name} ({temp_user_role}) completed login via OTP verification.")
            flash("Login completed successfully!", "success")
            
            # Redirect based on role
            if temp_user_role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif temp_user_role == 'volunteer':
                return redirect(url_for('volunteer_dashboard'))
            elif temp_user_role == 'elderly':
                return redirect(url_for('home'))
            else:
                return redirect(url_for('home'))  # Default fallback
        else:
            # Debug information
            print(f"DEBUG: Entered OTP: '{entered_otp}' (type: {type(entered_otp)})")
            print(f"DEBUG: Session OTP: '{session.get('login_otp_code')}' (type: {type(session.get('login_otp_code'))})")
            print(f"DEBUG: OTP Match: {entered_otp == session.get('login_otp_code')}")
            flash("Invalid OTP. Please try again.", "error")
            app.logger.warning(f"Failed OTP verification during login for user {session.get('temp_user_name')}")
            return render_template('verify_otp.html')

    return render_template('verify_otp.html')

@app.route('/resend_login_otp', methods=['POST'])
@require_login_session
def resend_login_otp():
    """Resend OTP for login verification"""
    
    try:
        # Generate a new OTP
        new_otp = generate_otp()
        session['login_otp_code'] = new_otp
        
        # Send the new OTP to the email
        send_otp_email(session['login_otp_email'], new_otp)
        
        flash("A new verification code has been sent to your email.", "info")
        app.logger.info(f"Login OTP resent for user {session.get('temp_user_name')}")
    except Exception as e:
        flash("Failed to resend verification code. Please try again.", "error")
        app.logger.error(f"Error resending login OTP: {e}")
    
    return redirect(url_for('login_verify_otp'))

@app.route('/mfa')
def mfa():
    return render_template('mfa.html')


# Security Questions Routes - imported from security_questions module
@app.route('/security_questions', methods=['GET', 'POST'])
def security_questions():
    """Security questions route using the security_questions module with session protection"""
    # Check if user has either a valid signup or login session
    has_signup_session = is_signup_session_valid()
    has_login_session = is_login_session_valid()
    
    if not has_signup_session and not has_login_session:
        # Force logout by clearing all session data
        session.clear()
        flash("Invalid session", "error")
        return redirect(url_for('login'))
    
    return security_questions_route()

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Password reset route using the security_questions module"""
    return reset_password_route()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password route using the security_questions module"""
    return forgot_password_route()


@app.route('/add_event', methods=['GET', 'POST'], endpoint='user_add_event')
#@login_required(['admin'])
def user_add_event():
    return render_template('add_events.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if g.role != 'admin':
        return redirect(url_for('login'))
    return render_template('admin.html')  # ✅ load the actual template

@app.route('/admin/accounts')
def account_management():
    if g.role != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = get_db_cursor(conn)

    # Fetch users by role with needed fields
    cursor.execute("SELECT email, username, created_at, role FROM Users WHERE role = 'volunteer'")
    volunteers = cursor.fetchall()

    cursor.execute("SELECT email, username, created_at, role FROM Users WHERE role = 'elderly'")
    elderly = cursor.fetchall()

    cursor.execute("SELECT email, username, created_at, role FROM Users WHERE role = 'admin'")
    admins = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('acc_management.html', volunteers=volunteers, elderly=elderly, admins=admins)

@app.route('/admin/accounts/<role_param>/<email_param>', methods=['GET', 'POST'])
@role_required(['admin'])
def account_details(role_param, email_param):
    conn = None
    cursor = None
    user = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            # A03:2021-Injection & A04:2021-Insecure Design: Server-side input validation for updates
            username = request.form.get('username', '').strip()
            updated_role = request.form.get('role', '').strip()
            updated_email = request.form.get('email', '').strip()
            dob = request.form.get('dob')
            location = request.form.get('location', '').strip()

            if not username or not updated_role or not updated_email:
                log_audit_action(
                    user_id=g.user,
                    email=g.username,
                    role=g.role,
                    action='Update_Account',
                    status='Failed',
                    details="Validation failed: missing required fields",
                    target_table='Users',
                    target_id=None
                )
                flash('All fields are required.', 'danger')
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            if updated_role not in ['elderly', 'volunteer', 'admin']:
                log_audit_action(
                    user_id=g.user,
                    email=g.username,
                    role=g.role,
                    action='Update_Account',
                    status='Failed',
                    details=f"Validation failed: invalid role {updated_role}",
                    target_table='Users',
                    target_id=None
                )
                flash('Invalid role specified.', 'danger')
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            if not re.match(r"[^@]+@[^@]+\.[^@]+", updated_email):
                log_audit_action(
                    user_id=g.user,
                    email=g.username,
                    role=g.role,
                    action='Update_Account',
                    status='Failed',
                    details=f"Validation failed: invalid email format {updated_email}",
                    target_table='Users',
                    target_id=None
                )
                flash("Invalid email format.", "danger")
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            # Important: Check if the new email already exists for another user
            cursor.execute("SELECT user_id FROM Users WHERE email = %s AND email != %s", (updated_email, email_param))
            if cursor.fetchone():
                log_audit_action(
                    user_id=g.user,
                    email=g.username,
                    role=g.role,
                    action='Update_Account',
                    status='Failed',
                    details=f"Validation failed: email {updated_email} already in use",
                    target_table='Users',
                    target_id=None
                )
                flash("This email is already in use by another account.", "danger")
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            cursor.execute('''
                UPDATE Users
                SET username = %s, role = %s, email = %s, DOB = %s, location_id = %s
                WHERE email = %s AND role = %s
            ''', (username, updated_role, updated_email, dob if dob else None, location, email_param, role_param))
            conn.commit()

            # Success audit log
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Update_Account',
                status='Success',
                details=f"Updated user {email_param} to {updated_email} with role {updated_role}",
                target_table='Users',
                target_id=None
            )

            # A09:2021-Security Logging: Log administrative actions
            app.logger.info(f"Admin {g.username} updated user {email_param} to {updated_email} (role: {updated_role}).")
            flash('User details updated successfully!', 'success')
            return redirect(url_for('account_management'))

        # GET request - fetch user to prefill form
        cursor.execute("SELECT * FROM Users WHERE email = %s AND role = %s", (email_param, role_param))
        user = cursor.fetchone()

        if user:
            dob_val = user.get('DOB')
            try:
                if isinstance(dob_val, (datetime, date)):
                    user['DOB'] = dob_val.strftime('%Y-%m-%d')
                elif isinstance(dob_val, str):
                    for fmt in ('%Y-%m-%d', '%d/%m/%Y'):
                        try:
                            dob_obj = datetime.strptime(dob_val, fmt)
                            user['DOB'] = dob_obj.strftime('%Y-%m-%d')
                            break
                        except ValueError:
                            continue
                    else:
                        user['DOB'] = ''
                else:
                    user['DOB'] = ''
            except Exception as e:
                app.logger.warning(f"DOB formatting error for user {email_param}: {e}")
                user['DOB'] = ''

            return render_template('acc_details.html', user=user)
        else:
            flash('User not found or role mismatch.', 'warning')
            return redirect(url_for('account_management'))

    except Exception as e:
        log_audit_action(
            user_id=g.user,
            email=g.username,
            role=g.role,
            action='Update_Account',
            status='Failed',
            details=f"Exception during update: {e}",
            target_table='Users',
            target_id=None
        )
        app.logger.error(f"Error in account_details for {email_param}: {e}")
        flash('Failed to process user details.', 'danger')
        if conn: conn.rollback()
        return redirect(url_for('account_management')) # Always redirect on error to prevent exposing internal details
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/delete_account', methods=['POST'])
@role_required(['admin'])
def delete_account():
    # A08:2021-Software and Data Integrity Failures: CSRF protection is handled by Flask-WTF or custom token
    # For a simple form, you might rely on SameSite cookies or implement a CSRF token.
    # The current code lacks explicit CSRF token verification, making it vulnerable to CSRF attacks.
    # Flask-WTF is highly recommended for this.

    email_to_delete = request.form.get('email', '').strip()
    role_to_delete = request.form.get('role', '').strip() # Added role to ensure specific deletion

    if not email_to_delete or not role_to_delete:
        log_audit_action(
            user_id=g.user,
            email=g.username,
            role=g.role,
            action='Delete_Account',
            status='Failed',
            details="No email or role provided for deletion",
            target_table='Users',
            target_id=None
        )
        flash('No email or role provided for deletion.', 'warning')
        return redirect(url_for('account_management'))

    if email_to_delete == g.username: # Prevent admin from deleting themselves
        log_audit_action(
            user_id=g.user,
            email=g.username,
            role=g.role,
            action='Delete_Account',
            status='Failed',
            details="Admin attempted to delete own account",
            target_table='Users',
            target_id=None
        )
        flash('You cannot delete your own admin account!', 'danger')
        return redirect(url_for('account_management'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # A03:2021-Injection: Parameterized query
        cursor.execute("DELETE FROM Users WHERE email = %s AND role = %s", (email_to_delete, role_to_delete))
        conn.commit()

        if cursor.rowcount > 0:
            flash(f'Account {email_to_delete} ({role_to_delete}) deleted successfully.', 'success')
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Delete_Account',
                status='Success',
                details=f"Deleted account {email_to_delete} ({role_to_delete})",
                target_table='Users',
                target_id=None
            )
            app.logger.info(f"Admin {g.username} deleted account: {email_to_delete} ({role_to_delete}).") # A09:2021-Security Logging
        else:
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Delete_Account',
                status='Failed',
                details=f"Account {email_to_delete} ({role_to_delete}) not found or role mismatch",
                target_table='Users',
                target_id=None
            )
            flash(f'Account {email_to_delete} ({role_to_delete}) not found or role mismatch.', 'warning')

    except Exception as e:
        log_audit_action(
            user_id=g.user,
            email=g.username,
            role=g.role,
            action='Delete_Account',
            status='Failed',
            details=f"Exception during deletion: {e}",
            target_table='Users',
            target_id=None
        )
        flash('Error deleting account. Please try again.', 'danger')
        app.logger.error(f"Error deleting account {email_to_delete} ({role_to_delete}): {e}") # A09:2021-Security Logging
        if conn: conn.rollback()
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
    return redirect(url_for('account_management'))

@app.route('/eventdetails/<int:event_id>')
def event_details(event_id):
    """
    Connects to the MySQL database, fetches data for a specific event by ID,
    and renders it in an HTML template. It also checks if the current guest user
    has already signed up for this event and if they are a volunteer for it.
    """
    db_connection = None
    cursor = None
    event = None
    has_signed_up = False
    is_volunteer_for_event = False

    # IMPORTANT: Use g.user directly for ID, g.role for role, and g.username for username
    current_user_id = g.user
    current_user_role = g.role

    # Handle cases where g.user or g.role might be None (not logged in)
    if not current_user_id:
        flash("You need to be logged in to view event details.", 'info')
        return redirect(url_for('login'))

    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        cursor.execute("SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event WHERE EventID = %s", (event_id,))
        event = cursor.fetchone()

        if not event:
            flash(f"No event found with ID {event_id}.", 'error')
            return redirect(url_for('usereventpage'))

        check_signup_query = "SELECT COUNT(*) FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_signup_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            has_signed_up = True

        # Volunteer logic now allows 'user' role (all guests) to volunteer, or 'volunteer' role
        if current_user_role in ['volunteer', 'elderly']: # assuming elderly can also volunteer now based on prev logic
            check_volunteer_query = "SELECT COUNT(*) FROM event_volunteers WHERE event_id = %s AND user_id = %s"
            cursor.execute(check_volunteer_query, (event_id, current_user_id))
            if cursor.fetchone()['COUNT(*)'] > 0:
                is_volunteer_for_event = True

    except mysql.connector.Error as err:
        print(f"Error: {err}")
        flash(f"Database error: {err}", 'error')
        return render_template('error.html', message=f"Database error: {err}")
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('eventdetailpage.html',
                           event=event,
                           has_signed_up=has_signed_up,
                           is_volunteer_for_event=is_volunteer_for_event,
                           user_role=current_user_role)

@app.route('/sign_up_for_event', methods=['POST'])
def sign_up_for_event():
    """
    Handles a user (or guest) signing up for an event.
    """
    event_id = request.form.get('event_id', type=int)
    # IMPORTANT: Use g.user directly for ID and g.username for username
    current_user_id = g.user
    current_username = g.username

    if not current_user_id: # Ensure user is logged in
        flash("You must be logged in to sign up for events.", 'info')
        return redirect(url_for('login'))

    if not event_id:
        flash("Invalid event ID provided for sign-up.", 'error')
        return redirect(url_for('usereventpage'))

    # Removed admin check as per previous comments, assuming only regular users sign up.
    # If admins are explicitly disallowed from signing up, re-add the check:
    # if g.role == 'admin':
    #     flash("Admins cannot sign up for events as regular users.", 'warning')
    #     return redirect(url_for('event_details', event_id=event_id))

    db_connection = None
    cursor = None
    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        check_signup_query = "SELECT COUNT(*) FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_signup_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash(f"You have already signed up for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO user_calendar_events (event_id, user_id, username) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id, current_username))
        db_connection.commit()

        flash(f"Successfully signed up for the event!", 'success')

    except mysql.connector.Error as err:
        print(f"Error signing up for event: {err}")
        flash(f"Error signing up for event: {err}", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))

@app.route('/remove_sign_up', methods=['POST'])
def remove_sign_up():
    """
    Handles removing a user's (or guest's) sign-up for an event.
    """
    event_id = request.form.get('event_id', type=int)
    current_user_id = g.user # Directly use g.user for ID

    if not current_user_id: # Ensure user is logged in
        flash("You must be logged in to remove event sign-ups.", 'info')
        return redirect(url_for('login'))

    if not event_id:
        flash("Invalid event ID provided for removal.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        delete_query = "DELETE FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(delete_query, (event_id, current_user_id))
        db_connection.commit()

        if cursor.rowcount > 0:
            flash(f"Event sign-up removed successfully!", 'success')
        else:
            flash(f"No sign-up found for this event to remove.", 'warning')

    except mysql.connector.Error as err:
        print(f"Error removing event sign-up: {err}")
        flash(f"Error removing event sign-up: {err}", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))

# --- Route for Volunteer Sign-up (Now accessible by 'user' role too) ---
@app.route('/volunteer_for_event', methods=['POST'])
def volunteer_for_event():
    """
    Handles a user signing up to help at an event.
    """
    current_user_id = g.user # Directly use g.user for ID
    current_user_role = g.role

    # This check needs to be aligned with your user roles.
    # If only 'volunteer' role can volunteer:
    # if current_user_role != 'volunteer':
    #     flash("You are not authorized to volunteer for events.", 'error')
    #     return redirect(url_for('home')) # Or redirect to login

    # If all logged-in users (elderly and volunteer) can volunteer:
    if not current_user_id:
        flash("You must be logged in to volunteer for events.", 'info')
        return redirect(url_for('login'))

    event_id = request.form.get('event_id', type=int)
    # user_id = g.user['id'] # The current guest user ID -- CHANGED TO g.user directly for ID

    if not event_id:
        flash("Invalid event ID provided for volunteering.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        # Check if already volunteered
        check_query = "SELECT COUNT(*) FROM event_volunteers WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash("You have already volunteered for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO event_volunteers (event_id, user_id) VALUES (%s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id))
        db_connection.commit()
        flash("Successfully signed up to volunteer for the event!", 'success')

    except mysql.connector.Error as err:
        print(f"Error volunteering for event: {err}")
        flash(f"Error volunteering for event: {err}", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))

@app.route('/remove_volunteer', methods=['POST'])
def remove_volunteer():
    """
    Handles a user removing their sign-up to help at an event.
    """
    current_user_id = g.user # Directly use g.user for ID
    current_user_role = g.role

    # Check for authorization. Only logged-in users can remove their volunteer sign-up.
    if not current_user_id:
        flash("You must be logged in to remove your volunteer sign-up.", 'info')
        return redirect(url_for('login'))

    event_id = request.form.get('event_id', type=int)
    # user_id = g.user['id'] -- CHANGED TO g.user directly for ID

    if not event_id:
        flash("Invalid event ID provided for removal.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        delete_query = "DELETE FROM event_volunteers WHERE event_id = %s AND user_id = %s"
        cursor.execute(delete_query, (event_id, current_user_id))
        db_connection.commit()

        if cursor.rowcount > 0:
            flash("Successfully removed your volunteer sign-up.", 'success')
        else:
            flash("No volunteer sign-up found for this event to remove.", 'warning')

    except mysql.connector.Error as err:
        print(f"Error removing volunteer sign-up: {err}")
        flash(f"Error removing volunteer sign-up: {err}", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))


# --- API Endpoint for FullCalendar.js ---
@app.route('/api/my_events')
def api_my_events():
    """
    Returns the current user's signed-up events in a JSON format suitable for FullCalendar.js.
    This also fetches the username.
    """
    current_user_id = g.user # Directly use g.user for ID
    current_username = g.username # Directly use g.username for username

    if not current_user_id: # Ensure user is logged in
        return jsonify({"error": "Unauthorized"}), 401

    events = []

    db_connection = None
    cursor = None
    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        # Query to fetch events from user_calendar_events and event_volunteers
        # UNION to combine and deduplicate results.
        query = f"""
            SELECT uce.username AS signup_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue
            FROM user_calendar_events uce
            JOIN event e ON uce.event_id = e.EventID
            WHERE uce.user_id = %s

            UNION

            SELECT '{current_username}' AS signup_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue
            FROM event_volunteers ev
            JOIN event e ON ev.event_id = e.EventID
            WHERE ev.user_id = %s

            ORDER BY Date, Time
        """
        cursor.execute(query, (current_user_id, current_user_id))
        signed_up_events_raw = cursor.fetchall()

        for event_data in signed_up_events_raw:
            event_date_obj = event_data['Date']
            event_time_str = event_data['Time']

            start_time_obj, end_time_obj = parse_time_range(event_time_str)

            start_datetime = datetime.combine(event_date_obj, start_time_obj)
            end_datetime = datetime.combine(event_date_obj, end_time_obj)

            if end_datetime < start_datetime:
                end_datetime += timedelta(days=1)

            # Display title now includes the username of the signer-upper
            display_title = f"{event_data['EventDescription']} ({event_data['signup_username']})"

            events.append({
                'id': event_data['EventID'],
                'title': display_title,
                'start': start_datetime.isoformat(),
                'end': end_datetime.isoformat(),
                'allDay': False,
                'url': url_for('event_details', event_id=event_data['EventID'])
            })

    except mysql.connector.Error as err:
        print(f"Error fetching events for API: {err}")
        return jsonify({"error": "Failed to load events"}), 500
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return jsonify(events)


@app.route('/calendar')
def calendar():
    """
    Renders the calendar page, displaying the FullCalendar.js widget and
    a list of ALL signed-up events on the left sidebar (no date filter),
    including events volunteered for. This also fetches the username.
    """
    current_user_id = g.user # Directly use g.user for ID
    current_username = g.username # Directly use g.username for username

    if not current_user_id: # Ensure user is logged in
        flash("You need to be logged in to view your calendar.", 'info')
        return redirect(url_for('login'))

    db_connection = None
    cursor = None
    signed_up_events = []

    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        query = f"""
            SELECT uce.username AS event_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue, e.Category
            FROM user_calendar_events uce
            JOIN event e ON uce.event_id = e.EventID
            WHERE uce.user_id = %s

            UNION

            SELECT '{current_username}' AS event_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue, e.Category
            FROM event_volunteers ev
            JOIN event e ON ev.event_id = e.EventID
            WHERE ev.user_id = %s

            ORDER BY Date ASC, Time ASC
        """
        cursor.execute(query, (current_user_id, current_user_id))
        signed_up_events = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Error fetching signed up events for calendar list: {err}")
        flash(f"Error loading your events list: {err}", 'error')
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('calendar.html', signed_up_events=signed_up_events, user_id=current_user_id)


# --- Helper function to parse time strings like "9am-12pm" or "10:00-11:00" ---
def parse_time_range(time_str):
    """
    Parses a time range string (e.g., "9am-12pm", "10:00-11:00") into
    start and end datetime.time objects.
    """
    try:
        parts = time_str.split('-')
        start_time_str = parts[0].strip()
        end_time_str = parts[1].strip() if len(parts) > 1 else None

        # Helper to convert various time formats to HH:MM (24-hour)
        def convert_to_24hr_format(t_str):
            t_str = t_str.lower().replace('.', '') # remove dots like 9.30am

            if 'am' in t_str:
                t_str = t_str.replace('am', '')
                if ':' in t_str: # e.g., 9:30am
                    return datetime.strptime(t_str, '%I:%M').strftime('%H:%M')
                else: # e.g., 9am
                    return datetime.strptime(t_str, '%I').strftime('%H:%M')
            elif 'pm' in t_str:
                t_str = t_str.replace('pm', '')
                if ':' in t_str: # e.g., 1:30pm
                    dt_obj = datetime.strptime(t_str, '%I:%M')
                    if dt_obj.hour == 12: # 12 PM is 12:xx
                        return dt_obj.strftime('%H:%M')
                    return (dt_obj + timedelta(hours=12)).strftime('%H:%M')
                else: # e.g., 1pm
                    dt_obj = datetime.strptime(t_str, '%I')
                    if dt_obj.hour == 12: # 12 PM is 12:xx
                        return dt_obj.strftime('%H:%M')
                    return (dt_obj + timedelta(hours=12)).strftime('%H:%M')
            elif ':' in t_str: # Assume HH:MM format (24-hour or 12-hour without am/pm)
                return datetime.strptime(t_str, '%H:%M').strftime('%H:%M')
            else: # Assume just hour in 24-hour format
                return datetime.strptime(t_str, '%H').strftime('%H:%M')

        start_24hr = convert_to_24hr_format(start_time_str)
        start_dt_time = datetime.strptime(start_24hr, '%H:%M').time()

        end_dt_time = None
        if end_time_str:
            end_24hr = convert_to_24hr_format(end_time_str)
            end_dt_time = datetime.strptime(end_24hr, '%H:%M').time()
        else:
            # If no end time is specified, assume a default duration, e.g., 1 hour
            # This is a fallback; ideally, your database 'Time' has clear ranges.
            start_dt = datetime.combine(datetime.min.date(), start_dt_time)
            end_dt_time = (start_dt + timedelta(hours=1)).time()

        return start_dt_time, end_dt_time

    except Exception as e:
        print(f"Warning: Could not parse time string '{time_str}'. Error: {e}")
        return time(0, 0), time(23, 59) # Default to full day if parsing fails


@app.route('/chat')
def chat():
    """
    Renders the chatbot page.
    This page will contain JavaScript to send messages to the /api/chat endpoint.
    """
    return render_template('chat.html', openai_api_key=OPENAI_API_KEY)

@app.route('/events')
def events():
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute("SELECT * FROM event;")
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('events.html', events=events)



@app.route('/signup/google/callback')
def google_signup_callback():
    try:
        if not google.authorized:
            # User hasn't authorized yet or authorization was cancelled
            # Redirect silently back to signup without error message
            return redirect(url_for("signup"))

        resp = google.get("/oauth2/v1/userinfo")
        if not resp.ok:
            flash("Failed to fetch user info from Google", "error")
            return redirect(url_for("signup"))

        google_info = resp.json()
        email = google_info.get("email")
        username = google_info.get("name") or email.split("@")[0]

        # Only prefill signup form, do NOT log the user in
        session['oauth_signup_email'] = email
        session['oauth_signup_username'] = username
        flash("Google info filled. Please complete signup.", "info")
        return redirect(url_for('signup'))
    except Exception as e:
        # Only show error for actual exceptions, not authorization failures
        flash(f"Google authentication error: {e}", "error")
        return redirect(url_for("signup"))

# OAuth authorized handler for Flask-Dance
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    # Let the manual callback route handle everything
    # This handler just needs to exist to prevent Flask-Dance from throwing errors
    return False  # Don't save the token, let the callback route handle the logic



@app.route('/api/events')
def api_get_events():
    search = request.args.get('search', '').strip()
    categories = request.args.getlist('category')
    locations = request.args.getlist('location')

    page = request.args.get('page', 1, type=int)
    per_page = 6
    offset = (page - 1) * per_page

    filters = []
    values = []

    if categories:
        placeholders = ','.join(['%s'] * len(categories))
        filters.append(f"category IN ({placeholders})")
        values.extend(categories)

    if locations:
        placeholders = ','.join(['%s'] * len(locations))
        filters.append(f"location_name IN ({placeholders})")
        values.extend(locations)

    if search:
        filters.append("title LIKE %s")
        values.append(f"%{search}%")

    where_clause = "WHERE " + " AND ".join(filters) if filters else ""

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    count_query = f"SELECT COUNT(*) AS total FROM Events {where_clause}"
    cursor.execute(count_query, values)
    total_events = cursor.fetchone()['total']
    total_pages = ceil(total_events / per_page) if total_events > 0 else 1

    query = f"""
        SELECT event_id AS id, title, event_date, organisation, category,
               image, description, current_elderly, max_elderly,
               current_volunteers, max_volunteers, location_name
        FROM Events
        {where_clause}
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """

    cursor.execute(query, values + [per_page, offset])
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify({
        "events": [{
            'id': row['id'],
            'title': row['title'],
            'event_date': row['event_date'].strftime('%Y-%m-%d') if row['event_date'] else '',
            'organisation': row['organisation'],
            'category': row['category'],
            'image': row['image'],
            'description': row['description'],
            'current_elderly': row['current_elderly'],
            'max_elderly': row['max_elderly'],
            'current_volunteers': row['current_volunteers'],
            'max_volunteers': row['max_volunteers'],
            'location_name': row['location_name'] or ""  # fallback to empty string
        } for row in rows],
        "page": page,
        "total_pages": total_pages
    })

@app.route('/admin/events')
def admin_events():
    if g.role != 'admin':
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    per_page = 6
    offset = (page - 1) * per_page

    categories = request.args.getlist('category')
    locations = request.args.getlist('location')
    search = request.args.get('search', '').strip()

    filters = []
    values = []

    if categories:
        placeholders = ','.join(['%s'] * len(categories))
        filters.append(f"category IN ({placeholders})")
        values.extend(categories)

    if locations:
        placeholders = ','.join(['%s'] * len(locations))
        filters.append(f"location_name IN ({placeholders})")
        values.extend(locations)

    if search:
        filters.append("title LIKE %s")
        values.append(f"%{search}%")

    where_clause = "WHERE " + " AND ".join(filters) if filters else ""

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get distinct categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM Events ORDER BY category ASC")
    all_categories = [row['category'] for row in cursor.fetchall()]

    # *** CHANGE HERE: Get location names FROM Locations table ***
    cursor.execute("SELECT location_name FROM Locations ORDER BY location_name ASC")
    all_locations = [row['location_name'] for row in cursor.fetchall()]

    # Count total filtered events for pagination
    count_query = f"SELECT COUNT(*) AS total FROM Events {where_clause}"
    cursor.execute(count_query, values)
    total_events = cursor.fetchone()['total']
    total_pages = ceil(total_events / per_page) if total_events > 0 else 1

    # Select events with filters and pagination
    query = f"""
        SELECT * FROM Events
        {where_clause}
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
    """
    cursor.execute(query, values + [per_page, offset])
    events = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        'admin_events.html',
        events=events,
        page=page,
        total_pages=total_pages,
        selected_categories=categories,
        selected_locations=locations,
        search_query=search,
        all_categories=all_categories,
        all_locations=all_locations
    )

  
@app.route('/admin/events/add', methods=['GET', 'POST'], endpoint='admin_add_event')
def admin_add_event():
    if g.role != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['event_title']
        organization = request.form['organization']
        date = request.form['date']
        max_participants = request.form['participants']
        max_volunteers = request.form['volunteers']
        category = request.form['category']
        description = request.form['description']
        picture = request.files['picture']
        address_input = request.form['location']

        # Get latitude and longitude from user input address
        lat, lng = get_lat_lng_from_address(address_input)
        if lat is None or lng is None:
            flash('Invalid address. Please enter a valid location.', 'danger')
            return redirect(url_for('add_event'))

        # Get human-readable address (reverse geocode)
        location_name = request.form['location']  # Admin’s original input

        if picture and picture.filename != '':
            filename = secure_filename(picture.filename)
            image_path = os.path.join('static', 'images', filename)
            picture.save(image_path)
        else:
            flash('Image upload failed or missing.', 'danger')
            return redirect(url_for('add_event'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO Events (
                    title, organisation, event_date, max_elderly,
                    max_volunteers, latitude, longitude, location_name, 
                    category, description, image, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                title, organization, date, max_participants,
                max_volunteers, lat, lng, location_name,
                category, description, filename
            ))

            conn.commit()
            
            flash('Event added successfully!', 'success')
            return redirect(url_for('admin_events'))

        except Exception as e:
            print("Error inserting event:", e)
            flash("Failed to add event.", "danger")
            if conn:
                conn.rollback()
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('add_events.html')


@app.route('/admin/event/<int:event_id>')
def admin_event_details(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM Events WHERE event_id = %s", (event_id,))
    event = cursor.fetchone()

    if not event:
        flash('Event not found.', 'danger')
        return redirect(url_for('admin_events'))

    event_date = None
    if event['event_date']:
        try:
            event_date = datetime.strptime(str(event['event_date']), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                event_date = datetime.strptime(str(event['event_date']), '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format for event.', 'danger')

    cursor.execute("""
        SELECT u.username, u.email
        FROM Event_detail ed
        JOIN Users u ON ed.user_id = u.user_id
        WHERE ed.event_id = %s AND u.role = 'volunteer'
    """, (event_id,))
    volunteers = cursor.fetchall()

    cursor.execute("""
        SELECT u.username, u.email
        FROM Event_detail ed
        JOIN Users u ON ed.user_id = u.user_id
        WHERE ed.event_id = %s AND u.role = 'elderly'
    """, (event_id,))
    elderly = cursor.fetchall()

    cursor.close()
    conn.close()

    delete_error = request.args.get('delete_error')
    return render_template('event_details.html', event={
        'id': event['event_id'],
        'title': event['Title'],
        'description': event['description'],
        'date': event_date,
        'organisation': event['organisation'],
        'category': event['category'],
        'image': event['image'],
        'location': event['location_name'],  # Use cached human-readable address
        'max_elderly': event['max_elderly'],
        'max_volunteers': event['max_volunteers'],
        'current_elderly': event['current_elderly'],
        'current_volunteers': event['current_volunteers'],
        'volunteers': volunteers,
        'elderly': elderly
    }, delete_error=delete_error)


@app.route('/admin/event/<int:event_id>/delete', methods=['POST'])
def delete_event(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    email = request.form.get('admin_email')
    password = request.form.get('admin_password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get event title before deleting
    cursor.execute("SELECT title FROM Events WHERE event_id = %s", (event_id,))
    event = cursor.fetchone()

    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for('admin_events'))

    event_title = event['title']

    # Get admin record
    cursor.execute("SELECT * FROM Users WHERE email = %s AND role = 'admin'", (email,))
    admin = cursor.fetchone()

    # Verify admin
    if not admin or not check_password_hash(admin['password'], password):
        # Log failed delete due to auth failure
        log_audit_action(
            user_id=None,
            email=email,
            role='admin',
            action='Delete_Event',
            status='Failed',
            details=f"Authentication failed for deleting event_id {event_id}",
            target_table='Events',
            target_id=event_id
        )
        cursor.close()
        conn.close()
        return redirect(url_for('admin_event_details', event_id=event_id, delete_error="Authentication failed. Please try again."))

    # Delete event
    cursor.execute("DELETE FROM Events WHERE event_id = %s", (event_id,))
    conn.commit()
     # Log successful deletion
    log_audit_action(
        user_id=admin['user_id'],
        email=admin['email'],
        role=admin['role'],
        action='Delete_Event',
        status='Success',
        details=f"Deleted event titled '{event_title}'",
        target_table='Events',
        target_id=event_id
    )
    cursor.close()
    conn.close()

    flash(f'"{event_title}" was successfully deleted.', 'success')
    return redirect(url_for('admin_events'))

@app.route('/admin/event/<int:event_id>/update_image', methods=['POST'])
def update_event_image(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    file = request.files.get('new_image')
    if not file or file.filename == '':
        flash('No file selected.', 'danger')
        # Log failure due to no file selected
        log_audit_action(
            user_id=g.user,
            email=session.get('user_email'),
            role=g.role,
            action='Update_Event_Image',
            status='Failed',
            details=f"No file selected for event_id {event_id}",
            target_table='Events',
            target_id=event_id
        )
        return redirect(url_for('admin_event_details', event_id=event_id))

    if not allowed_file(file.filename):
        # Log failure due to invalid file type
        log_audit_action(
            user_id=g.user,
            email=session.get('user_email'),
            role=g.role,
            action='Update_Event_Image',
            status='Failed',
            details=f"Invalid file type for event_id {event_id}",
            target_table='Events',
            target_id=event_id
        )
        flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'danger')
        return redirect(url_for('admin_event_details', event_id=event_id))

    # Secure filename
    filename = secure_filename(file.filename)
    filepath = os.path.join('static', 'images', filename)

    # Save file
    file.save(filepath)

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE Events SET image = %s WHERE event_id = %s", (filename, event_id))
    conn.commit()
    # Log success
    log_audit_action(
        user_id=g.user,
        email=session.get('user_email'),
        role=g.role,
        action='Update_Event_Image',
        status='Success',
        details=f"Updated image to '{filename}'",
        target_table='Events',
        target_id=event_id
    )
    cursor.close()
    conn.close()

    flash('Event image updated successfully.', 'success')
    return redirect(url_for('admin_event_details', event_id=event_id))

@app.route('/admin/event/<int:event_id>/update_details', methods=['POST'])
def update_event_details(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    title = request.form.get('title')
    organisation = request.form.get('organisation')
    location = request.form.get('location')
    date = request.form.get('date')
    description = request.form.get('description')

    # Update DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE Events
        SET title=%s, organisation=%s, location=%s, event_date=%s, description=%s
        WHERE event_id=%s
    """, (title, organisation, location, date, description, event_id))
    conn.commit()
    # Log success
    log_audit_action(
        user_id=g.user,
        email=session.get('user_email'),
        role=g.role,
        action='Update_Event_Details',
        status='Success',
        details=f"Updated event details: title='{title}', organisation='{organisation}', location='{location}', date='{date}'",
        target_table='Events',
        target_id=event_id
    )
    cursor.close()
    conn.close()

    # If AJAX request, return JSON response with updated data
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'event': {
                'title': title,
                'organisation': organisation,
                'location': location,
                'date': date,
                'description': description
            }
        })

    flash('Event details updated successfully.', 'success')
    return redirect(url_for('admin_event_details', event_id=event_id))

# OAuth authorized handler for Flask-Dance
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        # No token received, user likely cancelled or there was an issue
        return False

    resp = blueprint.session.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return False

    google_info = resp.json()
    session['oauth_signup_email'] = google_info.get("email")
    session['oauth_signup_username'] = google_info.get("name") or google_info.get("email").split("@")[0]
    flash("Google account connected successfully!", "success")
    return False  # Don't save the token, just redirect

@app.route('/audit')
@role_required(['admin'])
def audit():
    reset = request.args.get('reset', '')

    if reset == '1':
        filter_date = ''
        filter_role = ''
        filter_action = ''
    else:
        filter_date = request.args.get('date', '')
        filter_role = request.args.get('role', '')
        filter_action = request.args.get('action', '')

    query = """
        SELECT a.audit_id, a.user_id, a.role as actor_role, a.action, a.target_table, a.target_id, a.timestamp, a.status, a.details, u.email as actor_email
        FROM Audit_Log a
        LEFT JOIN Users u ON a.user_id = u.user_id
        WHERE a.timestamp >= NOW() - INTERVAL 30 DAY
    """
    
    params = []
    
    # Add filters to query if provided
    if filter_date:
        query += " AND DATE(a.timestamp) = %s"
        params.append(filter_date)
    
    if filter_role:
        query += " AND a.role = %s"
        params.append(filter_role)
    
    if filter_action:
        query += " AND a.action = %s"
        params.append(filter_action)
    
    query += " ORDER BY a.timestamp DESC"
    
    conn = None
    cursor = None
    audit_logs = []
    
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute(query, params)
        audit_logs = cursor.fetchall()
    except Exception as e:
        flash(f"Error loading audit logs: {e}", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('audit.html', 
                         audit_logs=audit_logs,
                         filter_date=filter_date,
                         filter_role=filter_role,
                         filter_action=filter_action)

@app.route('/cancel_signup')
def cancel_signup():
    """Allow users to cancel the signup process"""
    clear_signup_session()
    flash("Signup cancelled.", "info")
    return redirect(url_for('signup'))

@app.route('/cancel_login')
def cancel_login():
    """Allow users to cancel the login process if they're stuck in security questions or OTP verification"""
    clear_login_session()
    flash("Login cancelled. Please try again.", "info")
    return redirect(url_for('login'))

@app.route('/error')
def error(): 
    # A11:2021-Software and Data Integrity Failures: This route should handle errors gracefully.
    # It can be used to render a custom error page.
    return render_template('error.html', message="An unexpected error occurred. Please try again later.")

@app.route('/session_status')
def session_status():
    """Debug route to check current session status - remove in production"""
    if not app.debug:
        return abort(404)
    
    return jsonify({
        'signup_session_valid': is_signup_session_valid(),
        'login_session_valid': is_login_session_valid(),
        'user_logged_in': bool(g.user),
        'session_data': {k: str(v) for k, v in session.items() if not k.startswith('_')}
    })

@app.route('/logout')
def logout():
    """Logout route to clear user session and redirect to login"""
    # Log the logout action
    if g.user:
        log_audit_action(
            action='Logout',
            details=f"User {g.username} logged out",
            user_id=g.user,
            status='Success'
        )
        app.logger.info(f"User {g.username} ({g.role}) logged out.")
    
    # Clear all session data
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    """Support page for users to submit and view tickets"""
    # This is a basic support page implementation
    # You can expand this based on your support ticket system requirements
    return render_template('support.html')

@app.route('/admin_support')
@role_required(['admin'])
def admin_support():
    """Admin support page to manage support tickets"""
    # This is a basic admin support page implementation
    # You can expand this based on your admin requirements
    return render_template('admin_support.html')

@app.route('/usereventpage')
@login_required
def usereventpage():
    """Events page showing all available events"""
    conn = None
    cursor = None
    events = []
    
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        
        # Fetch all events from database
        cursor.execute("""
            SELECT EventID as event_id, EventDescription as description, 
                   Date, Time, Venue, Category, ImageFileName as image
            FROM event 
            ORDER BY Date, Time
        """)
        events = cursor.fetchall()
        
    except Exception as e:
        app.logger.error(f"Error fetching events: {e}")
        flash("Error loading events. Please try again later.", "error")
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('usereventpage.html', events=events)

@app.route('/view_ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    """View individual support ticket"""
    # Basic implementation - expand based on your ticket system
    return render_template('view-ticket.html', ticket_id=ticket_id)

@app.route('/close_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def close_ticket(ticket_id):
    """Close a support ticket"""
    # Basic implementation - expand based on your ticket system
    flash("Ticket closed successfully.", "success")
    return redirect(url_for('support'))

@app.route('/delete_ticket/<int:ticket_id>', methods=['POST'])
@role_required(['admin'])
def delete_ticket(ticket_id):
    """Delete a support ticket (admin only)"""
    # Basic implementation - expand based on your ticket system
    flash("Ticket deleted successfully.", "success")
    return redirect(url_for('admin_support'))

if __name__ == '__main__':
    # Debug: Print API routes to verify they're registered
    print("\n=== DEBUG: API Routes ===")
    for rule in app.url_map.iter_rules():
        if 'api' in rule.rule:
            print(f"Route: {rule.rule} -> {rule.endpoint} (methods: {list(rule.methods)})")
    print("=== End API Routes ===\n")
    
    # A05:2021-Security Misconfiguration: Never run with debug=True in production.
    # Debug mode can expose sensitive information and allow arbitrary code execution.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='127.0.0.1', port=5000) # Use 0.0.0.0 to make it accessible in container/VM, but bind to specific IP in production if possible