import os
import uuid
import pytz
import mysql.connector
import uuid
import cv2
import base64
import numpy as np
import re  # For input validation
import smtplib
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
from flask import redirect, send_file
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from security_questions import security_questions_route, reset_password_route, forgot_password_route
from facial_recog import register_user_face, capture_face_from_webcam, process_webcam_image_data, verify_user_face, check_face_recognition_enabled
from honeypot import log_honeypot_access, log_security_questions_access, log_form_submission, get_honeypot_logs, get_suspicious_user_agents, get_bot_statistics, get_honeypot_logs_filtered
# SERVER-SIDE VALIDATION: Import validation functions for all authentication features
from validation import (
    validate_login_credentials, validate_user_exists_and_active,
    validate_signup_username, validate_signup_email, validate_signup_password,
    validate_date_of_birth_server, validate_location_selection,
    validate_security_question_answers, validate_security_question_verification,
    validate_face_image_data, validate_face_detection_result,
    validate_otp_input, validate_session_data, validate_user_role,
    sanitize_input
)

# ================================================================================================
# SERVER-SIDE VALIDATION QUICK REFERENCE GUIDE
# ================================================================================================
# To quickly find server-side validation implementations, search for these terms:
#
# "SERVER-SIDE VALIDATION:" - Marks all validation implementation points
# "validate_login_credentials" - Login form validation (line ~510)
# "validate_signup_" - Signup form validations (line ~680)
# "validate_otp_input" - OTP verification validation (line ~890, ~1300)
# "validate_face_" - Facial recognition validations (line ~1040, ~1110)
# "validate_security_question_" - Security questions validation (security_questions.py)
# "validate_session_data" - Session integrity validation (multiple locations)
# "sanitize_input" - Input sanitization (throughout application)
#
# All validation functions are implemented in validation.py with comprehensive documentation.
# Each validation returns (is_valid: bool, error_message: str) for consistent error handling.
# ================================================================================================


from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import HiddenField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from event_images import store_event_image, resize_image, get_event_image_base64,get_event_image 
from io import BytesIO

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Allow insecure transport for OAuth (not recommended for production)


load_dotenv()  # Load environment variables from .env file

# ================================================================================================
# SERVER-SIDE VALIDATION IMPLEMENTATION SUMMARY
# ================================================================================================
# This application implements comprehensive server-side validation for all authentication 
# features to ensure security and data integrity. Each validation point is clearly marked
# with "SERVER-SIDE VALIDATION:" comments for easy identification.
#
# VALIDATION COVERAGE:
# 
# 1. LOGIN VALIDATION (/login route):
#    - Email/username format validation (validate_login_credentials)
#    - Input sanitization (sanitize_input) 
#    - User existence and account status validation (validate_user_exists_and_active)
#    - Role-based access control (validate_user_role in role_required decorator)
#
# 2. SIGNUP VALIDATION (/signup route):
#    - Username format and uniqueness validation (validate_signup_username)
#    - Email format and uniqueness validation (validate_signup_email)
#    - Password complexity validation (validate_signup_password)
#    - Date of birth validation (validate_date_of_birth_server)
#    - Location selection validation (validate_location_selection)
#    - Database uniqueness checks for username and email
#
# 3. OTP VALIDATION (/verify_otp, /login_verify_otp routes):
#    - OTP format validation (validate_otp_input)
#    - Session data integrity validation (validate_session_data)
#    - Input sanitization for OTP codes
#
# 4. FACIAL RECOGNITION VALIDATION (/capture_face, /login_verify_face routes):
#    - Image data format validation (validate_face_image_data)
#    - Face detection validation (validate_face_detection_result)
#    - Image size and quality validation
#    - Session validation for face capture flows
#
# 5. SECURITY QUESTIONS VALIDATION (security_questions.py):
#    - Answer format validation (validate_security_question_answers)
#    - Answer verification validation (validate_security_question_verification)
#    - Input sanitization for security question answers
#
# 6. SESSION VALIDATION (throughout application):
#    - Session expiry validation (is_signup_session_valid, is_login_session_valid)
#    - Required session field validation (validate_session_data)
#    - Session security validation
#
# All validation functions are centralized in validation.py for maintainability and reusability.
# Each validation function returns a tuple of (is_valid, error_message) for consistent handling.
# ================================================================================================

# --- Database config (replace with your actual config or import from config file) ---
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = int(os.environ.get('DB_PORT', 3306))

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key')
app.permanent_session_lifetime = timedelta(minutes=30)  # Use a secure secret key in production
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
if not OPENAI_API_KEY:
    print("WARNING: OPENAI_API_KEY environment variable is not set. Chatbot may not function.")

api_key = os.getenv('OPEN_CAGE_API_KEY')
geocoder = OpenCageGeocode(api_key)
# Set session lifetime to 5 minutes for all permanent sessions


@app.errorhandler(404)
def page_not_found(e):
    # Log the not found error for debugging
    app.logger.warning(f"404 Not Found: {request.path}")
    # Render the custom 404.html page and set the status code to 404
    return render_template('error404.html'), 404

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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
@app.route('/ping')
def ping():
    session['last_active'] = str(datetime.utcnow())
    return '', 204
@app.before_request
def enforce_admin_idle_timeout():
    session.modified = True  # Refresh session on request

    if session.get('role') == 'admin':
        from datetime import datetime, timedelta

        now = datetime.utcnow()
        last_active = session.get('last_active')

        if last_active:
            last_active = datetime.strptime(last_active, '%Y-%m-%d %H:%M:%S.%f')
            if now - last_active > timedelta(minutes=5):
                session.clear()
                flash("You've been logged out due to inactivity.", "warning")
                return redirect(url_for('login'))

        # Update the timestamp
        session['last_active'] = str(now)

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

        # Default to session values if not explicitly passed
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
        print("Audit log inserted successfully.")
    except Exception as e:
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

def create_temp_login_session(user_data, step='password_verified'):
    """
    Creates a temporary session for multi-step login authentication (e.g., for OTP or Face ID).
    This is NOT the final authenticated session.
    """
    session['temp_user_id'] = user_data.get('user_id')
    session['temp_user_role'] = user_data.get('role')
    session['temp_user_name'] = user_data.get('username')
    session['temp_user_email'] = user_data.get('email', '')
    session['login_step'] = step
    
    # Mark as a temporary session (this data will not persist after server restart)
    session.permanent = False
    print(f"DEBUG: Created temporary login session at step {step}")

def complete_login(user_id, username, role):
    """
    This is the FINAL step. Called ONLY AFTER ALL security verifications pass.
    It creates the secure, permanent authenticated session.
    """
    # Clear any temporary session data first
    clear_temp_login_session()
    
    # Now, set the final, secure session keys
    session['user_id'] = user_id
    session['username'] = username
    session['user_name'] = username  # Also set user_name for consistency
    session['role'] = role
    session['user_role'] = role  # Set both for compatibility
    
    # Mark the session as permanent to enable session timeout based on inactivity
    session.permanent = True
    print("DEBUG: Final, authenticated session created.")


def is_signup_session_valid():
    """
    SERVER-SIDE VALIDATION: Check if there's a valid active signup session
    
    Validates session expiry, required data, and security constraints.
    This prevents session hijacking and ensures data integrity.
    """
    if not session.get('signup_session_active'):
        return False
    
    # SERVER-SIDE VALIDATION: Check if session has expired
    expires = session.get('signup_session_expires')
    if expires and datetime.now().timestamp() > expires:
        clear_signup_session()
        return False
    
    # SERVER-SIDE VALIDATION: Check if required data exists
    if not session.get('pending_signup'):
        return False
    
    return True

def is_login_session_valid():
    """
    SERVER-SIDE VALIDATION: Check if there's a valid active login session
    
    Validates session expiry, required data, and security constraints.
    This prevents session hijacking and unauthorized access during multi-step authentication.
    """
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
            flash("Account created but facial recognition setup failed. You can still log in normally.", "warning")
        
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

def clear_temp_login_session():
    """Clear only the temporary, in-progress login session data."""
    keys = ['temp_user_id', 'temp_user_role', 'temp_user_name', 'temp_user_email',
            'login_step', 'login_otp_code', 'login_otp_email', 'face_failed_attempts']
    for key in keys:
        session.pop(key, None)
    print("DEBUG: Cleared temporary login session.")

def clear_login_session():
    """
    Clears only login-related session data, preserving signup session data.
    This prevents interference between login and signup flows.
    """
    # Clear only login-related keys, preserve signup data
    login_keys = [
        'user_id', 'username', 'role', 'user_role', 'user_name',
        'temp_user_id', 'temp_user_role', 'temp_user_name', 'temp_user_email',
        'login_step', 'login_otp_code', 'login_otp_email', 'face_failed_attempts',
        'login_session_active', 'login_session_expires', 'last_active'
    ]
    
    for key in login_keys:
        session.pop(key, None)
    
    print("DEBUG: Login session data cleared, signup data preserved.")

def clear_all_session_data():
    """
    Clears ALL session data. Use this for complete logout only.
    """
    session.clear()
    print("DEBUG: All session data cleared.")

def require_signup_session(f):
    """Decorator to require an active signup session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('pending_signup'):
            session.clear()
            flash("Invalid session. Please sign up again.", "error")
            return redirect(url_for('signup'))
        return f(*args, **kwargs)
    return decorated_function

def require_login_session(f):
    """Decorator to require an active login session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('temp_user_id'):
            session.clear()
            flash("Invalid session. Please log in again.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Role-Based Access Control (RBAC) Decorators ---
# A01:2021-Broken Access Control: Implement robust access control with decorators.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
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
    """
    SERVER-SIDE VALIDATION: Role-based access control decorator
    
    Validates user roles server-side to prevent unauthorized access to admin functions.
    This decorator provides an additional layer of security beyond client-side checks.
    """
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            # SERVER-SIDE VALIDATION: Validate user role against allowed roles
            role_valid, role_message = validate_user_role(g.role, allowed_roles)
            
            if not role_valid:
                flash("You do not have permission to access this page.", 'danger')
                app.logger.warning(f"Unauthorized access attempt by user {g.user} (role: {g.role}) to a {allowed_roles} page.")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- User Context Loading ---
@app.before_request
def load_logged_in_user():
    """
    Loads a user's context ONLY if they have a final, authenticated session.
    This runs on every request.
    """
    if 'user_id' in session:
        g.user = session.get('user_id')
        g.role = session.get('role')
        g.username = session.get('username')
    else:
        g.user = None
        g.role = None
        g.username = None

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

        # SERVER-SIDE VALIDATION: Validate login credentials format and security
        is_valid, validation_message = validate_login_credentials(email_or_username, password)
        if not is_valid:
            flash(validation_message, 'error')
            return render_template('login.html')

        # SERVER-SIDE VALIDATION: Sanitize inputs to prevent injection attacks
        email_or_username = sanitize_input(email_or_username, 255)
        
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
                WHERE (email = %s OR username = %s)
                AND is_deleted = 0
            """, (email_or_username, email_or_username))
            user = cursor.fetchone()

            # SERVER-SIDE VALIDATION: Validate user exists and account is active
            user_valid, user_message = validate_user_exists_and_active(user)
            if not user_valid:
                flash('Invalid credentials.', 'error')  # Generic message to prevent user enumeration
                return render_template('login.html')

            # A07:2021-Identification and Authentication Failures: Generic error message for login
            # This prevents user enumeration.
            if user and check_password_hash(user['password'], password):
                # Clear any existing sessions first
                clear_signup_session()
                clear_login_session()
                
                # Create login session
                create_temp_login_session(user)

                app.logger.info(f"Password verification successful for user {user['username']} ({user['role']}).")

                 # Log successful login
                log_audit_action(
                    action='Login',
                    details=f"Password verified for user {user['email']} with role {user['role']}",
                    user_id=user['user_id'],
                    target_table='Users',
                    target_id=user['user_id'],
                    status='Success',
                    role=user['role'],
                )

                # ✅ [New] Enable session timeout handling
                session.permanent = True  # Flask will manage session lifetime
                if user['role'] == 'admin':
                    from datetime import datetime
                    session['last_active'] = str(datetime.utcnow())  # Store current time for idle tracking


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
                        session['login_step'] = 'security_questions_required'
                        flash("Please set up your security questions to complete login.", "info")
                        return redirect(url_for('security_questions'))
                    else:
                        # User has security questions - must verify them to complete login
                        session['login_step'] = 'security_questions_required'
                        flash("Please verify your security questions to complete login.", "info")
                        return redirect(url_for('security_questions'))
            else:
                flash('Invalid credentials.', 'error')

                # Log failed login attempt
                log_audit_action(
                    action='Login',
                    details=f"Invalid credentials for email/username: {email_or_username}",
                    user_id=None,
                    target_table=None,
                    target_id=None,
                    role=user['role'],
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
        
        # SERVER-SIDE VALIDATION: Sanitize all inputs to prevent injection attacks
        email = sanitize_input(email, 255)
        username = sanitize_input(username, 50)
        dob = sanitize_input(dob, 20)
        location_id = sanitize_input(location_id, 10)
        
        # SERVER-SIDE VALIDATION: Comprehensive input validation
        validation_errors = []
        
        # SERVER-SIDE VALIDATION: Username validation
        username_valid, username_msg = validate_signup_username(username)
        if not username_valid:
            validation_errors.append(username_msg)
        
        # SERVER-SIDE VALIDATION: Email validation (optional field)
        email_valid, email_msg = validate_signup_email(email)
        if not email_valid:
            validation_errors.append(email_msg)
        
        # SERVER-SIDE VALIDATION: Password validation
        password_valid, password_msg = validate_signup_password(password, confirm_password)
        if not password_valid:
            validation_errors.append(password_msg)
        
        # SERVER-SIDE VALIDATION: Date of birth validation
        dob_valid, dob_msg = validate_date_of_birth_server(dob)
        if not dob_valid:
            validation_errors.append(dob_msg)
        
        # SERVER-SIDE VALIDATION: Location selection validation
        location_valid, location_msg = validate_location_selection(location_id, locations)
        if not location_valid:
            validation_errors.append(location_msg)
        
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
            # SERVER-SIDE VALIDATION: Check username uniqueness in database
            cursor.execute("SELECT username FROM Users WHERE username = %s", (username,))
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

            # SERVER-SIDE VALIDATION: Check email uniqueness if provided
            if email:
                cursor.execute("SELECT email FROM Users WHERE email = %s", (email,))
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

            if email:
                otp = generate_otp()
                print(f"DEBUG: Generated signup OTP: '{otp}' (type: {type(otp)})")
                print(f"DEBUG: Generated signup OTP: '{otp}' (type: {type(otp)})")
                
                # Store signup data safely before clearing login session
                signup_data = session.get('pending_signup')
                if not signup_data:
                    flash("Session error. Please try signing up again.", "error")
                    return render_template('signup.html', 
                                         locations=locations,
                                         prefill_email=email,
                                         prefill_username=username,
                                         prefill_dob=dob,
                                         max_date=date.today().isoformat())
                
                # Clear any leftover login session data to avoid confusion
                clear_login_session()
                
                # Create secure signup session
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
                signup_data = session.get('pending_signup')
                if not signup_data:
                    flash("Session error. Please try signing up again.", "error")
                    return render_template('signup.html', 
                                         locations=locations,
                                         prefill_email=email,
                                         prefill_username=username,
                                         prefill_dob=dob,
                                         max_date=date.today().isoformat())
                
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
        
        # SERVER-SIDE VALIDATION: Sanitize OTP input
        entered_otp = sanitize_input(entered_otp, 10)
        
        # SERVER-SIDE VALIDATION: Validate OTP format and correctness
        session_otp = str(session.get('otp_code', ''))
        otp_valid, otp_message = validate_otp_input(entered_otp, session_otp)
        
        if not otp_valid:
            flash(otp_message, "error")
            return render_template('verify_otp.html')

        # Debug logging
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
    email = signup_data.get('email', '')
    dob = signup_data['dob']
    location_id = signup_data['location_id']
    is_volunteer = signup_data['is_volunteer']
    hashed_password = generate_password_hash(password)
    role = 'volunteer' if is_volunteer else 'elderly'
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
            
            # SERVER-SIDE VALIDATION: Validate face image data
            image_valid, image_message, opencv_image = validate_face_image_data(image_data)
            
            if not image_valid:
                flash(image_message, "error")
                return render_template('capture_face.html')
            
            # SERVER-SIDE VALIDATION: Validate face detection in image
            face_valid, face_message = validate_face_detection_result(opencv_image)
            
            if not face_valid:
                flash(face_message, "error")
                return render_template('capture_face.html')
            
            # Process the face image immediately without storing in session
            flash("Face captured and validated successfully!", "success")
            
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
    app.logger.info(f"login_verify_face called with method: {request.method}")
    app.logger.info(f"Session data: temp_user_id={session.get('temp_user_id')}, temp_user_role={session.get('temp_user_role')}, login_step={session.get('login_step')}")
    
    if request.method == 'POST':
        try:
            app.logger.info("Starting facial recognition POST processing")
            image_data = request.form.get('image_data')
            app.logger.info(f"Image data received: {bool(image_data)}, length: {len(image_data) if image_data else 0}")
            
            # SERVER-SIDE VALIDATION: Validate face image data for login
            image_valid, image_message, opencv_image = validate_face_image_data(image_data)
            app.logger.info(f"Image validation result: valid={image_valid}, message={image_message}")
            
            if not image_valid:
                app.logger.warning(f"Image validation failed: {image_message}")
                flash(image_message, "error")
                return render_template('login_verify_face.html')
            

            # SERVER-SIDE VALIDATION: Validate face detection in login image
            face_valid, face_message = validate_face_detection_result(opencv_image)
            app.logger.info(f"Face detection result: valid={face_valid}, message={face_message}")

            
            if not face_valid:
                app.logger.warning(f"Face detection failed: {face_message}")
                flash(face_message, "error")
                return render_template('login_verify_face.html')
            

            # SERVER-SIDE VALIDATION: Validate login session data
            required_session_fields = ['temp_user_id', 'login_step']
            session_valid, session_message = validate_session_data(session, required_session_fields)
            app.logger.info(f"Session validation result: valid={session_valid}, message={session_message}")
            
            if not session_valid:
                app.logger.warning(f"Session validation failed: {session_message}")
                flash("Login session expired. Please login again.", "error")
                session.clear() 
                return redirect(url_for('login'))
            

            # Get user ID from login session
            user_id = session.get('temp_user_id')
            app.logger.info(f"Retrieved user_id from session: {user_id}")
            
            # Verify the face against stored image
            app.logger.info(f"Starting face verification for user_id: {user_id}")
            success, message = verify_user_face(user_id, opencv_image)
            app.logger.info(f"Face verification result: success={success}, message='{message}'")
            
            # Log the similarity information that should be in the message
            if "similarity" in message.lower():
                app.logger.info(f"FACE SIMILARITY DETAILS: {message}")
            
            if success:
                app.logger.info("Face verification SUCCESSFUL - proceeding to complete login")
                user_role = session.get('temp_user_role')
                user_name = session.get('temp_user_name')
                user_email = session.get('temp_user_email', '')
                
                app.logger.info(f"User details for login completion: role={user_role}, name={user_name}, email={user_email}")
                
                clear_temp_login_session()
                complete_login(user_id, user_name, user_role)

                log_audit_action(
                    action='Login',
                    details=f'Facial recognition verified for user {user_email} with role {user_role}',
                    user_id=user_id,
                    status='Success'
                )
                
                flash("Login successful! Face verification completed.", "success")
                
                # Redirect based on role
                app.logger.info(f"Redirecting user with role '{user_role}' to appropriate dashboard")
                if user_role == 'admin':
                    app.logger.info("Redirecting to admin_dashboard")
                    return redirect(url_for('admin_dashboard'))
                elif user_role == 'volunteer':
                    app.logger.info("Redirecting to volunteer_dashboard")
                    return redirect(url_for('volunteer_dashboard'))
                elif user_role == 'elderly':
                    app.logger.info("Redirecting to home page")
                    return redirect(url_for('home'))
                else:
                    app.logger.info("Redirecting to home page (default fallback)")
                    return redirect(url_for('home'))  # Default fallback
            else:
                failed_attempts = session.get('face_failed_attempts', 0) + 1
                session['face_failed_attempts'] = failed_attempts
                
                app.logger.info(f"Face verification failed: {message}. Attempt {failed_attempts}/3")
                
                log_audit_action(
                    action='Login',
                    details=f'Facial recognition failed for user {session.get("temp_user_email", "")} with role {session.get("temp_user_role")}: {message} (Attempt {failed_attempts}/3)',
                    user_id=user_id,
                    status='Failed'
                )
                
                if failed_attempts >= 3:
                    app.logger.info(f"Max face verification attempts reached. Checking fallback options.")
                    
                    user_email = session.get('temp_user_email')
                    app.logger.info(f"User email for fallback: {user_email}")
                    
                    if user_email and user_email.strip() and user_email.strip().lower() != 'null':
                        app.logger.info("Redirecting to email OTP verification")
                        return redirect(url_for('face_fallback_email'))
                    else:
                        app.logger.info("Redirecting to security questions verification")
                        return redirect(url_for('face_fallback_security'))
                else:
                    flash("Face verification failed.", "error")
                
                return render_template('login_verify_face.html')
                
        except Exception as e:
            app.logger.error(f"Error during face verification: {e}")
            flash("Error processing face verification. Please try again.", "error")
            return render_template('login_verify_face.html')

    return render_template('login_verify_face.html')


@app.route('/face_fallback_email', methods=['GET', 'POST'])
@require_login_session
def face_fallback_email():
    """Fallback to email OTP when face verification fails"""
    user_email = session.get('temp_user_email') or ''
    user_email = user_email.strip() if user_email else ''
    has_email = user_email and user_email != 'null' and len(user_email.strip()) > 0
    
    if not has_email:
        flash("Email authentication is not available for your account.", "error")
        return redirect(url_for('login_verify_face'))
    
    try:
        # Generate and send OTP
        otp = generate_otp()
        session['login_otp_code'] = otp
        session['login_otp_email'] = user_email
        session['login_step'] = 'otp_required'
        
        send_otp_email(user_email, otp)
        flash("Verification code sent to your email.", "info")
        return redirect(url_for('login_verify_otp'))
        
    except Exception as e:
        app.logger.error(f"Failed to send login OTP to {user_email}: {e}")
        flash("Failed to send verification code. Please try again.", "error")
        return redirect(url_for('login_verify_face'))

@app.route('/face_fallback_security', methods=['GET', 'POST'])
@require_login_session
def face_fallback_security():
    """Fallback to security questions when face verification fails"""
    app.logger.info("face_fallback_security route called")
    print("DEBUG: face_fallback_security route called")
    session['login_step'] = 'security_questions_required'
    flash("Please verify your security questions to complete login.", "info")
    app.logger.info("Redirecting to security_questions route")
    print("DEBUG: Redirecting to security_questions route")
    return redirect(url_for('security_questions'))

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
        
        # SERVER-SIDE VALIDATION: Sanitize and validate OTP input
        entered_otp = sanitize_input(entered_otp, 10)
        
        # SERVER-SIDE VALIDATION: Validate OTP format and correctness for login
        session_otp = str(session.get('login_otp_code', ''))
        otp_valid, otp_message = validate_otp_input(entered_otp, session_otp)
        
        if not otp_valid:
            flash(otp_message, "error")
            return render_template('verify_otp.html')

        if entered_otp == session.get('login_otp_code'):
            # OTP verified - complete login
            temp_user_id = session.get('temp_user_id')
            temp_user_role = session.get('temp_user_role')
            temp_user_name = session.get('temp_user_name')
            
            # SERVER-SIDE VALIDATION: Validate session data before completing login
            required_fields = ['temp_user_id', 'temp_user_role', 'temp_user_name']
            session_valid, session_message = validate_session_data(session, required_fields)
            
            if not session_valid:
                flash("Login session is invalid. Please login again.", "error")
                clear_login_session()
                return redirect(url_for('login'))
            
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
# security_questions.py or your main app file

@app.route('/security_questions', methods=['GET', 'POST'])
def security_questions():
    """Security questions route with correct session protection."""
    # Check for valid session - either signup process, login fallback, or direct login redirect
    has_signup_session = session.get('pending_signup')
    has_login_fallback_session = session.get('temp_user_id') and session.get('login_step') == 'security_questions_required'
    has_direct_login_session = session.get('temp_user_id') and session.get('login_step') in ['password_verified', 'security_questions_required']
    
    if not has_signup_session and not has_login_fallback_session and not has_direct_login_session:
        app.logger.warning(f"Invalid session in security_questions: pending_signup={session.get('pending_signup')}, temp_user_id={session.get('temp_user_id')}, login_step={session.get('login_step')}")
        session.clear()
        flash("Invalid session. Please start over.", "error")
        return redirect(url_for('login'))
    
    # Update login step to security_questions_required if coming from direct login
    if session.get('temp_user_id') and session.get('login_step') == 'password_verified':
        session['login_step'] = 'security_questions_required'
        app.logger.info("Updated login_step from 'password_verified' to 'security_questions_required'")
    
    # Assuming you have a `security_questions_route()` function from another module
    # as mentioned in your code.
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
    return render_template('admin.html',username=g.username)  # ✅ load the actual template

@app.route('/delete_account', methods=['POST'])
@role_required(['admin'])
def delete_account():
    uuid_to_delete = request.form.get('uuid', '').strip()
    admin_password_input = request.form.get('admin_password', '').strip()
    
    if not uuid_to_delete or not admin_password_input:
        flash('Deletion Unsuccessful', 'warning')
        return redirect(url_for('account_management'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current admin hashed password from DB
        cursor.execute("SELECT password FROM Users WHERE user_id = %s", (g.user,))
        admin_user = cursor.fetchone()

        if not admin_user or not check_password_hash(admin_user['password'], admin_password_input):
            flash('Invalid Credential', 'danger')
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Delete_Account',
                status='Failed',
                details="Incorrect password for deletion attempt",
                target_table='Users',
                target_id=None
            )
            return redirect(url_for('account_management'))

        # Fetch the target user to ensure they exist and prevent self-deletion
        cursor.execute("SELECT email FROM Users WHERE uuid = %s", (uuid_to_delete,))
        user_record = cursor.fetchone()

        if not user_record:
            flash('User not found.', 'warning')
            return redirect(url_for('account_management'))

        if user_record['email'] == g.username:
            flash('You cannot delete your own admin account!', 'danger')
            return redirect(url_for('account_management'))

        # Soft delete by setting is_deleted = 1
        cursor.execute("UPDATE Users SET is_deleted = 1 WHERE uuid = %s", (uuid_to_delete,))
        conn.commit()


        if cursor.rowcount > 0:
            flash('Account deleted successfully.', 'success')
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Delete_Account',
                status='Success',
                details=f"Deleted account with UUID {uuid_to_delete}",
                target_table='Users',
                target_id=None
            )
        else:
            flash('Account not found or already deleted.', 'warning')

    except Exception as e:
        if conn:
            conn.rollback()
        flash('Error deleting account. Please try again.', 'danger')
        app.logger.error(f"Error deleting account UUID {uuid_to_delete}: {e}")
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
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('account_management'))
@app.route('/admin/accounts')
def account_management():
    if g.role != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = get_db_cursor(conn)

    # Fetch users by role with needed fields
    cursor.execute("SELECT uuid, email, username, created_at, role FROM Users WHERE role = 'volunteer' AND is_deleted = 0")
    volunteers = cursor.fetchall()

    cursor.execute("SELECT uuid, email, username, created_at, role FROM Users WHERE role = 'elderly' AND is_deleted = 0")
    elderly = cursor.fetchall()

    cursor.execute("SELECT uuid, email, username, created_at, role FROM Users WHERE role = 'admin' AND is_deleted = 0")
    admins = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('acc_management.html', volunteers=volunteers, elderly=elderly, admins=admins)

def sanitize_username(username):
    return re.sub(r'[^\w\.\-]', '', username)

def normalize_email(email):
    return email.strip().lower()

def validate_dob(dob_str):
    if not dob_str:
        return None
    try:
        dob_date = datetime.strptime(dob_str, '%Y-%m-%d').date()
    except ValueError:
        return False

    if dob_date > date.today() or dob_date < date(1900, 1, 1):
        return False

    return dob_date
@app.route('/admin/accounts/<uuid_param>', methods=['GET', 'POST'])
@role_required(['admin'])
def account_details(uuid_param):
    conn = None
    cursor = None
    user = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            # Get raw inputs
            raw_username = request.form.get('username', '')
            raw_email = request.form.get('email', '')
            dob_str = request.form.get('dob', '').strip()
            updated_role = request.form.get('role', '').strip()

            # Sanitize and normalize inputs
            username = sanitize_username(raw_username)
            updated_email = normalize_email(raw_email)
            dob = validate_dob(dob_str)

            # Get location_id from form, convert to int or None if empty
            location_id_raw = request.form.get('location_id')
            if location_id_raw in (None, '', 'None'):
                location_id = None
            else:
                try:
                    location_id = int(location_id_raw)
                except ValueError:
                    location_id = None

            # Validate required fields
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
                return redirect(url_for('account_details', uuid_param=uuid_param))

            # Validate role value
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
                return redirect(url_for('account_details', uuid_param=uuid_param))

            # Validate email format
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
                return redirect(url_for('account_details', uuid_param=uuid_param))

            # Validate DOB
            if dob is False:
                log_audit_action(
                    user_id=g.user,
                    email=g.username,
                    role=g.role,
                    action='Update_Account',
                    status='Failed',
                    details=f"Validation failed: invalid DOB {dob_str}",
                    target_table='Users',
                    target_id=None
                )
                flash("Invalid date of birth. Please enter a valid date (YYYY-MM-DD).", "danger")
                return redirect(url_for('acc_management', uuid_param=uuid_param))

            # Check if the new email already exists for another user (excluding current user)
            cursor.execute("SELECT uuid FROM Users WHERE email = %s AND uuid != %s", (updated_email, uuid_param))
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
                return redirect(url_for('account_details', uuid_param=uuid_param))

            # Update user info by uuid
            cursor.execute('''
                UPDATE Users
                SET username = %s, role = %s, email = %s, DOB = %s, location_id = %s
                WHERE uuid = %s
            ''', (username, updated_role, updated_email, dob if dob else None, location_id, uuid_param))
            conn.commit()

            # Log success audit
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Update_Account',
                status='Success',
                details=f"Updated user with UUID {uuid_param} to email {updated_email} and role {updated_role}",
                target_table='Users',
                target_id=None
            )

            app.logger.info(f"Admin {g.username} updated user with UUID {uuid_param} to {updated_email} (role: {updated_role}).")
            flash('User details updated successfully!', 'success')
            return redirect(url_for('account_management'))
        
        max_date = date.today().strftime('%Y-%m-%d')

        # GET request - fetch user by uuid to prefill form
        cursor.execute("SELECT * FROM Users WHERE uuid = %s AND is_deleted = 0", (uuid_param,))
        user = cursor.fetchone()

        # Fetch all locations for dropdown
        locations = get_community_centers()

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
                app.logger.warning(f"DOB formatting error for user UUID {uuid_param}: {e}")
                user['DOB'] = ''

            return render_template('acc_details.html', user=user, locations=locations, max_date=max_date)

        else:
            flash('User not found.', 'warning')
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
        app.logger.error(f"Error in account_details for UUID {uuid_param}: {e}")
        flash('Failed to process user details.', 'danger')
        if conn:
            conn.rollback()
        return redirect(url_for('account_management'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

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

        cursor.execute("SELECT event_id, Title, description, event_date, Time, location_name, category, image FROM Events WHERE event_id = %s", (event_id,))
        event = cursor.fetchone()

        if not event:
            flash(f"No event found with ID {event_id}.", 'error')
            return redirect(url_for('usereventpage'))

        # A03:2021-Injection: Parameterized queries for signup and volunteer checks
        cursor.execute("SELECT COUNT(*) FROM Event_detail WHERE event_id = %s AND user_id = %s", (event_id, current_user_id,))
        if cursor.fetchone()['COUNT(*)'] > 0:
            has_signed_up = True

        # Volunteer logic now allows 'user' role (all guests) to volunteer, or 'volunteer' role
        if current_user_role in ['volunteer', 'elderly']: # assuming elderly can also volunteer now based on prev logic
            check_volunteer_query = "SELECT COUNT(*) FROM Event_detail WHERE event_id = %s AND user_id = %s"
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
    signup_type = g.role
    assigned_at = datetime.now()
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

        check_signup_query = "SELECT COUNT(*) FROM Event_detail WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_signup_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash(f"You have already signed up for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO Event_detail (event_id, user_id, username, signup_type, assigned_at) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id, current_username, signup_type, assigned_at))
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

        delete_query = "DELETE FROM Event_detail WHERE event_id = %s AND user_id = %s"
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
    signup_type = g.role
    assigned_at = datetime.now()

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
        check_query = "SELECT COUNT(*) FROM Event_detail WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash("You have already volunteered for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO Event_detail (event_id, user_id, signup_type, assigned_at) VALUES (%s, %s, %s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id, signup_type, assigned_at))
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
    signup_type = g.role
    assigned_at = datetime.now()

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

        delete_query = "DELETE FROM Event_detail WHERE event_id = %s AND user_id = %s"
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
            start_dt = datetime.combine(datetime.min.date(), start_dt_time)
            end_dt_time = (start_dt + timedelta(hours=1)).time()

        return start_dt_time, end_dt_time

    except Exception as e:
        # Using print for now as app.logger might not be fully set up in this snippet
        print(f"Warning: Could not parse time string '{time_str}'. Error: {e}")
        return time(0, 0), time(23, 59) # Default to full day if parsing fails


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

        # A03:2021-Injection: Parameterized UNION query
        query = """
            SELECT ed.username AS signup_username, e.event_id AS EventID, e.description AS EventDescription, e.event_date AS Date, e.Time, e.location_name AS Venue
            FROM Event_detail ed
            JOIN Events e ON ed.event_id = e.event_id
            WHERE ed.user_id = %s
            ORDER BY Date, Time
        """
        cursor.execute(query, (current_user_id,))

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
# -----------------------------------------------------------------------------

@app.route('/calendar')
@login_required # --- CORRECTED: Added back the login_required decorator ---
def calendar():
    """
    Renders the calendar page, displaying the FullCalendar.js widget and
    a list of ALL signed-up events on the left sidebar (no date filter).
    """
    current_user_id = g.user
    current_username = g.username

    if not current_user_id:
        flash("You need to be logged in to view your calendar.", 'info')
        return redirect(url_for('login'))

    db_connection = None
    cursor = None
    signed_up_events = []

    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True) # Ensure dictionary cursor

        # Query to get events the user has signed up for, for the sidebar list
        query = """
        SELECT
            e.event_id,
            e.Title,
            e.description,
            e.event_date,
            e.Time,
            e.location_name,
            ed.username AS signup_username,
            ed.signup_type
        FROM Event_detail ed
        JOIN Events e ON ed.event_id = e.event_id
        WHERE ed.user_id = %s
        ORDER BY e.event_date, e.Time;
        """
        cursor.execute(query, (current_user_id,)) # Correct parameter count
        signed_up_events = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Database error fetching signed up events for calendar list for user {current_user_id}: {err}")
        flash(f"Error loading your events list: {err}", 'error')
    except Exception as e:
        print(f"An unexpected error occurred in calendar route for user {current_user_id}: {e}")
        flash(f"An unexpected error occurred while loading your events list: {e}", 'error')
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('calendar.html', signed_up_events=signed_up_events, user_id=current_user_id, username=current_username)



@app.route('/chat')
@login_required  # if you use login_required decorator
def chat():
    is_admin = (g.role == 'admin')
    return render_template('chat.html', openai_api_key=OPENAI_API_KEY, is_admin=is_admin)


@app.route('/get_chat_sessions', methods=['GET'])
@login_required
def get_chat_sessions():
    """
    Fetches all chat sessions for the current user from the database.
    Returns session_id, name, pinned status, and last_message_timestamp.
    """
    user_id = g.user # Get user_id from the global g object (set by @app.before_request)
    if not user_id:
        # This should ideally be caught by @login_required, but added as a safeguard
        return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 401

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        # Select all relevant session metadata for the current user
        # Order by pinned status (pinned first) then by last message timestamp (most recent first)
        query = """
        SELECT session_id, name, pinned, created_at, last_message_timestamp
        FROM ChatSessions
        WHERE user_id = %s
        ORDER BY pinned DESC, last_message_timestamp DESC, created_at DESC
        """
        cursor.execute(query, (user_id,))
        sessions = cursor.fetchall()

        # Convert datetime objects to ISO format strings for JSON serialization
        for session in sessions:
            if session['created_at']:
                session['created_at'] = session['created_at'].isoformat()
            if session['last_message_timestamp']:
                session['last_message_timestamp'] = session['last_message_timestamp'].isoformat()

        return jsonify({'status': 'success', 'sessions': sessions})

    except mysql.connector.Error as err:
        app.logger.error(f"Database error fetching chat sessions for user {user_id}: {err}")
        return jsonify({'status': 'error', 'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error fetching chat sessions for user {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/create_new_chat_session', methods=['POST'])
@login_required
def create_new_chat_session():
    """
    Creates a new chat session record in the database for the current user.
    Returns the new session_id.
    """
    user_id = g.user
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 401

    new_session_id = str(uuid.uuid4()) # Generate a unique UUID for the session

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor() # Use a non-dictionary cursor for INSERT

        insert_query = """
        INSERT INTO ChatSessions (session_id, user_id, name, created_at, last_message_timestamp)
        VALUES (%s, %s, %s, %s, %s)
        """
        current_time = datetime.now()
        cursor.execute(insert_query, (new_session_id, user_id, "New Chat", current_time, current_time))
        conn.commit()

        return jsonify({'status': 'success', 'session_id': new_session_id, 'message': 'New chat session created.'})

    except mysql.connector.Error as err:
        app.logger.error(f"Database error creating new chat session for user {user_id}: {err}")
        if conn: conn.rollback()
        return jsonify({'status': 'error', 'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error creating new chat session for user {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/get_chat_history/<string:session_id>', methods=['GET'])
@login_required
def get_chat_history(session_id):
    """
    Fetches all messages for a specific chat session and user from the database.
    """
    user_id = g.user
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 401

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        # Select messages for the given session and user, ordered by timestamp
        query = """
        SELECT sender, message_text, timestamp
        FROM ChatMessages
        WHERE session_id = %s AND user_id = %s
        ORDER BY timestamp ASC
        """
        cursor.execute(query, (session_id, user_id))
        messages = cursor.fetchall()

        # Convert datetime objects to ISO format strings for JSON serialization
        for msg in messages:
            if msg['timestamp']:
                msg['timestamp'] = msg['timestamp'].isoformat()

        return jsonify({'status': 'success', 'messages': messages})

    except mysql.connector.Error as err:
        app.logger.error(f"Database error fetching chat history for session {session_id}, user {user_id}: {err}")
        return jsonify({'status': 'error', 'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error fetching chat history for session {session_id}, user {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/send_chat_message', methods=['POST'])
@login_required
def send_chat_message():
    """
    Receives a new chat message from the frontend and saves it to the database.
    Also updates the last_message_timestamp for the associated session.
    """
    user_id = g.user
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 401

    data = request.get_json()
    session_id = data.get('chat_session_id')
    sender = data.get('sender') # 'User' or 'AI'
    message_text = data.get('message')

    if not session_id or not sender or not message_text:
        return jsonify({'status': 'error', 'message': 'Missing chat_session_id, sender, or message.'}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert the new message into ChatMessages
        insert_message_query = """
        INSERT INTO ChatMessages (session_id, user_id, sender, message_text, timestamp)
        VALUES (%s, %s, %s, %s, %s)
        """
        current_time = datetime.now()
        cursor.execute(insert_message_query, (session_id, user_id, sender, message_text, current_time))

        # Update the last_message_timestamp for the chat session
        update_session_query = """
        UPDATE ChatSessions
        SET last_message_timestamp = %s
        WHERE session_id = %s AND user_id = %s
        """
        cursor.execute(update_session_query, (current_time, session_id, user_id))

        conn.commit()
        return jsonify({'status': 'success', 'message': 'Message saved successfully.'})

    except mysql.connector.Error as err:
        app.logger.error(f"Database error saving chat message for session {session_id}, user {user_id}: {err}")
        if conn: conn.rollback()
        return jsonify({'status': 'error', 'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error saving chat message for session {session_id}, user {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/update_chat_session_metadata', methods=['POST'])
@login_required
def update_chat_session_metadata():
    """
    Updates the name or pinned status of a chat session.
    """
    user_id = g.user
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 401

    data = request.get_json()
    session_id = data.get('chat_session_id')
    new_name = data.get('name')
    new_pinned_status = data.get('pinned')

    if not session_id:
        return jsonify({'status': 'error', 'message': 'Missing chat_session_id.'}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        update_fields = []
        update_values = []

        if new_name is not None:
            update_fields.append("name = %s")
            update_values.append(new_name)
        if new_pinned_status is not None:
            update_fields.append("pinned = %s")
            update_values.append(new_pinned_status)

        if not update_fields:
            return jsonify({'status': 'error', 'message': 'No fields to update.'}), 400

        query = f"""
        UPDATE ChatSessions
        SET {', '.join(update_fields)}
        WHERE session_id = %s AND user_id = %s
        """
        update_values.extend([session_id, user_id])

        cursor.execute(query, tuple(update_values))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'status': 'error', 'message': 'Chat session not found or not authorized.'}), 404

        return jsonify({'status': 'success', 'message': 'Chat session metadata updated.'})

    except mysql.connector.Error as err:
        app.logger.error(f"Database error updating chat session metadata for session {session_id}, user {user_id}: {err}")
        if conn: conn.rollback()
        return jsonify({'status': 'error', 'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error updating chat session metadata for session {session_id}, user {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/delete_chat_session', methods=['POST'])
@login_required
def delete_chat_session():
    """
    Deletes a chat session and all its associated messages from the database.
    """
    user_id = g.user
    if not user_id:
        return jsonify({'status': 'error', 'message': 'User not authenticated.'}), 401

    data = request.get_json()
    session_id = data.get('chat_session_id')

    if not session_id:
        return jsonify({'status': 'error', 'message': 'Missing chat_session_id.'}), 400

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Due to ON DELETE CASCADE, deleting from ChatSessions will automatically
        # delete associated messages from ChatMessages.
        delete_query = "DELETE FROM ChatSessions WHERE session_id = %s AND user_id = %s"
        cursor.execute(delete_query, (session_id, user_id))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'status': 'error', 'message': 'Chat session not found or not authorized.'}), 404

        return jsonify({'status': 'success', 'message': 'Chat session and messages deleted.'})

    except mysql.connector.Error as err:
        app.logger.error(f"Database error deleting chat session {session_id}, user {user_id}: {err}")
        if conn: conn.rollback()
        return jsonify({'status': 'error', 'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error deleting chat session {session_id}, user {user_id}: {e}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()





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
               description, current_elderly, max_elderly,
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

    events_list = []
    for row in rows:
        # Retrieve image from BLOB and convert to base64 directly
        image_b64 = get_event_image_base64(row['id'])

        events_list.append({
            'id': row['id'],
            'title': row['title'],
            'event_date': row['event_date'].strftime('%Y-%m-%d') if row['event_date'] else '',
            'organisation': row['organisation'],
            'category': row['category'],
            'image': image_b64,
            'description': row['description'],
            'current_elderly': row['current_elderly'],
            'max_elderly': row['max_elderly'],
            'current_volunteers': row['current_volunteers'],
            'max_volunteers': row['max_volunteers'],
            'location_name': row['location_name'] or ""
        })

    return jsonify({
        "events": events_list,
        "page": page,
        "total_pages": total_pages
    })


@app.route('/get_event_image/<int:event_id>')
def get_event_image_route(event_id):
    """
    This route fetches the image BLOB from the database and serves it.
    """
    image_blob = get_event_image(event_id)
    if image_blob:
        return send_file(BytesIO(image_blob), mimetype='image/jpeg')
    else:
        # Return a blank or placeholder image if the event or image is not found
        return "Image not found", 404

@app.route('/admin/events')
def admin_events():
    if g.role != 'admin':
        flash('You are not authorized to access this page', 'danger')  # Debug flash message
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

    # Get location names
    cursor.execute("SELECT DISTINCT location_name FROM Events WHERE location_name IS NOT NULL AND location_name != '' ORDER BY location_name ASC")
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

    # For each event, retrieve the Base64 image
    events_with_image = []
    for event in events:
        image_b64 = get_event_image_base64(event['event_id'])  # Get image as Base64
        event['image'] = image_b64  # Add image to the event
        events_with_image.append(event)

    cursor.close()
    conn.close()

    return render_template(
        'admin_events.html',
        events=events_with_image,  # Pass events with image data to the template
        page=page,
        total_pages=total_pages,
        selected_categories=categories,
        selected_locations=locations,
        search_query=search,
        all_categories=all_categories,
        all_locations=all_locations
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_text(text, max_len=255):
    return re.sub(r'[<>"]', '', text.strip())[:max_len]

def validate_date(date_text):
    try:
        date_obj = datetime.strptime(date_text, '%Y-%m-%d')
        if date_obj.date() < datetime.today().date():
            return None
        return date_obj
    except ValueError:
        return None
    
@app.route('/admin/events/add', methods=['GET', 'POST'], endpoint='admin_add_event')
def admin_add_event():
    
    if g.role != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        # --- Sanitize and validate inputs ---
        title = sanitize_text(request.form['event_title'], max_len=100)
        organization = sanitize_text(request.form['organization'], max_len=100)
        description = sanitize_text(request.form['description'], max_len=1000)
        category = sanitize_text(request.form['category'], max_len=50)
        location_name = sanitize_text(request.form['location'], max_len=255)

        try:
            max_participants = int(request.form['participants'])
            max_volunteers = int(request.form['volunteers'])
            if max_participants < 1 or max_volunteers < 1:
                raise ValueError()
        except ValueError:
            flash("Participants and Volunteers must be valid positive integers.", "danger")
            return redirect(url_for('admin_add_event'))

        date_str = request.form['date']
        validated_date = validate_date(date_str)
        if not validated_date:
            flash("Invalid or past date entered.", "danger")
            return redirect(url_for('admin_add_event'))

        lat, lng = get_lat_lng_from_address(location_name)
        if lat is None or lng is None:
            flash('Invalid address. Please enter a valid location.', 'danger')
            return redirect(url_for('admin_add_event'))

        # --- Handle image upload ---
        picture = request.files.get('picture')
        if not picture or picture.filename == '':
            flash('Image upload failed or missing.', 'danger')
            return redirect(url_for('admin_add_event'))
        # Check if the file is allowed
        if not allowed_file(picture.filename):
            flash('Invalid file type. Allowed types: png, jpg, jpeg, gif.', 'danger')
            return redirect(url_for('admin_add_event'))

        # Check if the file size exceeds the limit (handled globally by MAX_CONTENT_LENGTH)
        if picture.content_length > app.config['MAX_CONTENT_LENGTH']:
            flash('File size exceeds 2MB limit.', 'danger')
            return redirect(url_for('admin_add_event'))
        
        # Read image into OpenCV
        file_bytes = np.frombuffer(picture.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        if img is None:
            flash('Invalid image uploaded.', 'danger')
            return redirect(url_for('admin_add_event'))

        # Optional: resize
        img = resize_image(img, 500, 500)

        # --- Insert event WITHOUT image first ---
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(""" 
                INSERT INTO Events (title, organisation, event_date, max_elderly,
                                    max_volunteers, latitude, longitude, location_name, 
                                    category, description, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                title, organization, validated_date.strftime('%Y-%m-%d'),
                max_participants, max_volunteers, lat, lng,
                location_name, category, description
            ))
            event_id = cursor.lastrowid
            conn.commit()

            # Store image as BLOB with MIME type
            success, msg = store_event_image(event_id, img)
            if not success:
                flash(f"Event added but image storage failed: {msg}", "warning")
            else:
                flash('Event added successfully!', 'success')

            cursor.close()
            conn.close()
            return redirect(url_for('admin_events'))

        except Exception as e:
            if conn:
                conn.rollback()
            flash(f"Failed to add event: {e}", "danger")
            return redirect(url_for('admin_add_event'))

    return render_template('add_events.html')

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

    # Convert event_date
    event_date = None
    if event['event_date']:
        try:
            event_date = datetime.strptime(str(event['event_date']), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                event_date = datetime.strptime(str(event['event_date']), '%Y-%m-%d')
            except ValueError:
                flash('Invalid date format for event.', 'danger')

    # Get volunteers and elderly
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

    # Get event image as base64
    image_src = get_event_image_base64(event_id)
    if not image_src:
        image_src = url_for('static', filename='images/default.png')  # Fallback image if none found

    cursor.close()
    conn.close()

    return render_template('event_details.html', event={
        'id': event['event_id'],
        'title': event['Title'],
        'description': event['description'],
        'date': event_date,
        'organisation': event['organisation'],
        'category': event['category'],
        'image': image_src,  # pass base64 string
        'location': event['location_name'],
        'max_elderly': event['max_elderly'],
        'max_volunteers': event['max_volunteers'],
        'current_elderly': event['current_elderly'],
        'current_volunteers': event['current_volunteers'],
        'volunteers': volunteers,
        'elderly': elderly
    })

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
            SELECT event_id, description, Title,
                   event_date, Time, location_name, category, image
            FROM Events
            ORDER BY event_date, Time
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

@app.route('/api/event/<int:event_id>/counts')
def get_event_counts(event_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Count volunteers
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN signup_type = 'volunteer' THEN 1 ELSE 0 END) AS volunteer_count,
                SUM(CASE WHEN signup_type = 'elderly' THEN 1 ELSE 0 END) AS elderly_count
            FROM Event_detail
            WHERE event_id = %s
        """, (event_id,))
        counts = cursor.fetchone()

        # Assuming you have max_volunteers and max_elderly stored somewhere,
        # for example in your Events table:
        cursor.execute("SELECT max_volunteers, max_elderly FROM Events WHERE event_id = %s", (event_id,))
        max_counts = cursor.fetchone()

        response = {
            "volunteers_count": counts['volunteer_count'] or 0,
            "max_volunteers": max_counts['max_volunteers'] or 0,
            "elderly_count": counts['elderly_count'] or 0,
            "max_elderly": max_counts['max_elderly'] or 0
        }

        return jsonify(response)

    except Exception as e:
        app.logger.error(f"Error fetching counts for event {event_id}: {e}")
        return jsonify({"error": "Failed to fetch counts"}), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

MAX_ATTEMPTS = 3
LOCK_DURATION = timedelta(minutes=5)  # block for 5 minutes after 3 fails

@app.route('/admin/event/<int:event_id>/delete', methods=['POST'])
def delete_event(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    email = request.form.get('admin_email')
    password = request.form.get('admin_password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get admin record
    cursor.execute("SELECT * FROM Users WHERE email = %s AND role = 'admin'", (email,))
    admin = cursor.fetchone()

    # Check if admin exists
    if not admin:
        flash("Admin not found.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('admin_event_details', event_id=event_id))

    user_id = admin['user_id']

    # Check failed attempts
    cursor.execute("SELECT * FROM Delete_Attempts WHERE user_id = %s", (user_id,))
    attempt = cursor.fetchone()

    now = datetime.now()
    if attempt and attempt['lock_until'] and now < attempt['lock_until']:
        flash(f"Too many failed attempts. Try again after {attempt['lock_until']}.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('admin_event_details', event_id=event_id))

    # Verify password
    if not check_password_hash(admin['password'], password):
        flash("Authentication failed. Please try again.", "danger")  # Only flash with 'danger' category
        # Update failed attempts
        if attempt:
            attempts = attempt['attempts'] + 1
        else:
            attempts = 1

        lock_until = now + LOCK_DURATION if attempts >= MAX_ATTEMPTS else None

        if attempt:
            cursor.execute(
                "UPDATE Delete_Attempts SET attempts=%s, last_attempt=%s, lock_until=%s WHERE user_id=%s",
                (attempts, now, lock_until, user_id)
            )
        else:
            cursor.execute(
                "INSERT INTO Delete_Attempts (user_id, attempts, last_attempt, lock_until) VALUES (%s, %s, %s, %s)",
                (user_id, attempts, now, lock_until)
            )
        conn.commit()

        log_audit_action(
            user_id=user_id,
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
        return redirect(url_for('admin_event_details', event_id=event_id))


    # Reset failed attempts on successful auth
    cursor.execute("DELETE FROM Delete_Attempts WHERE user_id=%s", (user_id,))
    conn.commit()

    # Get event title
    cursor.execute("SELECT title FROM Events WHERE event_id = %s", (event_id,))
    event = cursor.fetchone()
    if not event:
        flash("Event not found.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for('admin_events'))

    event_title = event['title']

    try:
        # Delete child rows first
        cursor.execute("DELETE FROM Event_detail WHERE event_id = %s", (event_id,))
        # Delete parent event
        cursor.execute("DELETE FROM Events WHERE event_id = %s", (event_id,))
        conn.commit()

        log_audit_action(
            user_id=user_id,
            email=email,
            role=admin['role'],
            action='Delete_Event',
            status='Success',
            details=f"Deleted event titled '{event_title}'",
            target_table='Events',
            target_id=event_id
        )

        flash(f'"{event_title}" was successfully deleted.', 'success')
        return redirect(url_for('admin_events'))

    except Exception as e:
        conn.rollback()
        flash(f"Error deleting event: {str(e)}", 'danger')
        return redirect(url_for('admin_event_details', event_id=event_id))

    finally:
        cursor.close()
        conn.close()

@app.route('/admin/event/<int:event_id>/update_image', methods=['POST'])
def update_event_image(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    file = request.files.get('new_image')
    if not file or file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('admin_event_details', event_id=event_id))

    if not allowed_file(file.filename):
        flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'danger')
        return redirect(url_for('admin_event_details', event_id=event_id))

    # Read image into OpenCV
    file_bytes = np.frombuffer(file.read(), np.uint8)
    img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
    if img is None:
        flash('Invalid image uploaded.', 'danger')
        return redirect(url_for('admin_event_details', event_id=event_id))

    # Store the new image as BLOB with MIME type
    success, msg = store_event_image(event_id, img)
    if not success:
        flash(f"Image update failed: {msg}", "danger")
    else:
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
    audit_logs = []  # changed variable name
    
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute(query, params)
        audit_logs = cursor.fetchall()

        # Convert timestamps to Singapore time
        for entry in audit_logs:
            if entry['timestamp']:
                utc_time = entry['timestamp'].replace(tzinfo=pytz.utc)
                sg_time = utc_time.astimezone(pytz.timezone('Asia/Singapore'))
                entry['timestamp'] = sg_time

    except Exception as e:
        flash(f"Error loading audit logs: {e}", "error")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    
    return render_template('audit.html', 
                           audit_logs=audit_logs,  # pass with same name
                           filter_date=filter_date,
                           filter_role=filter_role,
                           filter_action=filter_action)


@app.route("/report")
@role_required(['admin'])
def admin_report():
    """
    Admin-only report generation page.
    Shows total counts of users by role, other system metrics, 
    and event statistics per category.
    """
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Count users by role
        cursor.execute("""
            SELECT role, COUNT(*) as total
            FROM Users
            WHERE is_deleted = 0
            GROUP BY role
        """)
        role_counts = {row['role']: row['total'] for row in cursor.fetchall()}

        total_elderly = role_counts.get('elderly', 0)
        total_volunteers = role_counts.get('volunteer', 0)
        total_admins = role_counts.get('admin', 0)

        # Total registered users
        cursor.execute("""
            SELECT COUNT(*) AS total_users
            FROM Users
            WHERE is_deleted = 0
        """)
        total_users = cursor.fetchone()['total_users']

        # New users in the last 30 days
        cursor.execute("""
            SELECT COUNT(*) AS new_users_30d
            FROM Users
            WHERE is_deleted = 0
            AND created_at >= NOW() - INTERVAL 30 DAY
        """)
        new_users_30d = cursor.fetchone()['new_users_30d']

        # Get signups per category, separated by type
        cursor.execute("""
            SELECT e.category,
                SUM(CASE WHEN ed.signup_type='elderly' THEN 1 ELSE 0 END) AS elderly_count,
                SUM(CASE WHEN ed.signup_type='volunteer' THEN 1 ELSE 0 END) AS volunteer_count
            FROM Events e
            LEFT JOIN Event_detail ed ON e.event_id = ed.event_id
            GROUP BY e.category
        """)
        result = cursor.fetchall()

        event_categories = [row['category'] for row in result]
        elderly_signups = [row['elderly_count'] for row in result]
        volunteer_signups = [row['volunteer_count'] for row in result]

        # Count number of events per category (for donut chart)
        cursor.execute("""
            SELECT category, COUNT(*) AS event_count
            FROM Events
            GROUP BY category
        """)
        event_counts_rows = cursor.fetchall()
        event_counts = {row['category']: row['event_count'] for row in event_counts_rows}
        total_events = sum(event_counts.values())

        # Log the report view action
        log_audit_action(
            user_id=session.get('user_id'),
            email=session.get('email'),
            role=session.get('user_role'),
            action="view_report",
            status="success",
            details="Viewed admin report page",
            target_table="Users"
        )

        return render_template(
            "report.html",
            total_elderly=total_elderly,
            total_volunteers=total_volunteers,
            total_admins=total_admins,
            total_users=total_users,
            new_users_30d=new_users_30d,
            event_categories=event_categories,
            elderly_signups=elderly_signups,
            volunteer_signups=volunteer_signups,
            event_counts=event_counts,  # Pass to template for donut chart
            total_events=total_events
        )

    except Exception as e:
        app.logger.error(f"Error generating admin report: {e}")
        flash("An error occurred while generating the report.", "danger")
        return redirect(url_for("home"))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()



@app.route('/report/account_growth_data')
@role_required(['admin'])
def account_growth_data():
    """Return cumulative monthly account growth data grouped by role"""

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT YEAR(created_at) as year,
               MONTH(created_at) as month,
               role,
               COUNT(*) as count
        FROM Users
        WHERE is_deleted = 0 AND role IN ('elderly','volunteer')
        GROUP BY YEAR(created_at), MONTH(created_at), role
        ORDER BY YEAR(created_at), MONTH(created_at)
    """)
    results = cursor.fetchall()
    cursor.close()
    conn.close()

    # Step 1: structure monthly new accounts
    monthly_data = {}
    for row in results:
        key = f"{row['year']}-{row['month']:02d}"
        if key not in monthly_data:
            monthly_data[key] = {"elderly": 0, "volunteer": 0}
        monthly_data[key][row['role']] = row['count']

    # Step 2: compute cumulative totals
    cumulative_data = {}
    total_elderly = total_volunteer = 0
    for key in sorted(monthly_data.keys()):
        total_elderly += monthly_data[key]["elderly"]
        total_volunteer += monthly_data[key]["volunteer"]
        cumulative_data[key] = {"elderly": total_elderly, "volunteer": total_volunteer}

    return jsonify(cumulative_data)

@app.route('/report_details')
@role_required(['admin'])
def report_details():
    """Show detailed info of events in a selected category with participants"""
    category_param = request.args.get('category', '').strip()
    if not category_param:
        flash("No category selected.", "warning")
        return redirect(url_for('admin_report'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Fetch events and their participants in the category
        cursor.execute("""
            SELECT e.event_id, e.Title, e.category, e.event_date,
                   ed.username, ed.signup_type
            FROM Events e
            LEFT JOIN Event_detail ed ON e.event_id = ed.event_id
            WHERE LOWER(TRIM(e.category)) = LOWER(TRIM(%s))
            ORDER BY e.event_date ASC, ed.username ASC
        """, (category_param,))
        rows = cursor.fetchall()

        if not rows:
            flash(f"No events found for category '{category_param}'.", "info")
            return redirect(url_for('admin_report'))

        # Group data by event
        event_data = {}
        for row in rows:
            event_id = row['event_id']
            if event_id not in event_data:
                event_data[event_id] = {
                    "Title": row['Title'],
                    "Date": row['event_date'],
                    "participants": []
                }
            if row['username']:
                event_data[event_id]["participants"].append({
                    "studname": row['username'],
                    "role": row['signup_type']
                })

        # Convert dict to list for template rendering
        event_details = list(event_data.values())

        # Log the action
        log_audit_action(
            user_id=session.get('user_id'),
            email=session.get('email'),
            role=session.get('user_role'),
            action="view_report_details",
            status="success",
            details=f"Viewed events in category '{category_param}'",
            target_table="Events"
        )

        return render_template(
            "report_details.html",
            category=category_param,
            event_details=event_details
        )

    except Exception as e:
        app.logger.error(f"Error fetching report details: {e}")
        flash("An error occurred while fetching event details.", "danger")
        return redirect(url_for('admin_report'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()




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
    """Logs out the current user by clearing all session data and logging the action"""
    
    # Log the logout action before clearing session
    if g.user:
        log_audit_action(
            action='Logout',
            details=f"User {g.username} logged out",
            user_id=g.user,
            target_table='Users',
            target_id=g.user,
            role=g.role,
            status='Success'
        )
        app.logger.info(f"User {g.username} ({g.role}) logged out.")
    
    # Clear all session data for complete logout
    clear_all_session_data()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))


from flask import current_app, request, render_template, redirect, url_for, flash, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, smtplib, secrets
from email.mime.text import MIMEText
from datetime import datetime
from flask_wtf import FlaskForm

limiter = Limiter(app=app, default_limits=[], key_func=get_remote_address)

def send_ticket_email(to_email, subject, body):
    try:
        sender_email = "connex.systematic@gmail.com"
        sender_password = os.environ.get("GMAIL_APP_PASSWORD")

        if not sender_password:
            current_app.logger.error("❌ GMAIL_APP_PASSWORD not set in environment.")
            return False

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = to_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)

        current_app.logger.info(f"✅ Email sent to {to_email}")
        return True

    except Exception as e:
        current_app.logger.error(f"❌ Failed to send email to {to_email}: {e}")
        return False


@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    current_user = g.username or "Anonymous"
    is_admin = (g.role == 'admin')
    conn = cursor = None

    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        if request.method == 'POST':
            subject = request.form['subject']
            message = request.form['message']
            created_at = datetime.now()
            public_id = secrets.token_urlsafe(16)

            # Insert ticket
            cursor.execute("""
                INSERT INTO Tickets (subject, message, created_by, created_at, status, user_type, public_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (subject, message, current_user, created_at, 'open', g.role or 'user', public_id))
            ticket_db_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO Ticket_messages (ticket_id, sender, content, timestamp)
                VALUES (%s, %s, %s, %s)
            """, (ticket_db_id, current_user, message, created_at))

            cursor.execute("SELECT email FROM Users WHERE username = %s", (current_user,))
            user = cursor.fetchone()
            conn.commit()

            if user and user['email']:
                email_subject = f"Your Support Ticket has been received"
                email_body = f"""Hi {current_user},

Your ticket has been received and our team will get back to you shortly.

Ticket Details:
- Subject: {subject}
- Created: {created_at.strftime('%d/%m/%Y at %H:%M')}

Message:
{message}

You can track your ticket here:
{url_for('view_ticket', public_id=public_id, _external=True)}

Best regards,
Connex Support Team"""

                if send_ticket_email(user['email'], email_subject, email_body):
                    flash("Ticket submitted successfully! A confirmation email has been sent.", "success")
                else:
                    flash("Ticket submitted. Email could not be sent.", "warning")
            else:
                flash("Ticket submitted successfully.", "success")

            return redirect(url_for('support'))

        # Load tickets
        if is_admin:
            cursor.execute("SELECT * FROM Tickets ORDER BY created_at DESC")
        else:
            cursor.execute("SELECT * FROM Tickets WHERE created_by = %s ORDER BY created_at DESC", (current_user,))
        tickets = cursor.fetchall()
        open_tickets = [t for t in tickets if t['status'] == 'open']
        closed_tickets = [t for t in tickets if t['status'] == 'closed']

    except Exception as e:
        flash("Error loading support page.", "danger")
        current_app.logger.error(f"[support] {e}")
        open_tickets, closed_tickets = [], []

    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    return render_template("support.html",
                           open_tickets=open_tickets,
                           closed_tickets=closed_tickets,
                           is_admin=is_admin)


@app.route('/support/ticket/<public_id>', methods=['GET', 'POST'])
@limiter.limit("10/minute")
@login_required
def view_ticket(public_id):
    current_user = g.username or "Anonymous"
    is_admin = (g.role == 'admin')
    conn = cursor = None

    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        cursor.execute("SELECT * FROM Tickets WHERE public_id = %s", (public_id,))
        ticket = cursor.fetchone()
        if not ticket:
            flash("Ticket not found.", "warning")
            return redirect(url_for('support'))

        ticket_id = ticket['id']
        can_reply = ticket['status'] == 'open'

        if request.method == 'POST' and can_reply:
            message = request.form['message']
            timestamp = datetime.now()
            sender = "admin" if is_admin else current_user
            recipient = ticket['created_by'] if is_admin else "admin"

            cursor.execute("""
                INSERT INTO Ticket_messages (ticket_id, sender, recipient, content, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """, (ticket_id, sender, recipient, message, timestamp))
            conn.commit()
            flash("Message sent.", "success")

            # Notify user on admin reply
            if is_admin:
                cursor.execute("SELECT email FROM Users WHERE username = %s", (ticket['created_by'],))
                user = cursor.fetchone()
                if user and user['email']:
                    email_subject = f"New Reply to Your Ticket"
                    email_body = f"""Hi {ticket['created_by']},

An admin has replied to your ticket.

Subject: {ticket['subject']}
Reply Time: {timestamp.strftime('%d/%m/%Y at %H:%M')}

Admin Reply:
{message}

View your ticket: {url_for('view_ticket', public_id=public_id, _external=True)}

Best regards,
Connex Support Team"""

                    send_ticket_email(user['email'], email_subject, email_body)

        cursor.execute("SELECT * FROM Ticket_messages WHERE ticket_id = %s ORDER BY timestamp ASC", (ticket_id,))
        messages = cursor.fetchall()

    except Exception as e:
        flash("Error loading ticket.", "danger")
        current_app.logger.error(f"[view_ticket] {e}")
        return redirect(url_for('support'))

    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    return render_template("view-ticket.html",
                           ticket=ticket,
                           messages=messages,
                           current_user=current_user,
                           is_admin=is_admin,
                           can_reply=can_reply)


@app.route('/close_ticket/<public_id>', methods=['POST'])
@login_required
def close_ticket(public_id):
    if g.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('support'))

    conn = cursor = None

    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        cursor.execute("SELECT id, subject, created_by FROM Tickets WHERE public_id = %s", (public_id,))
        ticket = cursor.fetchone()
        if not ticket:
            flash("Ticket not found.", "warning")
            return redirect(url_for('support'))

        cursor.execute("UPDATE Tickets SET status = 'closed' WHERE id = %s", (ticket['id'],))
        conn.commit()

        cursor.execute("SELECT email FROM Users WHERE username = %s", (ticket['created_by'],))
        user = cursor.fetchone()

        if user and user['email']:
            email_subject = f"Support Ticket Closed"
            email_body = f"""Hi {ticket['created_by']},

Your support ticket has been marked as closed.

Subject: {ticket['subject']}
Closed: {datetime.now().strftime('%d/%m/%Y at %H:%M')}

View ticket: {url_for('view_ticket', public_id=public_id, _external=True)}

Thank you for contacting Connex Support!
"""
            send_ticket_email(user['email'], email_subject, email_body)

        flash("Ticket closed successfully.", "success")
        return redirect(url_for('view_ticket', public_id=public_id))

    except Exception as e:
        flash("Error closing ticket.", "danger")
        current_app.logger.error(f"[close_ticket] {e}")
        return redirect(url_for('support'))

    finally:
        if cursor: cursor.close()
        if conn: conn.close()

@app.route('/delete_ticket/<public_id>', methods=['POST'])
@role_required(['admin'])
def delete_ticket(public_id):
    conn = cursor = None

    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        # Get ticket by public_id
        cursor.execute("SELECT id, subject, created_by FROM Tickets WHERE public_id = %s", (public_id,))
        ticket = cursor.fetchone()
        if not ticket:
            flash("Ticket not found.", "warning")
            return redirect(url_for('support'))

        # Delete all related messages
        cursor.execute("DELETE FROM Ticket_messages WHERE ticket_id = %s", (ticket['id'],))
        # Delete the ticket
        cursor.execute("DELETE FROM Tickets WHERE id = %s", (ticket['id'],))
        conn.commit()

        flash("Ticket deleted successfully.", "success")
        return redirect(url_for('support'))

    except Exception as e:
        flash("Error deleting ticket.", "danger")
        current_app.logger.error(f"[delete_ticket] {e}")
        return redirect(url_for('support'))

    finally:
        if cursor: cursor.close()
        if conn: conn.close()



@app.route('/community_chats')
@login_required
def community_chat_list():
    conn = cursor = None
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute("SELECT * FROM CommunityChats ORDER BY name")
        chats = cursor.fetchall()
        return redirect(url_for('community_chat', chat_id=chats[0]['id']) if chats else '/no_chats')
    except Exception as e:
        flash("Unable to load chats", "danger")
        return render_template('community-chat.html', chats=[], messages=[], current_chat=None)
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


@app.route('/community_chat/<int:chat_id>', methods=['GET', 'POST'])
@limiter.limit("10/minute")  # Example: max 10 messages/min per IP
@login_required
def community_chat(chat_id):
    current_user = g.username or "Anonymous"
    is_admin = (g.role == 'admin')
    conn = cursor = None

    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        # Load all chats
        cursor.execute("SELECT * FROM CommunityChats ORDER BY name")
        chats = cursor.fetchall()

        # Load selected chat
        cursor.execute("SELECT * FROM CommunityChats WHERE id = %s", (chat_id,))
        current_chat = cursor.fetchone()

        if not current_chat:
            flash("Chat room not found", "warning")
            return redirect(url_for('community_chat_list'))

        # Handle new message
        if request.method == 'POST':
            message = request.form.get('message')
            cursor.execute(
                "INSERT INTO CommunityMessages (chat_id, sender, content) VALUES (%s, %s, %s)",
                (chat_id, current_user, message)
            )
            conn.commit()
            return redirect(url_for('community_chat', chat_id=chat_id))

        # Load messages for this chat
        cursor.execute("SELECT * FROM CommunityMessages WHERE chat_id = %s ORDER BY timestamp ASC", (chat_id,))
        messages = cursor.fetchall()

        return render_template(
            'community-chat.html',
            chats=chats,
            current_chat=current_chat,
            messages=messages,
            current_user=current_user,
            is_admin=is_admin
        )

    except Exception as e:
        flash("Could not load chat", "danger")
        return redirect(url_for('community_chat_list'))

    finally:
        if cursor: cursor.close()
        if conn: conn.close()

class TicketForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired(), Length(min=5, max=500)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10, max=500)])

@app.route('/faq')
def faq():
    """Render the FAQ page"""
    return render_template('faq.html')

# ================================================================================================
# HONEYPOT SECURITY ROUTES
# ================================================================================================
# These routes handle honeypot security functionality for detecting unauthorized access attempts

@app.route('/security_question')
def security_question_honeypot():
    """
    Honeypot security questions page - logs access attempts
    This is a decoy page to detect unauthorized access attempts
    """
    # Don't log here to avoid duplicate entries - let JavaScript handle it
    # Render the honeypot page
    return render_template('security_question.html')

@app.route('/honeypot/log_access', methods=['POST'])
def honeypot_log_access():
    """API endpoint to log honeypot page access with enhanced security"""
    try:
        data = request.get_json()
        
        # Validate JSON data
        if not data:
            print("DEBUG: No JSON data received in honeypot access")
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        
        webpage = data.get('webpage', 'unknown')
        input1 = data.get('input1', 'null')
        input2 = data.get('input2', 'null')
        input3 = data.get('input3', 'null')
        description = data.get('description', 'accessed page')
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        print(f"DEBUG: Honeypot access attempt - {webpage} from User-Agent: {user_agent[:100]}...")
        
        # Enhanced logging with input sanitization
        success = log_honeypot_access(webpage, input1, input2, input3, description)
        
        if success:
            print(f"DEBUG: Honeypot access logged successfully")
            return jsonify({'status': 'success', 'message': 'Access logged'}), 200
        else:
            print(f"DEBUG: Failed to log honeypot access")
            return jsonify({'status': 'error', 'message': 'Failed to log access'}), 500
            
    except Exception as e:
        print(f"Error in honeypot log access endpoint: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/honeypot/log_submission', methods=['POST'])
def honeypot_log_submission():
    """API endpoint to log honeypot form submissions with enhanced security"""
    try:
        data = request.get_json()
        
        # Validate that we have JSON data
        if not data:
            print("DEBUG: No JSON data received in honeypot submission")
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        
        # Extract and validate form data
        webpage = data.get('webpage', 'unknown')
        input1 = data.get('input1', 'null')
        input2 = data.get('input2', 'null')
        input3 = data.get('input3', 'null')
        description = data.get('description', 'data input')
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        print(f"DEBUG: Honeypot form submission - {webpage} from User-Agent: {user_agent[:100]}...")
        print(f"DEBUG: Form data captured - input1: {len(str(input1))} chars, input2: {len(str(input2))} chars, input3: {len(str(input3))} chars")
        
        # Check if any actual data was submitted (potential security threat)
        has_data = any(inp and inp != 'null' and len(str(inp).strip()) > 0 for inp in [input1, input2, input3])
        if has_data:
            print(f"🚨 SECURITY ALERT: Actual data submitted to honeypot!")
            print(f"  - Input1 length: {len(str(input1))}")
            print(f"  - Input2 length: {len(str(input2))}")
            print(f"  - Input3 length: {len(str(input3))}")
        
        # Log the submission with enhanced security
        success = log_honeypot_access(webpage, input1, input2, input3, description)
        
        if success:
            print(f"DEBUG: Honeypot form submission logged successfully")
            return jsonify({'status': 'success', 'message': 'Submission logged'}), 200
        else:
            print(f"DEBUG: Failed to log honeypot form submission")
            return jsonify({'status': 'error', 'message': 'Failed to log submission'}), 500
            
    except Exception as e:
        print(f"Error in honeypot log submission endpoint: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/test_honeypot_access')
def test_honeypot_access_page():
    """Test page for honeypot access logging with refresh detection"""
    return render_template('test_honeypot_access.html')

@app.route('/admin/honeypot')
@role_required(['admin'])
def admin_honeypot_logs():
    """Admin page to view honeypot logs"""
    try:
        # Get filter parameters
        filter_time_range = request.args.get('time_range', '')
        filter_webpage = request.args.get('webpage', '')
        filter_description = request.args.get('description', '')
        
        # Reset filters if reset button was clicked
        if request.args.get('reset'):
            filter_time_range = ''
            filter_webpage = ''
            filter_description = ''
        
        # Convert time range to hours
        hours = None
        if filter_time_range:
            try:
                hours = int(filter_time_range)
            except ValueError:
                hours = None
        
        # Get filtered honeypot logs
        logs = get_honeypot_logs_filtered(
            limit=100,
            time_range_hours=hours,
            webpage_filter=filter_webpage if filter_webpage else None,
            description_filter=filter_description if filter_description else None
        )
        
        # Get suspicious User-Agents (keep this for future use)
        suspicious_agents = get_suspicious_user_agents(days=7)
        
        # Get bot statistics (keep this for future use)
        bot_stats = get_bot_statistics(days=7)
        
        return render_template('admin_honeypot.html', 
                             logs=logs, 
                             suspicious_agents=suspicious_agents, 
                             bot_stats=bot_stats,
                             filter_time_range=filter_time_range,
                             filter_webpage=filter_webpage,
                             filter_description=filter_description)
        
    except Exception as e:
        flash("Error loading honeypot logs", "error")
        return redirect(url_for('admin_dashboard'))

# ================================================================================================
# HONEYPOT ROUTES
# ================================================================================================

@app.route('/admin_audit')
def admin_audit_honeypot():
    """
    Honeypot page that mimics an admin audit trail page.
    Only accessible through directory traversal attempts.
    Logs all access attempts for security monitoring.
    """
    # Log the honeypot access
    log_honeypot_access(
        webpage="admin audit",
        input1="null",
        input2="null", 
        input3="null",
        description="accessed page"
    )
    
    # Handle form submissions (filter attempts)
    if request.method == 'POST' or request.args:
        form_data = {}
        if request.method == 'POST':
            form_data = request.form.to_dict()
        else:
            form_data = request.args.to_dict()
        
        # Log form submission attempt
        log_honeypot_access(
            webpage="admin audit",
            input1=form_data.get('date', 'null'),
            input2=form_data.get('role', 'null'),
            input3=form_data.get('action', 'null'),
            description="form submission attempt"
        )
    
    return render_template('admin_audit.html')

@app.route('/admin_audit', methods=['POST'])
def admin_audit_honeypot_post():
    """Handle POST requests to admin_audit honeypot"""
    return admin_audit_honeypot()

# ================================================================================================

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