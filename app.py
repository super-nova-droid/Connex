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
import logging
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
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import HiddenField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from event_images import store_event_image, resize_image, get_event_image_base64,get_event_image 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Define security constants
MAX_FAILED_ATTEMPTS = 5
MAX_LOCKOUTS = 3
LOCK_DURATION = timedelta(minutes=10)

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
        
        # Get Singapore current time
        sg_timezone = pytz.timezone('Asia/Singapore')
        sg_now = datetime.now(sg_timezone)
        print("Current Singapore time:", sg_now)
         # Remove tzinfo before storing if DB column is DATETIME (not TIMESTAMP)
        sg_now_naive = sg_now.replace(tzinfo=None)
        print("Naive Singapore time (for DB):", sg_now_naive)
        # Insert audit log entry
        query = """
        INSERT INTO Audit_Log (user_id, email, role, action, status, details, target_table, target_id, timestamp) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, email, role, action, status, details, target_table, target_id, sg_now_naive))

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
    session['login_session_active'] = True  # Mark session as active
    
    # Mark as a temporary session (this data will not persist after server restart)
    session.permanent = False
    print(f"DEBUG: Created temporary login session at step {step} with temp_user_id: {user_data.get('user_id')}")
    print(f"DEBUG: Session contents: {dict(session)}")

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
    session['role'] = role
    
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
    Clears all session data. This is now the ONLY way to log out.
    It's a more secure and robust alternative to your original clear_login_session.
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
        print(f"DEBUG: require_login_session check - temp_user_id: {session.get('temp_user_id')}")
        print(f"DEBUG: require_login_session check - full session: {dict(session)}")
        if not session.get('temp_user_id'):
            print(f"DEBUG: No temp_user_id found, redirecting to login")
            session.clear()
            flash("Invalid session. Please log in again.", "error")
            return redirect(url_for('login'))
        print(f"DEBUG: require_login_session check passed, proceeding to route")
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
    # Check if a user is logged in before trying to access attributes on `g`
    if g.user is not None:
        user_role = g.role
        username = g.username
    else:
        # If no user is logged in, set default values
        user_role = None
        username = None

    # The template can now safely check for the presence of user_role
    return render_template('home.html', user_role=user_role, username=username)

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
            # A03:2021-Injection: Parameterized query
            # Check both email and username fields and get security questions info
            cursor.execute("""
                SELECT user_id, username, password, role, email, sec_qn_1, sec_qn_2, sec_qn_3,
                    failed_attempts, last_failed_attempt, lockout_count, permanently_locked
                FROM Users 
                WHERE (email = %s OR username = %s)
                AND is_deleted = 0
            """, (email_or_username, email_or_username))
            user = cursor.fetchone()



            # A07:2021-Identification and Authentication Failures: Generic error message for login
            # This prevents user enumeration.
            if user:
                # === Admin lockout handling ===
                if user['role'] == 'admin':
                    if user['permanently_locked']:
                        flash('Your account is permanently locked. Contact another admin.', 'danger')
                        return render_template('login.html')

                    # Temporary lockout: only check if last_failed_attempt exists and lockout time hasn't passed
                    if user['last_failed_attempt']:
                        
                        locked_time = user['last_failed_attempt'] + timedelta(hours=8, minutes=1)  # Assuming 1 minute lockout for failed attempts
                        now_time = datetime.now()
                        if now_time < locked_time:
                            remaining = locked_time - now_time
                            minutes_left = int(remaining.total_seconds() // 60) + 1
                            flash(f'Account temporarily locked. Try again in {minutes_left} minutes.', 'error')
                            
                            # Stop here, no further logging that references user['role']
                            return render_template('login.html')


                # Password verification
                if check_password_hash(user['password'], password):
                    # If admin and temporarily locked, do NOT allow login
                    if user['role'] == 'admin' and user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
                        flash('Your account is temporarily locked. Try again later.', 'error')
                        return render_template('login.html')
                    
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
                    
                    session['last_active'] = str(datetime.utcnow())  # Store current time for idle tracking


                # NEW FLOW: Check facial recognition first (highest priority)
                if check_face_recognition_enabled(user['user_id']):
                    # User has facial recognition enabled - redirect to face verification
                    flash("Please verify your identity using facial recognition.", "info")
                    session['login_step'] = 'face_verification_required'
                    session['login_session_active'] = True  # Mark session as active for face verification
                    print(f"DEBUG: Set login_session_active=True, redirecting to face verification")
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
        
        # Instead of storing the data in session here, create a dictionary to pass to the function
        signup_data = {
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
            cursor.execute("SELECT * FROM Users WHERE username = %s AND is_deleted = 0", (username,))

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
                cursor.execute("SELECT * FROM Users WHERE email = %s AND is_deleted = 0", (email,))

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
                
                # Clear any leftover login session data to avoid confusion
                clear_login_session()
                
                # Create secure signup session
                # Pass the data to the function, which should set the session variable.
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
                # Pass the data to the function, which should set the session variable.
                create_signup_session(signup_data)
                session['signup_method'] = 'security_questions'
                
                # CONDITIONAL LOGIC: Always do security questions first to avoid large session cookies
                # No Email + Face Capture → Security Questions + face capture
                # No Email + no Face Capture → Security Questions
                flash("Please set up security questions to complete your registration.", "info")
                return redirect(url_for('security_questions'))

        except Exception as e:
            # This is the key change. Provide a generic, user-friendly message.
            flash("An unexpected error occurred during signup. Please try again.", "error")
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
            email = signup_data.get('email', '').strip()
            username = signup_data.get('username', '').strip()

            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True, buffered=True)
            cursor.execute("SELECT * FROM Users WHERE (email = %s OR username = %s) AND is_deleted = 1",
                        (email, username))
            deleted_user = cursor.fetchone()
            cursor.close()
            conn.close()

            if deleted_user:
                # Mark as reactivation
                session['reactivate_user_uuid'] = deleted_user['uuid']
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
    """Create or reactivate account after email/security questions verification"""
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
        print(f"DEBUG: Creating/reactivating account...")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        import uuid
        
        # Check if a soft-deleted account exists with same username or email
        cursor.execute("""
            SELECT uuid FROM Users
            WHERE (username = %s OR email = %s) AND is_deleted = 1
        """, (name, email))
        deleted_user = cursor.fetchone()

        if deleted_user:
            # Reactivate and overwrite old account
            user_uuid = deleted_user['uuid']
            cursor.execute("""
                UPDATE Users
                SET username=%s,
                    email=%s,
                    password=%s,
                    dob=%s,
                    location_id=%s,
                    role=%s,
                    sec_qn_1=NULL,
                    sec_qn_2=NULL,
                    sec_qn_3=NULL,
                    facial_recognition_data=NULL,
                    is_deleted=0
                WHERE uuid=%s
            """, (name, email if email else None, hashed_password, dob, location_id, role, user_uuid))
            conn.commit()
            flash("Account reactivated and updated successfully!", "success")
            print(f"DEBUG: Reactivated user UUID: {user_uuid}")
        else:
            # Insert new user
            user_uuid = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO Users (uuid, username, email, password, dob, location_id, role, sec_qn_1, sec_qn_2, sec_qn_3)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL)
            """, (user_uuid, name, email if email else None, hashed_password, dob, location_id, role))
            conn.commit()
            flash("Account created successfully!", "success")
            print(f"DEBUG: New user UUID: {user_uuid}")
        
        # Clear signup session to prevent re-use
        clear_signup_session()
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"DEBUG: Error during account creation/reactivation: {e}")
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
    
    # DEBUG: Log session state at the start
    print(f"DEBUG: login_verify_face route called")
    print(f"DEBUG: Session data: {dict(session)}")
    print(f"DEBUG: temp_user_id: {session.get('temp_user_id')}")
    print(f"DEBUG: login_session_active: {session.get('login_session_active')}")
    print(f"DEBUG: Request method: {request.method}")
    
    if request.method == 'POST':
        try:
            image_data = request.form.get('image_data')
            
            # SERVER-SIDE VALIDATION: Validate face image data for login
            image_valid, image_message, opencv_image = validate_face_image_data(image_data)
            
            if not image_valid:
                flash(image_message, "error")
                return render_template('login_verify_face.html')
            

            # SERVER-SIDE VALIDATION: Validate face detection in login image
            face_valid, face_message = validate_face_detection_result(opencv_image)

            
            if not face_valid:
                flash(face_message, "error")
                return render_template('login_verify_face.html')
            

            # SERVER-SIDE VALIDATION: Validate login session data
            required_session_fields = ['temp_user_id', 'login_session_active']
            session_valid, session_message = validate_session_data(session, required_session_fields)
            
            if not session_valid:

                flash("Login session expired. Please login again.", "error")
                session.clear() 
                return redirect(url_for('login'))
            

            # Get user ID from login session
            user_id = session.get('temp_user_id')
            
            # Verify the face against stored image
            success, message = verify_user_face(user_id, opencv_image)
            
            # Extract similarity score from message for enhanced logging
            similarity_score = "unknown"
            try:
                if "similarity:" in message:
                    similarity_score = message.split("similarity: ")[1].split(")")[0]
            except:
                pass
            
            user_role = session.get('temp_user_role')
            user_name = session.get('temp_user_name')
            user_email = session.get('temp_user_email', '')
            
            # Enhanced facial recognition logging
            print(f"FACIAL RECOGNITION LOG:")
            print(f"  User: {user_name} (ID: {user_id})")
            print(f"  Email: {user_email}")
            print(f"  Role: {user_role}")
            print(f"  Similarity Score: {similarity_score}")
            print(f"  Result: {'ACCEPTED' if success else 'REJECTED'}")
            print(f"  Message: {message}")
            print(f"  Threshold: 0.60 (60%)")
            print("=" * 50)
            
            app.logger.info(f"FACIAL RECOGNITION: User {user_name} (ID: {user_id}) - Similarity: {similarity_score}, Result: {'ACCEPTED' if success else 'REJECTED'}, Message: {message}")
            
            if success:
                user_role = session.get('temp_user_role')
                user_name = session.get('temp_user_name')
                
                clear_temp_login_session()
                complete_login(user_id, user_name, user_role)

                log_audit_action(
                    action='Login',
                    details=f'Facial recognition verified for user {session.get("temp_user_email", "")} with role {user_role}',
                    user_id=user_id,
                    status='Success'
                )
                
                flash("Login successful! Face verification completed.", "success")
                return redirect(url_for('home'))
            else:
                failed_attempts = session.get('face_failed_attempts', 0) + 1
                session['face_failed_attempts'] = failed_attempts
                
                # Enhanced failure logging
                print(f"FACIAL RECOGNITION FAILED:")
                print(f"  User: {user_name} (ID: {user_id})")
                print(f"  Similarity Score: {similarity_score}")
                print(f"  Threshold Required: 0.60 (60%)")
                print(f"  Result: REJECTED - {message}")
                print(f"  Failed Attempts: {failed_attempts}/3")
                print("=" * 50)
                
                app.logger.warning(f"FACIAL RECOGNITION FAILED: User {user_name} (ID: {user_id}) - Similarity: {similarity_score}, Below threshold, Message: {message}, Attempt {failed_attempts}/3")
                
                log_audit_action(
                    action='Login',
                    details=f'Facial recognition failed for user {session.get("temp_user_email", "")} with role {session.get("temp_user_role")}: {message} (Attempt {failed_attempts}/3)',
                    user_id=user_id,
                    status='Failed'
                )
                
                if failed_attempts >= 3:
                    
                    
                    user_email = session.get('temp_user_email')
                    
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
@login_required  # if you use login_required decorator
def mfa():
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
    return render_template('chat.html', openai_api_key=OPENAI_API_KEY, is_admin=is_admin, csrf_token=generate_csrf)


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
        user_message = request.json.get('message')
        chat_session_id = request.json.get('session_id')
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
            'event_date': row['event_date'].strftime('%d %B %Y') if row['event_date'] else '',
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
        'location_name': event['location_name'],
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


@app.route('/admin/event/<int:event_id>/delete', methods=['POST'])
def delete_event(event_id):
    if g.role != 'admin':
        return redirect(url_for('login'))

    email = request.form.get('admin_email')
    password = request.form.get('admin_password')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get admin record
        cursor.execute("SELECT * FROM Users WHERE email = %s AND role = 'admin'", (email,))
        admin = cursor.fetchone()

        # Check if admin exists
        if not admin:
            flash("Admin not found.", "danger")
            return redirect(url_for('admin_event_details', event_id=event_id))

        # Verify password
        if not check_password_hash(admin['password'], password):
            flash("Invalid admin password.", "danger")
            return redirect(url_for('admin_event_details', event_id=event_id))

        # Delete the event
        cursor.execute("DELETE FROM Events WHERE event_id = %s", (event_id,))
        conn.commit()

        if cursor.rowcount > 0:
            flash('Event deleted successfully.', 'success')
            log_audit_action(
                user_id=g.user,
                email=g.username,
                role=g.role,
                action='Delete_Event',
                status='Success',
                details=f"Deleted event with ID {event_id}",
                target_table='Events',
                target_id=event_id
            )
        else:
            flash('Event not found or already deleted.', 'warning')

    except Exception as e:
        if conn:
            conn.rollback()
        flash('Error deleting event. Please try again.', 'danger')
        app.logger.error(f"Error deleting event {event_id}: {e}")
    finally:
        if cursor: 
            cursor.close()
        if conn: 
            conn.close()

    return redirect(url_for('admin_events'))


# Account deletion route - this appears to be missing its route decorator
@app.route('/admin/delete_account', methods=['POST'])
@role_required(['admin'])
def delete_account():
    uuid_to_delete = request.form.get('uuid_to_delete')
    admin_password_input = request.form.get('admin_password')
    
    if not uuid_to_delete or not admin_password_input:
        flash('Missing required fields.', 'danger')
        return redirect(url_for('account_management'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get admin record
        cursor.execute("SELECT * FROM Users WHERE user_id = %s AND role = 'admin'", (g.user,))
        admin = cursor.fetchone()

        if not admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('account_management'))
        
        # ✅ Early check: is the UUID to delete my own account?
        cursor.execute("SELECT user_id FROM Users WHERE uuid = %s", (uuid_to_delete,))
        target_user = cursor.fetchone()

        if target_user and target_user['user_id'] == g.user:
            flash('You cannot delete your own account while logged in!', 'danger')
            return redirect(url_for('account_management'))
        
        now = datetime.now()

        # Check permanent lock
        if admin['permanently_locked']:
            flash('Your account is permanently locked. Contact another admin.', 'danger')
            session.clear()
            return redirect(url_for('login'))

        # Check temporary lock
        if admin['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
            last_failed = admin['last_failed_attempt']
            if last_failed:
                elapsed = now - last_failed
                if elapsed < LOCK_DURATION:
                    # Admin is still temporarily locked
                    flash(f'Account temporarily locked. Try again later.', 'danger')
                    session.clear()
                    return redirect(url_for('login', lockout=1))
                else:
                    # Lockout period expired: now reset failed_attempts
                    cursor.execute("""
                        UPDATE Users
                        SET failed_attempts = 0, last_failed_attempt = NULL
                        WHERE user_id = %s
                    """, (g.user,))
                    conn.commit()
                    admin['failed_attempts'] = 0

        # Verify password
        if not check_password_hash(admin['password'], admin_password_input):
            flash('Invalid Credential', 'danger')

            # Increment failed_attempts + update last_failed_attempt
            cursor.execute("""
                UPDATE Users
                SET failed_attempts = failed_attempts + 1,
                    last_failed_attempt = NOW()
                WHERE user_id = %s
            """, (g.user,))
            conn.commit()
            app.logger.debug("DEBUG: Invalid password, incremented failed_attempts")

            # Fetch updated info
            cursor.execute("SELECT failed_attempts, lockout_count FROM Users WHERE user_id=%s", (g.user,))
            updated_user = cursor.fetchone()
            app.logger.debug(f"DEBUG: Updated user info after failed attempt: {updated_user}")

            # Check if reached temporary lockout
            if updated_user['failed_attempts'] >= MAX_FAILED_ATTEMPTS:
                new_lockout_count = updated_user['lockout_count'] + 1
                permanently_locked = 0
                cursor.execute("""
                    UPDATE Users
                    SET lockout_count = %s,
                        failed_attempts = 0,
                        last_failed_attempt = NOW(),
                        permanently_locked = %s
                    WHERE user_id = %s
                """, (new_lockout_count, permanently_locked, g.user))
                conn.commit()

                # Check permanent lock after max lockouts
                if new_lockout_count >= MAX_LOCKOUTS:
                    cursor.execute("UPDATE Users SET permanently_locked=1 WHERE user_id=%s", (g.user,))
                    conn.commit()

                flash('Too many failed attempts. Account temporarily locked.', 'danger')
                session['locked'] = True
                return redirect(url_for('account_management', lockout=1, minutes=10))
            # If just 1-4 failed attempts, stay on account management
            return redirect(url_for('account_management'))

        # ✅ Correct password: reset failed_attempts
        cursor.execute("""
            UPDATE Users
            SET failed_attempts=0, last_failed_attempt=NULL
            WHERE user_id=%s
        """, (g.user,))
        conn.commit()

        # Proceed with deletion
        cursor.execute("SELECT email FROM Users WHERE uuid = %s", (uuid_to_delete,))
        user_record = cursor.fetchone()

        if not user_record:
            flash('User not found.', 'warning')
            return redirect(url_for('account_management'))

        # Soft delete
        cursor.execute("UPDATE Users SET is_deleted=1 WHERE uuid=%s", (uuid_to_delete,))
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
        webpage = data.get('webpage', 'null')
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

# Add this debug check to your app.py to verify the password is loaded
@app.route('/debug_email_settings')
@role_required(['admin'])
def debug_email_settings():
    gmail_password = os.environ.get("GMAIL_APP_PASSWORD")
    return jsonify({
        'gmail_password_set': bool(gmail_password),
        'gmail_password_length': len(gmail_password) if gmail_password else 0,
        'sender_email': "connex.systematic@gmail.com"
    })