
from math import ceil
import mysql.connector
from datetime import datetime, timedelta, time, date
from dotenv import load_dotenv
import os
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash,generate_password_hash
from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.google import make_google_blueprint, google
from connexmail import send_otp_email, generate_otp
from flask import redirect
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from security_questions import security_questions_route, reset_password_route, forgot_password_route
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Allow insecure transport for OAuth (not recommended for production)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g,abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import re # For input validation
from functools import wraps # For decorators

load_dotenv()  # Load environment variables from .env file


DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = int(os.environ.get('DB_PORT', 3306))

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
if not OPENAI_API_KEY:
    print("WARNING: OPENAI_API_KEY environment variable is not set. Chatbot may not function.")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(413)
def too_large(e):
    flash("File is too large. Maximum allowed size is 2MB.", "danger")
    return redirect(request.referrer or url_for('admin_events'))

def get_lat_lng_from_address(address):
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
    api_key = os.getenv('OPEN_CAGE_API_KEY')
    geocoder = OpenCageGeocode(api_key)
    result = geocoder.reverse_geocode(lat, lng)
    
    if result and len(result):
        return result[0]['formatted']  # A readable address string
    return None

# --- Helper functions for /events route ---


# A05:2021-Security Misconfiguration: Critical to have a strong, unique secret key.
# Fallback is for development only. Production MUST have this set.
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# Google OAuth Blueprint setup
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
    try:
        return mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
    except mysql.connector.Error as err:
        # A09:2021-Security Logging: Log database connection errors.
        app.logger.error(f"Database connection error: {err}")
        flash("Could not connect to the database. Please try again later.", "error")
        # In a real application, you might want to redirect to an error page or render an error template.
        raise  # Re-raise to stop execution if DB connection is critical

def get_db_cursor(conn):
    return conn.cursor(dictionary=True)

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
    g.user = session.get('user_id')
    g.role = session.get('user_role')
    g.username = session.get('user_name')

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/home')
@role_required(['elderly', 'volunteer', 'admin']) # Allow all logged-in roles to access home

def home():
    if g.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif g.role == 'volunteer':
        return redirect(url_for('volunteer_dashboard'))
    else:
        return render_template('home.html')

@app.route('/volunteer_dashboard')
@role_required(['volunteer', 'admin']) # Admins can also see volunteer dashboard
def volunteer_dashboard():
    return render_template('volunteer.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: # A07:2021-Identification and Authentication Failures: Redirect if already logged in
        return redirect(url_for('home'))

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
                # First authentication step passed - store user info temporarily
                session['temp_user_id'] = user['user_id']
                session['temp_user_role'] = user['role']
                session['temp_user_name'] = user['username']
                session['login_step'] = 'password_verified'

                app.logger.info(f"Password verification successful for user {user['username']} ({user['role']}).")

                # Check if user has an email (not null or empty)
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
                        session.clear()
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
                app.logger.warning(f"Failed login attempt for email/username: {email_or_username}") # A09:2021-Security Logging
        except Exception as e:
            app.logger.error(f"Login error for email/username {email_or_username}: {e}")
            flash("An unexpected error occurred during login. Please try again.", "error")
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    return render_template('login.html')

# --- Routes ---
# All your other routes (home, login, etc.) would be here, unchanged.


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if g.user:
        return redirect(url_for('home'))

    prefill_email = session.get("oauth_signup_email")
    prefill_username = session.get("oauth_signup_username")
    
    # Define community centers
    locations = [
        {'location_id': 1, 'location_name': 'Hougang Community Centre', 'address': 'Hougang'},
        {'location_id': 2, 'location_name': 'Seng Kang Community Centre', 'address': 'Seng Kang'},
        {'location_id': 3, 'location_name': 'Punggol Community Centre', 'address': 'Punggol'},
        {'location_id': 4, 'location_name': 'Ang Mo Kio Community Centre', 'address': 'Ang Mo Kio'},
        {'location_id': 5, 'location_name': 'Bishan Community Centre', 'address': 'Bishan'}
    ]

    locations = []
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        # Ensure a dictionary cursor is used here and consistently.
        cursor = get_db_cursor(conn)
        cursor.execute("SELECT location_id, location_name, address FROM Locations")
        locations = cursor.fetchall()
    except Exception as e:
        app.logger.error(f"Error fetching locations: {e}")
        flash("Could not load community clubs. Please try again later.", "error")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    if request.method == 'POST':
        name = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        email = request.form.get('email', '').strip()
        dob = request.form.get('dob')
        location_id = request.form.get('location_id')
        is_volunteer = 'is_volunteer' in request.form

        # --- REVISED VALIDATION LOGIC FOR INLINE ERRORS ---
        password_error = None
        username_error = None
        email_error = None
        
        # Check password complexity
        if len(password) < 8:
            password_error = "Password must be at least 8 characters long."
        elif not re.search(r'[A-Z]', password):
            password_error = "Password must contain at least one uppercase letter."
        elif not re.search(r'[a-z]', password):
            password_error = "Password must contain at least one lowercase letter."
        elif not re.search(r'\d', password):
            password_error = "Password must contain at least one number."
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            password_error = "Password must contain at least one special character."
        elif password != confirm_password:
            password_error = "Passwords do not match."
        
        # Check email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            email_error = "Invalid email format."
            
        # If any client-side validation fails, re-render the page with errors
        if password_error or email_error:
            flash("Please correct the errors below.", "error")
            return render_template('signup.html', locations=locations, username=name, email=email, dob=dob, location_id=location_id, password_error=password_error, email_error=email_error)

        hashed_password = generate_password_hash(password)
        role = 'volunteer' if is_volunteer else 'elderly'

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check for existing username (server-side check)
            cursor.execute("SELECT user_id FROM Users WHERE username = %s", (name,))
            if cursor.fetchone():
                username_error = "This username is already taken. Please choose another one."
                flash("Please correct the errors below.", "error")
                return render_template('signup.html', locations=locations, username=name, email=email, dob=dob, location_id=location_id, username_error=username_error)

            # Check for existing email (server-side check)
            cursor.execute("SELECT user_id FROM Users WHERE email = %s", (email,))
            if cursor.fetchone():
                email_error = "An account with this email already exists."
                flash("Please correct the errors below.", "error")
                return render_template('signup.html', locations=locations, username=name, email=email, dob=dob, location_id=location_id, email_error=email_error)

            cursor.execute("""
                INSERT INTO Users (username, email, password, dob, location_id, role)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, hashed_password, dob, location_id, role))
            conn.commit()

            flash("Account created successfully! Please log in.", "success")
            app.logger.info(f"New user registered: {name} ({email}) with role {role}.")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            app.logger.error(f"Database error during signup for {email}: {err}")
            if err.errno == 1062: # Duplicate entry error code
                # Re-check to be more specific about the duplication
                try:
                    cursor.execute("SELECT user_id FROM Users WHERE username = %s", (name,))
                    if cursor.fetchone():
                        username_error = "This username is already taken. Please choose another one."
                    cursor.execute("SELECT user_id FROM Users WHERE email = %s", (email,))
                    if cursor.fetchone():
                        email_error = "An account with this email already exists."
                except Exception as e:
                    app.logger.error(f"Error during duplicate check: {e}")
                
                flash("Please correct the errors below.", "error")
                return render_template('signup.html', locations=locations, username=name, email=email, dob=dob, location_id=location_id, username_error=username_error, email_error=email_error)
            else:
                flash("Something went wrong. Please try again.", "error")
            if conn: conn.rollback()
            return render_template('signup.html', locations=locations, username=name, email=email, dob=dob, location_id=location_id)
        # Store form data in session, do NOT insert into DB yet
        email = request.form.get('email', '').strip()
        
        session['pending_signup'] = {
            'username': request.form['username'],
            'password': request.form['password'],
            'confirm_password': request.form['confirm_password'],
            'email': email,
            'dob': request.form['dob'],
            'location_id': request.form['location_id'],
            'is_volunteer': 'is_volunteer' in request.form
        }

        # Basic Validation
        if session['pending_signup']['password'] != session['pending_signup']['confirm_password']:
            flash("Passwords do not match.", "error")
            # Clear session data
            session.pop('pending_signup', None)
            return redirect(url_for('signup'))

        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        try:
            # Check if username already exists
            cursor.execute("SELECT * FROM Users WHERE username = %s", (session['pending_signup']['username'],))
            existing_username = cursor.fetchone()
            cursor.fetchall()  # Consume any remaining results

            if existing_username:
                flash("Username is already taken.", "error")
                # Clear session data
                session.pop('pending_signup', None)
                return redirect(url_for('signup'))

            # If user provided an email, use OTP verification
            if email:
                # Check if email already exists
                cursor.execute("SELECT * FROM Users WHERE email = %s", (session['pending_signup']['email'],))
                existing_email = cursor.fetchone()
                cursor.fetchall()  # Consume any remaining results

                if existing_email:
                    flash("Email is already registered.", "error")
                    # Clear session data
                    session.pop('pending_signup', None)
                    return redirect(url_for('signup'))

                otp = generate_otp()
                print(f"DEBUG: Generated signup OTP: '{otp}' (type: {type(otp)})")
                
                # Clear any leftover login session data to avoid confusion
                session.pop('login_step', None)
                session.pop('login_otp_code', None)
                session.pop('login_otp_email', None)
                session.pop('temp_user_id', None)
                session.pop('temp_user_role', None)
                session.pop('temp_user_name', None)
                
                session['otp_email'] = session['pending_signup']['email']
                session['otp_code'] = otp
                session['otp_verified'] = False
                print(f"DEBUG: Signup session state: login_step='{session.get('login_step')}', otp_code='{session.get('otp_code')}'")

                send_otp_email(session['pending_signup']['email'], otp)
                return redirect(url_for('verify_otp'))
            else:
                # No email provided - redirect to security questions for verification
                session['signup_method'] = 'security_questions'
                flash("Please set up security questions to complete your registration.", "info")
                return redirect(url_for('security_questions'))

        except Exception as e:
            flash("An error occurred during signup. Please try again.", "error")
            print(f"Error: {e}")
            # Clear session data
            session.pop('pending_signup', None)
            return redirect(url_for('signup'))
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html', locations=locations)
    return render_template('signup.html', prefill_email=prefill_email, prefill_username=prefill_username, locations=locations)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if not entered_otp:
            flash("OTP cannot be empty.", "error")
            return redirect(url_for('verify_otp'))

        if entered_otp == session.get('otp_code'):
            # Insert user into DB only after OTP is verified
            signup_data = session.get('pending_signup')
            if not signup_data:
                flash("Signup session expired. Please sign up again.", "error")
                return redirect(url_for('signup'))

            name = signup_data['username']
            password = signup_data['password']
            email = signup_data['email']
            dob = signup_data['dob']
            location_id = signup_data['location_id']
            is_volunteer = signup_data['is_volunteer']
            hashed_password = generate_password_hash(password)
            role = 'volunteer' if is_volunteer else 'elderly'

            conn = None
            cursor = None
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO Users (username, email, password, dob, location_id, role, sec_qn_1, sec_qn_2, sec_qn_3)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (name, email, hashed_password, dob, location_id, role, "null", "null", "null"))
                conn.commit()
                
                # Clean up session after successful insertion
                session.pop('pending_signup', None)
                session.pop('otp_code', None)
                session.pop('otp_email', None)
                session['otp_verified'] = True
                
                flash("Account created and email verified successfully!", "success")
                return redirect(url_for('login'))
                
            except mysql.connector.Error as err:
                print("Database error:", err)
                flash("Something went wrong. Please try again.", "error")
                return redirect(url_for('signup'))
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()
        else:
            flash("Invalid OTP. Please try again.", "error")
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')

@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    # Check if there's a pending signup session
    if 'pending_signup' not in session or 'otp_email' not in session:
        flash("No active OTP session found. Please sign up again.", "error")
        return redirect(url_for('signup'))
    
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
def login_verify_otp():
    """Verify OTP for login completion"""
    # Check if user is in correct login state
    if (session.get('login_step') != 'otp_required' or 
        not session.get('temp_user_id') or 
        not session.get('login_otp_code')):
        flash("Login session expired. Please log in again.", "error")
        return redirect(url_for('login'))
    
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
            
            # Clear temporary session data and set permanent login session
            session.clear()
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
def resend_login_otp():
    """Resend OTP for login verification"""
    # Check if there's an active login OTP session
    if (session.get('login_step') != 'otp_required' or 
        not session.get('temp_user_id') or 
        not session.get('login_otp_email')):
        flash("No active login OTP session found. Please log in again.", "error")
        return redirect(url_for('login'))
    
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
    # A07:2021-Identification and Authentication Failures: Placeholder for MFA implementation.
    # This route should be part of a robust MFA flow (e.g., after successful password verification).
    flash("MFA integration is a critical security step for production applications.", "info")
    return render_template('mfa.html')


# Security Questions Routes - imported from security_questions module
@app.route('/security_questions', methods=['GET', 'POST'])
def security_questions():
    """Security questions route using the security_questions module"""
    return security_questions_route()

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Password reset route using the security_questions module"""
    return reset_password_route()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password route using the security_questions module"""
    return forgot_password_route()

@app.route('/add_event', methods=['GET', 'POST'])
#@login_required(['admin'])
def add_event():
    return render_template('add_events.html')


@app.route('/admin_dashboard')
@role_required(['admin'])
def admin_dashboard():
    return render_template('admin.html')

@app.route('/admin/accounts')
@role_required(['admin'])
def account_management():
    conn = None
    cursor = None
    volunteers, elderly, admins = [], [], []
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        cursor.execute("SELECT email, username, created_at, role FROM Users WHERE role = 'volunteer'")
        volunteers = cursor.fetchall()

        cursor.execute("SELECT email, username, created_at, role FROM Users WHERE role = 'elderly'")
        elderly = cursor.fetchall()

        cursor.execute("SELECT email, username, created_at, role FROM Users WHERE role = 'admin'")
        admins = cursor.fetchall()
    except Exception as e:
        app.logger.error(f"Error fetching accounts for management: {e}")
        flash("Failed to load accounts.", "error")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

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
                flash('All fields are required.', 'danger')
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            if updated_role not in ['elderly', 'volunteer', 'admin']:
                flash('Invalid role specified.', 'danger')
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            if not re.match(r"[^@]+@[^@]+\.[^@]+", updated_email):
                flash("Invalid email format.", "danger")
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            # Important: Check if the new email already exists for another user
            cursor.execute("SELECT user_id FROM Users WHERE email = %s AND email != %s", (updated_email, email_param))
            if cursor.fetchone():
                flash("This email is already in use by another account.", "danger")
                return redirect(url_for('account_details', role_param=role_param, email_param=email_param))

            cursor.execute('''
                UPDATE Users
                SET username = %s, role = %s, email = %s, DOB = %s, location_id = %s
                WHERE email = %s AND role = %s
            ''', (username, updated_role, updated_email, dob if dob else None, location, email_param, role_param))
            conn.commit()

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
        flash('No email or role provided for deletion.', 'warning')
        return redirect(url_for('account_management'))

    if email_to_delete == g.username: # Prevent admin from deleting themselves
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
            app.logger.info(f"Admin {g.username} deleted account: {email_to_delete} ({role_to_delete}).") # A09:2021-Security Logging
        else:
            flash(f'Account {email_to_delete} ({role_to_delete}) not found or role mismatch.', 'warning')

    except Exception as e:
        flash('Error deleting account. Please try again.', 'danger')
        app.logger.error(f"Error deleting account {email_to_delete} ({role_to_delete}): {e}") # A09:2021-Security Logging
        if conn: conn.rollback()
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
    return redirect(url_for('account_management'))

@app.route('/eventdetails/<int:event_id>')
@login_required
def event_details(event_id):
    db_connection = None
    cursor = None
    event = None
    has_signed_up = False
    is_volunteer_for_event = False

    current_user_id = g.user
    current_user_role = g.role

    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        # A03:2021-Injection: %s for parameterization
        cursor.execute("SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event WHERE EventID = %s", (event_id,))
        event = cursor.fetchone()

        if not event:
            flash(f"No event found with ID {event_id}.", 'error')
            app.logger.warning(f"Attempted to view non-existent event ID: {event_id} by user {current_user_id}.")
            return redirect(url_for('usereventpage'))

        # A03:2021-Injection: Parameterized queries for signup and volunteer checks
        cursor.execute("SELECT COUNT(*) FROM user_calendar_events WHERE event_id = %s AND user_id = %s", (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            has_signed_up = True

        if current_user_role in ['volunteer', 'elderly', 'admin']: # Assuming admins can also volunteer for testing
            cursor.execute("SELECT COUNT(*) FROM event_volunteers WHERE event_id = %s AND user_id = %s", (event_id, current_user_id))
            if cursor.fetchone()['COUNT(*)'] > 0:
                is_volunteer_for_event = True

    except mysql.connector.Error as err:
        app.logger.error(f"Error fetching event details for event ID {event_id}: {err}")
        flash(f"Database error: Could not retrieve event details.", 'error')
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
@login_required
def sign_up_for_event():
    event_id = request.form.get('event_id', type=int)
    current_user_id = g.user
    current_username = g.username

    if not event_id:
        flash("Invalid event ID provided for sign-up.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) FROM user_calendar_events WHERE event_id = %s AND user_id = %s", (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash(f"You have already signed up for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO user_calendar_events (event_id, user_id, username) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id, current_username))
        db_connection.commit()

        flash(f"Successfully signed up for the event!", 'success')
        app.logger.info(f"User {current_user_id} ({current_username}) signed up for event {event_id}.") # A09:2021-Security Logging

    except mysql.connector.Error as err:
        app.logger.error(f"Error signing up for event {event_id} by user {current_user_id}: {err}")
        flash(f"Error signing up for event: An unexpected database error occurred.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))

@app.route('/remove_sign_up', methods=['POST'])
@login_required
def remove_sign_up():
    event_id = request.form.get('event_id', type=int)
    current_user_id = g.user

    if not event_id:
        flash("Invalid event ID provided for removal.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        delete_query = "DELETE FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(delete_query, (event_id, current_user_id))
        db_connection.commit()

        if cursor.rowcount > 0:
            flash(f"Event sign-up removed successfully!", 'success')
            app.logger.info(f"User {current_user_id} removed sign-up for event {event_id}.") # A09:2021-Security Logging
        else:
            flash(f"No sign-up found for this event to remove.", 'warning')

    except mysql.connector.Error as err:
        app.logger.error(f"Error removing event sign-up for event {event_id} by user {current_user_id}: {err}")
        flash(f"Error removing event sign-up: An unexpected database error occurred.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))

@app.route('/volunteer_for_event', methods=['POST'])
@login_required
def volunteer_for_event():
    current_user_id = g.user
    current_user_role = g.role

    # A01:2021-Broken Access Control: Explicitly define who can volunteer
    # If only 'volunteer' role can volunteer:
    if current_user_role not in ['volunteer', 'elderly']: # Re-evaluate this business logic
        flash("You are not authorized to volunteer for events.", 'error')
        app.logger.warning(f"Unauthorized volunteer attempt by user {current_user_id} (role: {current_user_role}).")
        return redirect(url_for('home'))

    event_id = request.form.get('event_id', type=int)

    if not event_id:
        flash("Invalid event ID provided for volunteering.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) FROM event_volunteers WHERE event_id = %s AND user_id = %s", (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash("You have already volunteered for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO event_volunteers (event_id, user_id) VALUES (%s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id))
        db_connection.commit()
        flash("Successfully signed up to volunteer for the event!", 'success')
        app.logger.info(f"User {current_user_id} volunteered for event {event_id}.") # A09:2021-Security Logging

    except mysql.connector.Error as err:
        app.logger.error(f"Error volunteering for event {event_id} by user {current_user_id}: {err}")
        flash(f"Error volunteering for event: An unexpected database error occurred.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))

@app.route('/remove_volunteer', methods=['POST'])
@login_required
def remove_volunteer():
    current_user_id = g.user
    current_user_role = g.role

    if not current_user_id:
        flash("You must be logged in to remove your volunteer sign-up.", 'info')
        return redirect(url_for('login'))

    event_id = request.form.get('event_id', type=int)

    if not event_id:
        flash("Invalid event ID provided for removal.", 'error')
        return redirect(url_for('usereventpage'))

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        delete_query = "DELETE FROM event_volunteers WHERE event_id = %s AND user_id = %s"
        cursor.execute(delete_query, (event_id, current_user_id))
        db_connection.commit()

        if cursor.rowcount > 0:
            flash("Successfully removed your volunteer sign-up.", 'success')
            app.logger.info(f"User {current_user_id} removed volunteer sign-up for event {event_id}.") # A09:2021-Security Logging
        else:
            flash("No volunteer sign-up found for this event to remove.", 'warning')

    except mysql.connector.Error as err:
        app.logger.error(f"Error removing volunteer sign-up for event {event_id} by user {current_user_id}: {err}")
        flash(f"Error removing volunteer sign-up: An unexpected database error occurred.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(url_for('event_details', event_id=event_id))


# --- API Endpoint for FullCalendar.js ---
@app.route('/api/my_events')
@login_required # Ensure API endpoint requires login
def api_my_events():
    current_user_id = g.user
    current_username = g.username

    events = []
    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        # A03:2021-Injection: Parameterized UNION query
        query = """
            SELECT uce.username AS signup_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue
            FROM user_calendar_events uce
            JOIN event e ON uce.event_id = e.EventID
            WHERE uce.user_id = %s

            UNION

            SELECT %s AS signup_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue
            FROM event_volunteers ev
            JOIN event e ON ev.event_id = e.EventID
            WHERE ev.user_id = %s

            ORDER BY Date, Time
        """
        cursor.execute(query, (current_user_id, current_username, current_user_id))
        signed_up_events_raw = cursor.fetchall()

        for event_data in signed_up_events_raw:
            event_date_obj = event_data['Date']
            event_time_str = event_data['Time']

            start_time_obj, end_time_obj = parse_time_range(event_time_str)

            start_datetime = datetime.combine(event_date_obj, start_time_obj)
            end_datetime = datetime.combine(event_date_obj, end_time_obj)

            if end_datetime < start_datetime:
                end_datetime += timedelta(days=1)

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
        app.logger.error(f"Error fetching events for API for user {current_user_id}: {err}")
        return jsonify({"error": "Failed to load events"}), 500
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return jsonify(events)


@app.route('/calendar')
@login_required # Ensure calendar requires login
def calendar():
    current_user_id = g.user
    current_username = g.username

    db_connection = None
    cursor = None
    signed_up_events = []

    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        # A03:2021-Injection: Parameterized UNION query
        query = """
            SELECT uce.username AS event_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue, e.Category
            FROM user_calendar_events uce
            JOIN event e ON uce.event_id = e.EventID
            WHERE uce.user_id = %s

            UNION

            SELECT %s AS event_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue, e.Category
            FROM event_volunteers ev
            JOIN event e ON ev.event_id = e.EventID
            WHERE ev.user_id = %s

            ORDER BY Date ASC, Time ASC
        """
        cursor.execute(query, (current_user_id, current_username, current_user_id))
        signed_up_events = cursor.fetchall()

    except mysql.connector.Error as err:
        app.logger.error(f"Error fetching signed up events for calendar for user {current_user_id}: {err}")
        flash(f"Error loading your events list: An unexpected database error occurred.", 'error')
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('calendar.html', signed_up_events=signed_up_events, user_id=current_user_id)


# --- Helper function to parse time strings ---
# A04:2021-Insecure Design / A08:2021-Software and Data Integrity Failures: Robust input parsing
def parse_time_range(time_str):
    """
    Parses a time range string (e.g., "9am-12pm", "10:00-11:00") into
    start and end datetime.time objects. Improved error handling and validation.
    """
    try:
        parts = time_str.split('-')
        if not (1 <= len(parts) <= 2):
            raise ValueError("Time string format incorrect.")

        start_time_str = parts[0].strip()
        end_time_str = parts[1].strip() if len(parts) > 1 else None

        def convert_to_24hr_format(t_str_raw):
            t_str = t_str_raw.lower().replace('.', '').replace(' ', '')

            # Full 24-hour format (e.g., 09:30, 14:00)
            if re.match(r'^\d{1,2}:\d{2}$', t_str):
                return datetime.strptime(t_str, '%H:%M').strftime('%H:%M')

            # 12-hour format with am/pm
            if 'am' in t_str or 'pm' in t_str:
                if ':' in t_str: # e.g., 9:30am, 1:30pm
                    return datetime.strptime(t_str, '%I:%M%p').strftime('%H:%M')
                else: # e.g., 9am, 1pm
                    # Handle cases like "12am" (midnight)
                    if t_str == '12am':
                        return '00:00'
                    # Handle cases like "12pm" (noon)
                    elif t_str == '12pm':
                        return '12:00'
                    return datetime.strptime(t_str, '%I%p').strftime('%H:%M')
            else:
                # Assume HH or HH:MM (24-hour, no am/pm)
                if ':' in t_str:
                    return datetime.strptime(t_str, '%H:%M').strftime('%H:%M')
                else: # Assume just hour (e.g., "9", "14")
                    return datetime.strptime(t_str, '%H').strftime('%H:%M')

        start_24hr = convert_to_24hr_format(start_time_str)
        start_dt_time = datetime.strptime(start_24hr, '%H:%M').time()

        end_dt_time = None
        if end_time_str:
            end_24hr = convert_to_24hr_format(end_time_str)
            end_dt_time = datetime.strptime(end_24hr, '%H:%M').time()
        else:
            # If no end time, assume a default duration, e.g., 1 hour
            start_dt = datetime.combine(datetime.min.date(), start_dt_time)
            end_dt_time = (start_dt + timedelta(hours=1)).time()

        return start_dt_time, end_dt_time

    except Exception as e:
        app.logger.error(f"Failed to parse time string '{time_str}'. Defaulting. Error: {e}")
        # A09:2021-Security Logging: Log parsing failures.
        return time(0, 0), time(23, 59) # Default to full day if parsing fails

@app.route('/usereventpage')
@login_required # Ensure this page requires login
def usereventpage():
    db_connection = None
    cursor = None
    events = []

    try:
        db_connection = get_db_connection()
        cursor = db_connection.cursor(dictionary=True)

        query = "SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event ORDER BY Date ASC, Time ASC"
        cursor.execute(query) # No user input, so no %s needed here
        events = cursor.fetchall()

    except mysql.connector.Error as err:
        app.logger.error(f"Error fetching all events for usereventpage: {err}")
        flash(f"Error loading events: An unexpected database error occurred.", 'error')
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('usereventpage.html', events=events)

@app.route('/chat')
@login_required # Ensure chat requires login
def chat():
    """
    Renders the chatbot page.
    This page will contain JavaScript to send messages to the /api/chat endpoint.
    """
    return render_template('chat.html', openai_api_key=os.environ.get("OPENAI_API_KEY"))
    # A06:2021-Vulnerable and Outdated Components: Ensure your OpenAI library is up-to-date.
    # A10:2021-Server-Side Request Forgery (SSRF): The actual API call to OpenAI should happen server-side,
    # not directly from client-side JavaScript if you are passing the API key to the client.
    # If client-side JS directly uses OPENAI_API_KEY, this is a severe security risk.
    # It's better to have a server-side endpoint that makes the call.
    # If not OPENAI_API_KEY:
    #     flash("Chatbot is not available due to missing API key.", "warning")
    #     return redirect(url_for('home')) # Or render a specific error page
    # return render_template('chat.html', openai_api_key="PUBLIC_FACING_KEY_IF_ANY" if not OPENAI_API_KEY else "KEY_REDACTED_FOR_CLIENT")


@app.route('/events')
@login_required
def events():
    conn = None
    cursor = None
    events = []
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute("SELECT * FROM event;")
        events = cursor.fetchall()
    except Exception as e:
        app.logger.error(f"Error fetching events: {e}")
        flash("Failed to load events.", "error")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
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
@role_required(['admin'])
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

  
@app.route('/admin/events/add', methods=['GET', 'POST'])
def add_event():
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
        'title': event['title'],
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
        cursor.close()
        conn.close()
        return redirect(url_for('admin_event_details', event_id=event_id, delete_error="Authentication failed. Please try again."))

    # Delete event
    cursor.execute("DELETE FROM Events WHERE event_id = %s", (event_id,))
    conn.commit()
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
        return redirect(url_for('admin_event_details', event_id=event_id))

    if not allowed_file(file.filename):
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


@app.route('/logout')
@login_required # Only logged-in users can log out
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    app.logger.info(f"User {g.user} logged out.") # A09:2021-Security Logging
    return redirect(url_for('login'))

@app.route('/cancel_login')
def cancel_login():
    """Allow users to cancel the login process if they're stuck in security questions or OTP verification"""
    if session.get('login_step') in ['password_verified', 'otp_required']:
        session.clear()
        flash("Login cancelled. Please try again.", "info")
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/error')
def error(): 
    # A11:2021-Software and Data Integrity Failures: This route should handle errors gracefully.
    # It can be used to render a custom error page.
    return render_template('error.html', message="An unexpected error occurred. Please try again later.")


if __name__ == '__main__':
    # A05:2021-Security Misconfiguration: Never run with debug=True in production.
    # Debug mode can expose sensitive information and allow arbitrary code execution.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='127.0.0.1', port=5000) # Use 0.0.0.0 to make it accessible in container/VM, but bind to specific IP in production if possible