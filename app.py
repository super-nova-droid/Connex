import mysql.connector
from datetime import datetime, timedelta, time, date
from dotenv import load_dotenv
import os
from math import ceil
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash,generate_password_hash
from authlib.integrations.flask_client import OAuth
from flask_dance.contrib.google import make_google_blueprint, google
from connexmail import send_otp_email
import random
from flask import redirect
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Allow insecure transport for OAuth (not recommended for production)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
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
        email = request.form.get('email', '').strip() # A03:2021-Injection: Sanitize input by stripping whitespace
        password = request.form.get('password', '').strip()

        # A07:2021-Identification and Authentication Failures: Basic input validation
        if not email or not password:
            flash('Email and password are required.', 'error')
            return render_template('login.html')

        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = get_db_cursor(conn)
            # A03:2021-Injection: Parameterized query prevents SQL injection
            cursor.execute("SELECT user_id, username, password, role FROM Users WHERE email = %s", (email,))
            user = cursor.fetchone()

            # A07:2021-Identification and Authentication Failures: Generic error message for login
            # This prevents user enumeration.
            if user and check_password_hash(user['password'], password):
                session.clear() # Clear existing session to prevent session fixation
                session['user_id'] = user['user_id']
                session['user_role'] = user['role']
                session['user_name'] = user['username']
                # A07:2021-Identification and Authentication Failures: Regenerate session ID on successful login
                session.sid = os.urandom(24).hex() # Flask handles this automatically with 'session.regenerate_id()' in newer versions.
                                                  # For older versions or explicit control, you might do this or use Flask-Login.

                app.logger.info(f"User {user['username']} ({user['role']}) logged in successfully.")

                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'volunteer':
                    return redirect(url_for('volunteer_dashboard'))
                elif user['role'] == 'elderly':
                    return redirect(url_for('home'))
            else:
                flash('Invalid email or password.', 'error')
                app.logger.warning(f"Failed login attempt for email: {email}") # A09:2021-Security Logging
        except Exception as e:
            app.logger.error(f"Login error for email {email}: {e}")
            flash("An unexpected error occurred during login. Please try again.", "error")
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():

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

    if request.method == 'POST':
        # Store form data in session, do NOT insert into DB yet
        session['pending_signup'] = {
            'username': request.form['username'],
            'password': request.form['password'],
            'confirm_password': request.form['confirm_password'],
            'email': request.form['email'],
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
            # Check if email already exists
            cursor.execute("SELECT * FROM Users WHERE email = %s", (session['pending_signup']['email'],))
            existing_email = cursor.fetchone()
            cursor.fetchall()  # Consume any remaining results

            # Check if username already exists
            cursor.execute("SELECT * FROM Users WHERE username = %s", (session['pending_signup']['username'],))
            existing_username = cursor.fetchone()
            cursor.fetchall()  # Consume any remaining results

            if existing_email and existing_username:
                flash("Both email and username are already registered.", "error")
                # Clear session data
                session.pop('pending_signup', None)
                return redirect(url_for('signup'))
            elif existing_email:
                flash("Email is already registered.", "error")
                # Clear session data
                session.pop('pending_signup', None)
                return redirect(url_for('signup'))
            elif existing_username:
                flash("Username is already taken.", "error")
                # Clear session data
                session.pop('pending_signup', None)
                return redirect(url_for('signup'))

            otp = str(random.randint(100000, 999999))
            session['otp_email'] = session['pending_signup']['email']
            session['otp_code'] = otp
            session['otp_verified'] = False

            send_otp_email(session['pending_signup']['email'], otp)

            flash("Please verify your email with the OTP sent.", "info")
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash("An error occurred during signup. Please try again.", "error")
            print(f"Error: {e}")
            # Clear session data
            session.pop('pending_signup', None)
            return redirect(url_for('signup'))
        finally:
            cursor.close()
            conn.close()

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
                    INSERT INTO Users (username, email, password, dob, location_id, role)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (name, email, hashed_password, dob, location_id, role))
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
        new_otp = str(random.randint(100000, 999999))
        session['otp_code'] = new_otp
        
        # Send the new OTP to the same email
        send_otp_email(session['otp_email'], new_otp)
        
        flash("A new OTP has been sent to your email.", "info")
    except Exception as e:
        flash("Failed to resend OTP. Please try again.", "error")
        print(f"Error resending OTP: {e}")
    
    return redirect(url_for('verify_otp'))

@app.route('/mfa')
def mfa():
    # A07:2021-Identification and Authentication Failures: Placeholder for MFA implementation.
    # This route should be part of a robust MFA flow (e.g., after successful password verification).
    flash("MFA integration is a critical security step for production applications.", "info")
    return render_template('mfa.html')

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
        # The query has been updated to use the new table name 'Events' and
        # new column names, aliasing them to the old names to maintain compatibility
        # with the template. A placeholder for 'Time' has been added as it is not
        # present in the new schema.
        cursor.execute("SELECT event_id , description, Title, event_date, location_name, category, image, Time FROM Events WHERE event_id = %s", (event_id,))
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
            cursor.execute("SELECT COUNT(*) FROM Event_detail WHERE event_id = %s AND user_id = %s", (event_id, current_user_id))
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
    if current_user_role not in ['volunteer', 'admin']: # Re-evaluate this business logic
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

        cursor.execute("SELECT COUNT(*) FROM Event_detail WHERE event_id = %s AND user_id = %s", (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash("You have already volunteered for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO Event_detail (event_id, user_id, signup_type) VALUES (%s, %s, 'volunteer')"
        cursor.execute(insert_query, (event_id, current_user_id, 'volunteer' ))
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

        delete_query = "DELETE FROM Event_detail WHERE event_id = %s AND user_id = %s AND signup_type = 'volunteer'"
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

        query = "SELECT event_id, description, Title, event_date, location_name, category, image, Time FROM Events ORDER BY event_date, Time"
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
        all_locations=all_locations)

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

@app.route('/logout')
@login_required # Only logged-in users can log out
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    app.logger.info(f"User {g.user} logged out.") # A09:2021-Security Logging
    return redirect(url_for('login'))

if __name__ == '__main__':
    # A05:2021-Security Misconfiguration: Never run with debug=True in production.
    # Debug mode can expose sensitive information and allow arbitrary code execution.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    app.run(debug=True, host='127.0.0.1', port=5000) # Use 0.0.0.0 to make it accessible in container/VM, but bind to specific IP in production if possible