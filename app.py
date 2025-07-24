import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
import mysql.connector
from datetime import datetime, timedelta, date, time
import openai
import uuid
from openai import OpenAI
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash # For secure password hashing

# --- Flask Application Setup ---
app = Flask(__name__)

# --- Flask Secret Key Configuration ---
# CRITICAL: Set a strong, unique secret key via environment variable for production.
# This is vital for session security.
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    print("WARNING: FLASK_SECRET_KEY environment variable not set. Using a fallback, which is INSECURE for production!")
    app.secret_key = 'a_very_insecure_fallback_key_for_dev_only_please_change'

# --- MySQL Database Configuration from Environment Variables ---
DB_HOST = os.getenv('DB_HOST')
DB_PORT = int(os.getenv('DB_PORT', 3306)) # Default MySQL port if not specified
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

# --- OpenAI API Key Configuration ---
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
openai_client = None # Initialize to None

if OPENAI_API_KEY:
    try:
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        print("OpenAI client initialized successfully.")
    except Exception as e:
        print(f"Error initializing OpenAI client: {e}")
        print("Chatbot functionality may be impaired.")
else:
    print("WARNING: OPENAI_API_KEY environment variable not set. Chatbot functionality will be unavailable.")

# --- Critical Database Variable Check ---
if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
    print("ERROR: One or more critical database environment variables (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) are not set.")
    print("Please ensure your .env file is correctly configured and located in the project root.")
    # In a production app, you might want to raise an exception or exit here.
    # import sys
    # sys.exit(1)

# --- DEMONSTRATION ADMIN & USER CREDENTIALS (!!! INSECURE FOR PRODUCTION !!!) ---
# This is for testing the admin access control. In a real application,
# users (including admins) MUST be stored in a database with their passwords
# securely hashed (e.g., using Flask-Bcrypt).
MOCK_ADMIN_USERNAME = os.getenv('DEMO_ADMIN_USERNAME', 'admin')
MOCK_ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv('DEMO_ADMIN_PASSWORD', 'adminpass'))

MOCK_USER_USERNAME = os.getenv('DEMO_USER_USERNAME', 'user')
MOCK_USER_PASSWORD_HASH = generate_password_hash(os.getenv('DEMO_USER_PASSWORD', 'userpass'))
# --- END OF DEMONSTRATION CREDENTIALS ---


# --- Helper functions for database connection ---
def get_db_connection():
    """Establishes and returns a new database connection."""
    try:
        return mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        # In a real app, log this error more formally (e.g., to a file or monitoring service)
        return None # Return None on connection failure

def get_db_cursor(conn):
    """Returns a dictionary cursor for the given connection."""
    if conn:
        return conn.cursor(dictionary=True)
    return None

# --- Before Request: Load user from session or assign guest ---
@app.before_request
def load_user_data():
    """
    Loads user data from the session if available, otherwise assigns a unique guest user.
    This ensures `g.user` is always populated for every request.
    """
    user_id = session.get('user_id')
    username = session.get('username')
    role = session.get('role')

    if user_id and username and role:
        # User is logged in
        g.user = {'id': user_id, 'username': username, 'role': role}
    else:
        # Assign a guest user if no session or incomplete session
        # Ensure a unique ID for each guest session if not already set,
        # or if a real user logged out and guest state needs re-initialization.
        if 'user_id' not in session or session.get('username') != 'guest':
            session['user_id'] = str(uuid.uuid4()) # Unique ID for guests
            session['username'] = 'guest'
            session['role'] = 'user' # Guests have a 'user' role by default

        g.user = {
            'id': session['user_id'],
            'username': session['username'],
            'role': session['role']
        }
    # For debugging: print(f"Current g.user: {g.user}")


# --- Decorator for Role-Based Access Control ---
def role_required(required_role):
    """
    Decorator to restrict access to routes based on user role.
    Redirects to login if not authenticated or to home/error if not authorized.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # If the user is a guest AND the required role is not just a standard 'user' (which guests are)
            if g.user['role'] == 'guest' and required_role != 'user':
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('login'))

            # Check if the user has the required role
            if g.user['role'] != required_role:
                flash('You do not have permission to access this page.', 'error')
                # Decide where to redirect unauthorized users (e.g., home, or an error page)
                return redirect(url_for('home')) # Or abort(403) for Forbidden response

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # --- Input Validation for Login ---
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        # Basic length validation (adjust as needed)
        if len(username) < 3 or len(password) < 6:
            flash('Username must be at least 3 characters and password at least 6 characters.', 'error')
            return render_template('login.html')
        # --- End Input Validation ---

        # --- !!! INSECURE DEMONSTRATION LOGIN - REPLACE WITH DB AUTHENTICATION !!! ---
        # In a real application:
        # 1. Query your 'users' table for the username.
        # 2. If user exists, use check_password_hash(user.password_hash, password)
        #    to verify the password.
        # 3. Store user.id, user.username, user.role in the session.
        # 4. Handle user not found or incorrect password.
        if username == MOCK_ADMIN_USERNAME and check_password_hash(MOCK_ADMIN_PASSWORD_HASH, password):
            session['user_id'] = 'admin_user_unique_id_123' # Use a real unique ID from DB
            session['username'] = MOCK_ADMIN_USERNAME
            session['role'] = 'admin'
            flash('Logged in successfully as Admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        elif username == MOCK_USER_USERNAME and check_password_hash(MOCK_USER_PASSWORD_HASH, password):
            session['user_id'] = 'regular_user_unique_id_456' # Use a real unique ID from DB
            session['username'] = MOCK_USER_USERNAME
            session['role'] = 'user'
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'error')
        # --- END OF INSECURE DEMONSTRATION LOGIN ---

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/signup', endpoint='signup')
def signup():
    """
    Placeholder for user registration.
    In a real app, this would handle new user registration POST request,
    including hashing passwords and storing them in the database.
    """
    flash("User registration is not fully implemented in this demo. Please use the demo credentials to test login:", 'info')
    flash(f"Admin: Username '{MOCK_ADMIN_USERNAME}', Password '{os.getenv('DEMO_ADMIN_PASSWORD', 'adminpass')}'", 'info')
    flash(f"User: Username '{MOCK_USER_USERNAME}', Password '{os.getenv('DEMO_USER_PASSWORD', 'userpass')}'", 'info')
    return render_template('signup.html')


# --- Main Application Routes ---
@app.route('/')
def home():
    """
    Renders the home page of the application.
    """
    return render_template('home.html')

@app.route('/eventdetails/<int:event_id>')
def event_details(event_id):
    """
    Connects to the MySQL database, fetches data for a specific event by ID,
    and renders it in an HTML template. It also checks if the current user
    has already signed up for this event and if they are a volunteer for it.
    """
    db_connection = None
    cursor = None
    event = None
    has_signed_up = False
    is_volunteer_for_event = False

    current_user_id = g.user['id']
    current_user_role = g.user['role']

    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return render_template('error.html', message="Failed to load event details.")

        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return render_template('error.html', message="Failed to load event details.")

        cursor.execute("SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event WHERE EventID = %s", (event_id,))
        event = cursor.fetchone()

        if not event:
            flash(f"No event found with ID {event_id}.", 'error')
            return redirect(url_for('usereventpage')) # Redirect to a list of events

        # Check if user has signed up
        check_signup_query = "SELECT COUNT(*) FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_signup_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            has_signed_up = True

        # Check if user is a volunteer (only for 'user' roles, including guests)
        if current_user_role == 'user':
            check_volunteer_query = "SELECT COUNT(*) FROM event_volunteers WHERE event_id = %s AND user_id = %s"
            cursor.execute(check_volunteer_query, (event_id, current_user_id))
            if cursor.fetchone()['COUNT(*)'] > 0:
                is_volunteer_for_event = True

    except mysql.connector.Error as err:
        print(f"Database error in event_details: {err}")
        flash(f"Database error loading event details. Please try again later.", 'error')
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
    Includes input validation for event_id.
    """
    event_id_str = request.form.get('event_id')
    current_user_id = g.user['id']
    current_username = g.user['username']
    redirect_url = url_for('usereventpage') # Default redirect in case of error

    # --- Input Validation ---
    if not event_id_str:
        flash("Event ID is missing for sign-up.", 'error')
        return redirect(redirect_url)
    try:
        event_id = int(event_id_str)
        redirect_url = url_for('event_details', event_id=event_id) # Set for valid ID
    except ValueError:
        flash("Invalid Event ID format provided.", 'error')
        return redirect(redirect_url)
    # --- End Input Validation ---

    # Prevent admins from signing up as regular users
    if g.user['role'] == 'admin':
        flash("Admins cannot sign up for events as regular users.", 'warning')
        return redirect(redirect_url)

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return redirect(redirect_url)
        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return redirect(redirect_url)

        # Check if event exists (Good practice to avoid signing up for non-existent events)
        cursor.execute("SELECT EventID FROM event WHERE EventID = %s", (event_id,))
        if not cursor.fetchone():
            flash("Event not found. Cannot sign up.", 'error')
            return redirect(redirect_url)

        # Check if already signed up
        check_signup_query = "SELECT COUNT(*) FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_signup_query, (event_id, current_user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash(f"You have already signed up for this event.", 'warning')
            return redirect(redirect_url)

        insert_query = "INSERT INTO user_calendar_events (event_id, user_id, username) VALUES (%s, %s, %s)"
        cursor.execute(insert_query, (event_id, current_user_id, current_username))
        db_connection.commit()

        flash(f"Successfully signed up for the event!", 'success')

    except mysql.connector.Error as err:
        print(f"Error signing up for event: {err}")
        flash(f"Database error during sign-up. Please try again later.", 'error')
        if db_connection: db_connection.rollback() # Rollback on error
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(redirect_url)

@app.route('/remove_sign_up', methods=['POST'])
def remove_sign_up():
    """
    Handles removing a user's (or guest's) sign-up for an event.
    Includes input validation for event_id.
    """
    event_id_str = request.form.get('event_id')
    current_user_id = g.user['id']
    redirect_url = url_for('usereventpage') # Default redirect

    # --- Input Validation ---
    if not event_id_str:
        flash("Event ID is missing for sign-up removal.", 'error')
        return redirect(redirect_url)
    try:
        event_id = int(event_id_str)
        redirect_url = url_for('event_details', event_id=event_id) # Set for valid ID
    except ValueError:
        flash("Invalid Event ID format provided.", 'error')
        return redirect(redirect_url)
    # --- End Input Validation ---

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return redirect(redirect_url)
        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return redirect(redirect_url)

        delete_query = "DELETE FROM user_calendar_events WHERE event_id = %s AND user_id = %s"
        cursor.execute(delete_query, (event_id, current_user_id))
        db_connection.commit()

        if cursor.rowcount > 0:
            flash(f"Event sign-up removed successfully!", 'success')
        else:
            flash(f"No sign-up found for this event to remove.", 'warning')

    except mysql.connector.Error as err:
        print(f"Error removing event sign-up: {err}")
        flash(f"Database error removing sign-up. Please try again later.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(redirect_url)

@app.route('/volunteer_for_event', methods=['POST'])
def volunteer_for_event():
    """
    Handles a user signing up to help at an event.
    Includes input validation for event_id.
    """
    event_id_str = request.form.get('event_id')
    user_id = g.user['id'] # The current guest or logged-in user ID
    redirect_url = url_for('usereventpage') # Default redirect

    # --- Input Validation ---
    if not event_id_str:
        flash("Event ID is missing for volunteering.", 'error')
        return redirect(redirect_url)
    try:
        event_id = int(event_id_str)
        redirect_url = url_for('event_details', event_id=event_id) # Set for valid ID
    except ValueError:
        flash("Invalid Event ID format provided.", 'error')
        return redirect(redirect_url)
    # --- End Input Validation ---

    if g.user['role'] == 'admin':
        flash("Admins cannot volunteer for events.", 'warning')
        return redirect(redirect_url)

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return redirect(redirect_url)
        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return redirect(redirect_url)

        # Check if event exists
        cursor.execute("SELECT EventID FROM event WHERE EventID = %s", (event_id,))
        if not cursor.fetchone():
            flash("Event not found. Cannot volunteer.", 'error')
            return redirect(redirect_url)

        # Check if already volunteered
        check_query = "SELECT COUNT(*) FROM event_volunteers WHERE event_id = %s AND user_id = %s"
        cursor.execute(check_query, (event_id, user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash("You have already volunteered for this event.", 'warning')
            return redirect(redirect_url)

        insert_query = "INSERT INTO event_volunteers (event_id, user_id) VALUES (%s, %s)"
        cursor.execute(insert_query, (event_id, user_id))
        db_connection.commit()
        flash("Successfully signed up to volunteer for the event!", 'success')

    except mysql.connector.Error as err:
        print(f"Error volunteering for event: {err}")
        flash(f"Database error during volunteering. Please try again later.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(redirect_url)

@app.route('/remove_volunteer', methods=['POST'])
def remove_volunteer():
    """
    Handles a user removing their sign-up to help at an event.
    Includes input validation for event_id.
    """
    event_id_str = request.form.get('event_id')
    user_id = g.user['id']
    redirect_url = url_for('usereventpage') # Default redirect

    # --- Input Validation ---
    if not event_id_str:
        flash("Event ID is missing for volunteer removal.", 'error')
        return redirect(redirect_url)
    try:
        event_id = int(event_id_str)
        redirect_url = url_for('event_details', event_id=event_id) # Set for valid ID
    except ValueError:
        flash("Invalid Event ID format provided.", 'error')
        return redirect(redirect_url)
    # --- End Input Validation ---

    if g.user['role'] == 'admin':
        flash("Admins cannot remove volunteer sign-ups they didn't make.", 'warning')
        return redirect(redirect_url)

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return redirect(redirect_url)
        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return redirect(redirect_url)

        delete_query = "DELETE FROM event_volunteers WHERE event_id = %s AND user_id = %s"
        cursor.execute(delete_query, (event_id, user_id))
        db_connection.commit()

        if cursor.rowcount > 0:
            flash("Successfully removed your volunteer sign-up.", 'success')
        else:
            flash("No volunteer sign-up found for this event to remove.", 'warning')

    except mysql.connector.Error as err:
        print(f"Error removing volunteer sign-up: {err}")
        flash(f"Database error removing volunteer sign-up. Please try again later.", 'error')
        if db_connection: db_connection.rollback()
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return redirect(redirect_url)


# --- API Endpoint for FullCalendar.js ---
@app.route('/api/my_events')
def api_my_events():
    """
    Returns the current user's signed-up events and volunteered events
    in a JSON format suitable for FullCalendar.js.
    """
    current_user_id = g.user['id']
    current_username = g.user['username']
    events = []

    db_connection = None
    cursor = None
    try:
        db_connection = get_db_connection()
        if not db_connection:
            return jsonify({"error": "Failed to connect to database for events."}), 500
        cursor = get_db_cursor(db_connection)
        if not cursor:
            return jsonify({"error": "Failed to get database cursor for events."}), 500

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

            # Use helper to parse time
            start_time_obj, end_time_obj = parse_time_range(event_time_str)

            # Combine date and time for full datetime objects
            start_datetime = datetime.combine(event_date_obj, start_time_obj)
            # If end time is before start time (e.g., 10 PM - 2 AM), it means next day
            end_datetime = datetime.combine(event_date_obj, end_time_obj)
            if end_datetime < start_datetime:
                end_datetime += timedelta(days=1)

            # Display title includes the username (XSS protection handled by Jinja2 auto-escaping on render)
            display_title = f"{event_data['EventDescription']} ({event_data['signup_username']})"

            events.append({
                'id': event_data['EventID'],
                'title': display_title,
                'start': start_datetime.isoformat(),
                'end': end_datetime.isoformat(),
                'allDay': False,
                'url': url_for('event_details', event_id=event_data['EventID']) # Ensure URL is safe
            })

    except mysql.connector.Error as err:
        print(f"Error fetching events for API: {err}")
        return jsonify({"error": "Failed to load events from database."}), 500
    except Exception as e:
        print(f"Unexpected error in api_my_events: {e}")
        return jsonify({"error": "An unexpected error occurred loading events."}), 500
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
    current_user_id = g.user['id']
    current_username = g.user['username']
    db_connection = None
    cursor = None
    signed_up_events = []

    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return render_template('calendar.html', signed_up_events=[], user_id=current_user_id)
        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return render_template('calendar.html', signed_up_events=[], user_id=current_user_id)

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
        flash(f"Database error loading your events list: {err}", 'error')
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('calendar.html', signed_up_events=signed_up_events, user_id=current_user_id)


# --- Helper function to parse time strings like "9am-12pm" or "10:00-11:00" ---
def parse_time_range(time_str):
    """
    Parses a time range string (e.g., "9am-12pm", "10:00-11:00") into
    start and end datetime.time objects. Provides robust error handling.
    """
    if not isinstance(time_str, str) or not time_str.strip():
        # Handle empty or non-string input gracefully
        print(f"Warning: Invalid time string input: '{time_str}'. Defaulting to full day.")
        return time(0, 0), time(23, 59) # Default to full day

    try:
        parts = time_str.split('-')
        start_time_str = parts[0].strip()
        end_time_str = parts[1].strip() if len(parts) > 1 else None

        def convert_to_24hr_format(t_s):
            t_s = t_s.lower().replace('.', '')
            try:
                if 'am' in t_s:
                    t_s = t_s.replace('am', '')
                    return datetime.strptime(t_s, '%I:%M').strftime('%H:%M') if ':' in t_s else datetime.strptime(t_s, '%I').strftime('%H:%M')
                elif 'pm' in t_s:
                    t_s = t_s.replace('pm', '')
                    dt_obj = datetime.strptime(t_s, '%I:%M') if ':' in t_s else datetime.strptime(t_s, '%I')
                    return (dt_obj + timedelta(hours=12)).strftime('%H:%M') if dt_obj.hour != 12 else dt_obj.strftime('%H:%M') # Handle 12PM correctly
                elif ':' in t_s:
                    return datetime.strptime(t_s, '%H:%M').strftime('%H:%M') # Assume 24-hour or 12-hour without am/pm
                else:
                    return datetime.strptime(t_s, '%H').strftime('%H:%M') # Assume just hour in 24-hour
            except ValueError:
                raise ValueError(f"Could not parse time part: '{t_s}'")

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
        print(f"Warning: Could not parse time string '{time_str}'. Error: {e}. Defaulting to full day.")
        return time(0, 0), time(23, 59) # Default to full day if parsing fails


@app.route('/usereventpage')
def usereventpage():
    """
    Renders a user event page, showing all available events.
    """
    db_connection = None
    cursor = None
    events = []

    try:
        db_connection = get_db_connection()
        if not db_connection:
            flash("Failed to connect to the database.", 'error')
            return render_template('usereventpage.html', events=[])
        cursor = get_db_cursor(db_connection)
        if not cursor:
            flash("Failed to get database cursor.", 'error')
            return render_template('usereventpage.html', events=[])

        query = "SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event ORDER BY Date ASC, Time ASC"
        cursor.execute(query)
        events = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Error fetching all events for usereventpage: {err}")
        flash(f"Database error loading events: {err}", 'error')
    finally:
        if cursor: cursor.close()
        if db_connection: db_connection.close()

    return render_template('usereventpage.html', events=events)

@app.route('/chat')
def chat():
    """
    Renders the chatbot page.
    This page will contain JavaScript to send messages to the /api/chat endpoint.
    """
    return render_template('chat.html', openai_api_key=OPENAI_API_KEY)

@app.route('/events')
def events():
    """
    Renders a generic events page, likely for displaying all events without user context.
    """
    conn = get_db_connection()
    if not conn:
        flash("Failed to connect to the database to load events.", 'error')
        return render_template('events.html', events=[])
    cursor = get_db_cursor(conn)
    if not cursor:
        flash("Failed to get database cursor to load events.", 'error')
        conn.close()
        return render_template('events.html', events=[])

    try:
        cursor.execute("SELECT * FROM event;")
        events = cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Error fetching all events for generic events page: {err}")
        flash(f"Database error loading events: {err}", 'error')
        events = [] # Ensure events is always a list
    finally:
        cursor.close()
        conn.close()
    return render_template('events.html', events=events)


@app.route('/mfa')
def mfa():
    """
    Renders the Multi-Factor Authentication page.
    (Functionality for MFA is not implemented in this demo)
    """
    flash("MFA functionality is a placeholder and not implemented.", 'info')
    return render_template('mfa.html')

# --- Admin Routes (Protected by role_required decorator) ---
@app.route('/admin')
@role_required(required_role='admin')
def admin_dashboard():
    """
    Renders the admin dashboard page, accessible only to users with 'admin' role.
    """
    flash(f"Welcome, {g.user['username']}! You are in the admin dashboard.", 'success')
    return render_template('admin.html')

@app.route('/admin/accounts')
@role_required(required_role='admin')
def account_management():
    """
    Renders the account management page, accessible only to users with 'admin' role.
    (Placeholder functionality)
    """
    flash("This is the Account Management page. (Not fully implemented in this demo)", 'info')
    return render_template('acc_management.html')

@app.route('/admin/events')
@role_required(required_role='admin')
def admin_events():
    """
    Renders the admin event management page, accessible only to users with 'admin' role.
    (Placeholder functionality)
    """
    flash("This is the Admin Event Management page. (Not fully implemented in this demo)", 'info')
    return render_template('admin_events.html')

# --- API Endpoint for Chatbot ---
@app.route('/api/chat', methods=['POST'])
def api_chat():
    """
    Handles chat messages from the frontend, sends them to OpenAI,
    and returns the chatbot's response.
    Includes input validation for the message.
    """
    if not openai_client:
        return jsonify({"error": "Chatbot is not configured. Missing API key or initialization error."}), 503 # Service Unavailable

    user_message = request.json.get('message')

    # --- Input Validation for Chat Message ---
    if not user_message or not isinstance(user_message, str) or not user_message.strip():
        return jsonify({"error": "No message provided or message is invalid."}), 400
    if len(user_message) > 500: # Example max length
        return jsonify({"error": "Message too long."}), 400
    # --- End Input Validation ---

    try:
        # Example using OpenAI's chat completions API
        response = openai_client.chat.com.create(
            model="gpt-3.5-turbo", # Or "gpt-4", etc.
            messages=[
                {"role": "system", "content": "You are a helpful assistant for event management. Provide concise answers."},
                {"role": "user", "content": user_message}
            ]
        )
        chatbot_response = response.choices[0].message.content
        return jsonify({"response": chatbot_response})

    except openai.OpenAIError as e:
        # Catch specific OpenAI API errors
        print(f"OpenAI API Error: {e}")
        return jsonify({"error": f"AI service error: {e}"}), 500
    except Exception as e:
        print(f"Unexpected error in api_chat: {e}")
        return jsonify({"error": f"An unexpected error occurred with the chatbot."}), 500

@app.route('/support')
def support():
    """
    Renders the support page with contact information.
    """
    return render_template('support.html')

# --- Main entry point for running the Flask app ---
if __name__ == '__main__':
    # When debug is True, Flask automatically reloads on code changes
    # and provides a debugger in the browser. NEVER use debug=True in production.
    app.run(debug=True)