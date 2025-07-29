from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
from math import ceil
import mysql.connector
from datetime import datetime, timedelta, time,date
from dotenv import load_dotenv
from opencage.geocoder import OpenCageGeocode
import os
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename


load_dotenv()  # Load environment variables from .env file

# --- Database config (replace with your actual config or import from config file) ---
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = int(os.environ.get('DB_PORT', 3306))

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY') 
if not OPENAI_API_KEY:
    print("WARNING: OPENAI_API_KEY environment variable is not set. Chatbot may not function.")
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_secret_key')  # Use a secure secret key in production

api_key = os.getenv('OPEN_CAGE_API_KEY')
geocoder = OpenCageGeocode(api_key)

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
    
# --- Helper functions for /events route ---
def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
    )

def get_db_cursor(conn):
    return conn.cursor(dictionary=True)

# --- Set up g.user for sessionless/guest users ---
@app.before_request
def load_logged_in_user():
    g.user = session.get('user_id')
    g.role = session.get('user_role')
    g.username = session.get('user_name')

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
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['user_id']
            session['user_role'] = user['role']
            session['user_name'] = user['username']

            # Role-based redirection
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'volunteer':
                return redirect(url_for('volunteer_dashboard'))
            elif user['role'] == 'elderly':
                return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT location_id, location_name, address FROM Locations")
    locations = cursor.fetchall()

    if request.method == 'POST':
        name = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        email = request.form['email']
        dob = request.form['dob']
        location_id = request.form['location_id']  # Updated
        is_volunteer = 'is_volunteer' in request.form

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        role = 'volunteer' if is_volunteer else 'elderly'

        try:
            cursor.execute("""
                INSERT INTO Users (username, email, password, dob, role, location_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, email, hashed_password, dob, role, location_id))

            conn.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            print("Database error:", err)
            flash("Something went wrong. Please try again.", "error")
            return redirect(url_for('signup'))

    cursor.close()
    conn.close()
    return render_template('signup.html', locations=locations)




@app.route('/mfa')
def mfa():
    return render_template('mfa.html')


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

@app.route('/admin/accounts/<role>/<email>', methods=['GET', 'POST'])
def account_details(role, email):
    if g.role != 'admin':
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        username = request.form['username']
        updated_role = request.form['role']
        updated_email = request.form['email']
        dob = request.form.get('dob') or None  # Handles empty string
        province = request.form.get('province') or None

        try:
            cursor.execute('''
                UPDATE Users
                SET username = %s, role = %s, email = %s, DOB = %s, province = %s
                WHERE email = %s
            ''', (username, updated_role, updated_email, dob, province, email))
            conn.commit()

            flash('User details updated successfully!', 'success')
            return redirect(url_for('account_management'))

        except Exception as e:
            print('Error updating user:', e)
            flash('Failed to update user details.', 'danger')
            conn.rollback()

    # GET request - fetch user to prefill form
    cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        print('Fetched user keys:', user.keys())  # Debug
        print('Raw DOB value:', user.get('DOB'))
        print('Raw DOB type:', type(user.get('DOB')))

        # Format DOB to string 'YYYY-MM-DD' for HTML date input
        dob_val = user.get('DOB')
        try:
            if isinstance(dob_val, (datetime, date)):
                user['DOB'] = dob_val.strftime('%Y-%m-%d')
            elif isinstance(dob_val, str):
                # Try parsing string formats
                for fmt in ('%Y-%m-%d', '%d/%m/%Y'):
                    try:
                        dob_obj = datetime.strptime(dob_val, fmt)
                        user['DOB'] = dob_obj.strftime('%Y-%m-%d')
                        break
                    except ValueError:
                        continue
                else:
                    user['DOB'] = ''  # fallback if none match
            else:
                user['DOB'] = ''
        except Exception as e:
            print('DOB formatting error:', e)
            user['DOB'] = ''

        cursor.close()
        conn.close()
        return render_template('acc_details.html', user=user)

    else:
        cursor.close()
        conn.close()
        flash('User not found.', 'warning')
        return redirect(url_for('account_management'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if g.role != 'admin':
        flash('You must be an admin to perform this action.', 'danger')
        return redirect(url_for('login'))

    email_to_delete = request.form.get('email')
    role_to_delete = request.form.get('role')
    password_entered = request.form.get('password')

    # Validate admin's password (from session user_id)
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT password FROM Users WHERE user_id = %s", (session.get('user_id'),))
    admin_user = cursor.fetchone()

    if not admin_user or not check_password_hash(admin_user['password'], password_entered):
        flash('Incorrect password. Account deletion cancelled.', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('account_management'))

    # Prevent deleting self (optional safety)
    cursor.execute("SELECT email FROM Users WHERE user_id = %s", (session.get('user_id'),))
    current_email = cursor.fetchone()['email']
    if current_email == email_to_delete:
        flash('You cannot delete your own account.', 'danger')
        cursor.close()
        conn.close()
        return redirect(url_for('account_management'))

    try:
        cursor.execute("DELETE FROM Users WHERE email = %s AND role = %s", (email_to_delete, role_to_delete))
        conn.commit()
        flash(f'Account {email_to_delete} deleted successfully.', 'success')
    except Exception as e:
        flash('Error deleting account. Please try again.', 'danger')
        print('Delete error:', e)
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

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

    current_user_id = g.user['id']
    current_user_role = g.user['role'] # This will always be 'user' for guests

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

        # Volunteer logic now allows 'user' role (all guests) to volunteer
        if current_user_role == 'user':
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
    current_user_id = g.user['id']
    current_username = g.user['username']

    if not event_id:
        flash("Invalid event ID provided for sign-up.", 'error')
        return redirect(url_for('usereventpage'))

    # Since there are no admin roles, this check is now effectively removed.
    # It remains here as a placeholder for future re-integration.
    if g.user['role'] == 'admin':
        flash("Admins cannot sign up for events as regular users.", 'warning')
        return redirect(url_for('event_details', event_id=event_id))

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
    current_user_id = g.user['id']

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
    Since explicit login is removed, this is open to all for now (role 'user').
    """
    # The role check is simplified to allow the default 'user' role to volunteer
    if g.user['role'] != 'user':
        flash("You are not authorized to volunteer for events.", 'error')
        return redirect(url_for('home'))

    event_id = request.form.get('event_id', type=int)
    user_id = g.user['id'] # The current guest user ID

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
        cursor.execute(check_query, (event_id, user_id))
        if cursor.fetchone()['COUNT(*)'] > 0:
            flash("You have already volunteered for this event.", 'warning')
            return redirect(url_for('event_details', event_id=event_id))

        insert_query = "INSERT INTO event_volunteers (event_id, user_id) VALUES (%s, %s)"
        cursor.execute(insert_query, (event_id, user_id))
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
    Since explicit login is removed, this is open to all for now (role 'user').
    """
    # The role check is simplified to allow the default 'user' role to remove volunteer sign-up
    if g.user['role'] != 'user':
        flash("You are not authorized to perform this action.", 'error')
        return redirect(url_for('home'))

    event_id = request.form.get('event_id', type=int)
    user_id = g.user['id']

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
        cursor.execute(delete_query, (event_id, user_id))
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
    current_user_id = g.user['id']
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
        # Modified: For volunteered events, explicitly use g.user['username'] as signup_username
        query = f"""
            SELECT uce.username AS signup_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue
            FROM user_calendar_events uce
            JOIN event e ON uce.event_id = e.EventID
            WHERE uce.user_id = %s

            UNION

            SELECT '{g.user['username']}' AS signup_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue
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
    current_user_id = g.user['id']
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

            SELECT '{g.user['username']}' AS event_username, e.EventID, e.EventDescription, e.Date, e.Time, e.Venue, e.Category
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


@app.route('/usereventpage')
def usereventpage():
    """
    Renders a user event page, showing all available events.
    """
    db_connection = None
    cursor = None
    events = []

    try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)

        query = "SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event ORDER BY Date ASC, Time ASC"
        cursor.execute(query)
        events = cursor.fetchall()

    except mysql.connector.Error as err:
        print(f"Error fetching all events for usereventpage: {err}")
        flash(f"Error loading events: {err}", 'error')
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
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute("SELECT * FROM event;")
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('events.html', events=events)

    
@app.route('/admin/events')
def admin_events():
    if g.role != 'admin':
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int)
    per_page = 6
    offset = (page - 1) * per_page

    category = request.args.get('category', '')
    month = request.args.get('month', '')
    location = request.args.get('location', '')

    filters = []
    values = []

    if category:
        filters.append("category = %s")
        values.append(category)
    if month:
        filters.append("MONTH(event_date) = %s")
        values.append(month)
    if location:
        filters.append("organisation = %s")
        values.append(location)

    where_clause = "WHERE " + " AND ".join(filters) if filters else ""

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    count_query = f"SELECT COUNT(*) AS total FROM Events {where_clause}"
    cursor.execute(count_query, values)
    total_events = cursor.fetchone()['total']
    total_pages = ceil(total_events / per_page) if total_events > 0 else 1

    query = f"""
        SELECT * FROM Events
        {where_clause}
        ORDER BY event_date DESC
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
        selected_category=category,
        selected_month=month,
        selected_location=location
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
        location_name = request.form['location']

        # Get latitude and longitude using OpenCage
        lat, lng = get_lat_lng_from_address(location_name)
        if lat is None or lng is None:
            flash('Invalid address. Please enter a valid location.', 'danger')
            return redirect(url_for('add_event'))

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
                    max_volunteers, latitude, longitude, category, description, image
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                title, organization, date, max_participants,
                max_volunteers, lat, lng, category, description, filename
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


if __name__ == '__main__':
    app.run(debug=True)
