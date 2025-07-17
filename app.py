from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
import mysql.connector
import os
import uuid
from datetime import datetime, time, timedelta
from dotenv import load_dotenv

# Import the OpenAI library
from openai import OpenAI

# Load environment variables from .env file FIRST THING
load_dotenv()

app = Flask(__name__)

# --- Load configuration from environment variables ---
# Flask Secret Key
# It's crucial to set a strong, random key in your .env for production.
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    print("Warning: FLASK_SECRET_KEY environment variable not set. Using a fallback, which is INSECURE for production!")
    # Fallback for development if .env is missing, but strongly advise against this for production.
    app.secret_key = 'a_very_insecure_fallback_key_for_dev_only_please_change'

# MySQL DB configuration from environment variables
DB_HOST = os.getenv('DB_HOST')
DB_PORT = int(os.getenv('DB_PORT', 3306)) # Default MySQL port if not specified
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

# OpenAI API Key
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
    print("Warning: OPENAI_API_KEY environment variable not set. Chatbot functionality will be unavailable.")

# Basic check to ensure critical DB variables are loaded
if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
    print("Error: One or more critical database environment variables (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) are not set.")
    print("Please ensure your .env file is correctly configured and located in the project root.")
    # In a production app, you might want to raise an exception or exit here.
    # import sys
    # sys.exit(1)


# --- Before Request: Always set g.user to a guest ---
@app.before_request
def set_guest_user():
    """
    Sets a default 'guest' user for every request.
    This ensures g.user is always available and allows all functionalities
    to operate without explicit login. It also handles existing sessions
    that might not have 'username' or 'role' set yet.
    """
    # Ensure a unique user_id exists in session for this guest
    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())
        session['username'] = 'guest' # Initialize username if new session
        session['role'] = 'user'      # Initialize role if new session
    else:
        # If user_id exists but username/role don't (e.g., from an old session), set them
        if 'username' not in session:
            session['username'] = 'guest'
        if 'role' not in session:
            session['role'] = 'user'

    # Set g.user based on session for the current request
    g.user = {
        'id': session['user_id'],
        'username': session['username'],
        'role': session['role']
    }

# Removed: role_required decorator and all authentication routes (/register, /login, /logout)
# Removed: admin dashboard route (/admin_dashboard)

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
    return render_template('chat.html')

# --- NEW API ENDPOINT FOR CHATBOT ---
@app.route('/api/chat', methods=['POST'])
def api_chat():
    """
    Handles chat messages from the frontend, sends them to OpenAI,
    and returns the chatbot's response.
    """
    if not openai_client:
        return jsonify({"error": "Chatbot is not configured. Missing API key or initialization error."}), 503 # Service Unavailable

    user_message = request.json.get('message')
    if not user_message:
        return jsonify({"error": "No message provided."}), 400

    try:
        # Example using OpenAI's chat completions API
        # You can expand on this with context, message history, etc.
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo", # Or "gpt-4", etc.
            messages=[
                {"role": "system", "content": "You are a helpful assistant for event management. Provide concise answers."},
                {"role": "user", "content": user_message}
            ]
        )
        chatbot_response = response.choices[0].message.content
        return jsonify({"response": chatbot_response})

    except Exception as e:
        print(f"Error from OpenAI Chat: {e}")
        return jsonify({"error": f"Error interacting with chatbot: {e}"}), 500

@app.route('/support')
def support():
    """
    Renders the support page with contact information.
    """
    return render_template('support.html')

if __name__ == '__main__':
    app.run(debug=True)
