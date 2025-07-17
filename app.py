from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import os
import mysql.connector

app = Flask(__name__)

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.environ.get('DB_HOST', 'mainline.proxy.rlwy.net'),
            port=int(os.environ.get('DB_PORT', 41020)),
            user=os.environ.get('DB_USER', 'root'),
            password=os.environ.get('DB_PASSWORD', 'dQKyjkQpEgeSTJSAIOGzZLDOVPFcXccG'),
            database=os.environ.get('DB_NAME', 'railway')
        )
        print("Successfully connected to the MySQL database!")
        return connection
    except mysql.connector.Error as err:
        print(f"Failed to connect to MySQL database: {err}")
        return None
    

def get_db_cursor(conn):
    return conn.cursor(dictionary=True)
    

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/usereventpage')
def usereventpage():
    return render_template('usereventpage.html')

@app.route('/calendar')
def calendar():
    return render_template('calendar.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/events')
def events():
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute("SELECT * FROM event;")
    events = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('events.html', events=events)

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup', endpoint='signup')
def signup():
    return render_template('signup.html')

@app.route('/mfa')
def mfa():
    return render_template('mfa.html')

if __name__ == '__main__':
    app.run(debug=True)