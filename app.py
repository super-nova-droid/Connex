
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session

app = Flask(__name__)

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'Ilovemysql2025%')
DB_NAME = os.environ.get('DB_NAME', 'mydb')
DB_PORT = os.environ.get('DB_PORT', 3306)

try:
        db_connection = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, port=DB_PORT
        )
        cursor = db_connection.cursor(dictionary=True)
        
        cursor.execute("SELECT EventID, EventDescription, Date, Time, Venue, Category, ImageFileName FROM event WHERE EventID = %s", (event_id,))
        event = cursor.fetchone()
        
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

if __name__ == '__main__':
    app.run(debug=True)