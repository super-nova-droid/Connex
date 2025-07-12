
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session

app = Flask(__name__)

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