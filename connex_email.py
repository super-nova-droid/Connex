import os
import random
from flask_mail import Mail, Message

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(app, mail, recipient_email, otp):
    with app.app_context():
        msg = Message(
            subject="Your OTP Verification Code",
            sender=app.config['MAIL_USERNAME'],
            recipients=[recipient_email],
            body=f"Your OTP code is: {otp}"
        )
        mail.send(msg)
