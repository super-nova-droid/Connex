import smtplib
from email.mime.text import MIMEText

def send_otp_email(recipient_email, otp):
    sender_email = "your_email@gmail.com"
    sender_password = "your_email_app_password"  # App password or real password (not recommended)

    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
