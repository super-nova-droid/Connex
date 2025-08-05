import smtplib
from email.mime.text import MIMEText
import os  # To access environment variables

def send_otp_email(recipient_email, otp=None, subject=None, body=None):
    # Your Gmail email and App Password (not normal password)
    sender_email = "connex.systematic@gmail.com"
    sender_password = os.environ.get("GMAIL_APP_PASSWORD")  # Store this securely

    # Use default subject/body if OTP is provided
    if otp:
        subject = subject or "Your OTP Code"
        body = body or f"Your OTP code is: {otp}\n\n(This is an automated email, please do not reply.)"

    if not body:
        raise ValueError("Email body cannot be empty.")

    # Compose MIME email message
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    try:
        # Connect to Gmail SMTP server
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print("✅ Email sent successfully via Gmail.")
    except smtplib.SMTPAuthenticationError as e:
        print("❌ Authentication error: Check app password and SMTP settings.")
        print(f"Details: {e}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
