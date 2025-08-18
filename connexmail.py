import smtplib
from email.mime.text import MIMEText
import os  # To access environment variables
import random  # For OTP generation

def generate_otp():
    """Generate a 6-digit OTP code"""
    return str(random.randint(100000, 999999))

def send_otp_email(recipient_email, otp=None, subject=None, body=None):
    # Debug: Print what OTP was received
    print(f"DEBUG: send_otp_email received OTP: '{otp}' (type: {type(otp)})")
    print(f"DEBUG: Sending email to: {recipient_email}, Subject: {subject}, Body: {body}")
    
    # Your Gmail email and App Password (not normal password)
    sender_email = "connex.systematic@gmail.com"
    sender_password = os.environ.get("GMAIL_APP_PASSWORD")  # Store this securely

    # Enhanced debugging for password issues
    print(f"DEBUG: Sender email: {sender_email}")
    print(f"DEBUG: App password set: {bool(sender_password)}")
    print(f"DEBUG: App password length: {len(sender_password) if sender_password else 0}")
    
    if not sender_password:
        print("❌ CRITICAL: GMAIL_APP_PASSWORD environment variable is not set!")
        print("Please check your .env file or environment variables.")
        raise ValueError("Gmail App Password not configured")
    
    # Check password format (should be 16 characters, no spaces)
    sender_password = sender_password.strip()  # Remove any whitespace
    if len(sender_password) != 16:
        print(f"❌ WARNING: App password should be 16 characters, got {len(sender_password)}")
        print("Please generate a new Gmail App Password")
    
    # Use default subject/body if OTP is provided
    if otp:
        subject = subject or "Your OTP Code"
        body = body or f"Your OTP code is: {otp}\n\n(This is an automated email, please do not reply.)"
        print(f"DEBUG: Email body will contain OTP: '{otp}'")

    if not body:
        raise ValueError("Email body cannot be empty.")

    # Compose MIME email message
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    try:
        print("DEBUG: Attempting to connect to Gmail SMTP server...")
        # Connect to Gmail SMTP server
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            print("DEBUG: Connected to SMTP server, attempting login...")
            server.set_debuglevel(1)  # Enable SMTP debugging
            server.login(sender_email, sender_password)
            print("DEBUG: Login successful, sending message...")
            server.send_message(msg)
        print("✅ Email sent successfully via Gmail.")
    except smtplib.SMTPAuthenticationError as e:
        print("❌ Authentication error: Check app password and SMTP settings.")
        print(f"Details: {e}")
        print("\n🔧 TROUBLESHOOTING STEPS:")
        print("1. Go to Google Account settings: https://myaccount.google.com/")
        print("2. Security → 2-Step Verification (must be ON)")
        print("3. App passwords → Generate new password for 'Mail'")
        print("4. Update your .env file: GMAIL_APP_PASSWORD=your16digitpassword")
        print("5. Restart your application")
        raise  # Re-raise to maintain error handling
    except Exception as e:
        print(f"❌ Error sending email: {e}")
        raise
