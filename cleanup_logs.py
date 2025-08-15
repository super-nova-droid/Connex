# Connex/cleanup_logs.py
import mysql.connector
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_NAME = os.environ.get('DB_NAME')
DB_PORT = int(os.environ.get('DB_PORT', 3306))

# Log file in project directory
LOG_FILE = os.path.join(os.path.dirname(__file__), "audit_cleanup.log")

def log(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {message}\n")
def cleanup_audit_logs():
    print("Starting audit log cleanup...")
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT
        )
        cursor = conn.cursor()
        query = "DELETE FROM Audit_Log WHERE timestamp < NOW() - INTERVAL 30 DAY"
        cursor.execute(query)
        conn.commit()
        print(f" Deleted {cursor.rowcount} old audit log entries.")
        log(f" Deleted {cursor.rowcount} old audit log entries.")
    except Exception as e:
        print(f" Error during cleanup: {str(e)}")
        log(f" Error during cleanup: {str(e)}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
    print("Cleanup finished.")


if __name__ == "__main__":
    cleanup_audit_logs()


#& ".venv\Scripts\python.exe" cleanup_logs.py

